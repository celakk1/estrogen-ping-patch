use super::*;
use epp_core::icmp::{EchoOutcome, EchoStatus};

fn input() -> Request {
    Request::Packet {
        plan: packet_size::Plan {
            source: "127.0.0.1".parse().unwrap(),
            destination: "127.0.0.1".parse().unwrap(),
            interfaceMtu: 1500,
            timeoutMs: 100,
            intervalMs: 75,
            budgetMs: 5000,
        },
        limits: Limits::default(),
    }
}

fn sample(now: u64) -> Sample {
    Sample {
        sequence: 0,
        timestampUnixMs: now,
        packetBytes: 84,
        control: true,
        dontFragment: true,
        echo: EchoOutcome {
            status: EchoStatus::Reply,
            rttMs: Some(1),
            rttUnitMs: 1,
            callDurationMs: 1.0,
            responder: Some("127.0.0.1".parse().unwrap()),
            responderScopeId: None,
            nativeCode: Some(0),
        },
    }
}

fn report(input: &Request, now: u64) -> Report {
    let Request::Packet { plan, .. } = input else {
        panic!("fixture operation")
    };
    Report {
        schemaVersion: 1,
        plan: plan.clone(),
        outcome: Outcome::Cancelled,
        startedAtUnixMs: now,
        finishedAtUnixMs: now,
        maximumTestedBytes: 1500,
        largestSuccessfulBytes: None,
        smallestTooBigBytes: None,
        confirmedBoundaryBytes: None,
        requestedIpv4Bytes: 84,
        samples: vec![sample(now)],
        error: None,
    }
}

fn stream(input: &Request, now: u64) -> Vec<u8> {
    let mut encoder = Encoder {
        writer: Vec::new(),
        sequence: 0,
        bytes: 0,
    };
    encoder.send(Output::Sample(&sample(now))).unwrap();
    encoder.send(Output::Packet(&report(input, now))).unwrap();
    encoder.writer
}

#[test]
fn fixedModesRefuseChangedRequestsBeforeExecutingEitherOperation() {
    let routes = Request::Routes {
        targets: vec![routing::Address {
            ip: "127.0.0.1".parse().unwrap(),
            scopeId: 0,
        }],
    };
    for (input, packet) in [(input(), false), (routes, true)] {
        let request = serde_json::to_vec(&Frame {
            schemaVersion: 1,
            sequence: 0,
            body: input,
        })
        .unwrap();
        let error = runVerified(request, packet).unwrap_err().to_string();
        assert!(error.contains("does not match its token policy"));
    }
    let request = serde_json::to_value(Frame {
        schemaVersion: 1,
        sequence: 0,
        body: input(),
    })
    .unwrap();
    for failure in 0..5 {
        let mut changed = request.clone();
        match failure {
            0 => changed["schemaVersion"] = 2.into(),
            1 => changed["sequence"] = 1.into(),
            2 => changed["body"]["packet"]["limits"]["maximumProbes"] = 145.into(),
            3 => changed["body"]["packet"]["limits"]["maximumRequestedIpv4Bytes"] = 0.into(),
            _ => changed["body"]["packet"]["plan"]["extra"] = true.into(),
        }
        assert!(runVerified(serde_json::to_vec(&changed).unwrap(), true).is_err());
    }
}

#[test]
fn routeResultsMustPreserveTheFixedDestinationCohort() {
    let targets: Vec<_> = ["127.0.0.1", "127.0.0.2"]
        .map(|ip| routing::Address {
            ip: ip.parse().unwrap(),
            scopeId: 0,
        })
        .into();
    let input = Request::Routes {
        targets: targets.clone(),
    };
    let now = crate::watchdog::nowUnixMs().unwrap();
    for failure in 0..4 {
        let mut captures: Vec<_> = targets
            .iter()
            .map(|destination| routing::Capture::Unavailable {
                destination: destination.clone(),
                error: "fixture unavailable".into(),
            })
            .collect();
        match failure {
            1 => captures.reverse(),
            2 => {
                captures.pop();
            }
            3 => {
                let routing::Capture::Unavailable { error, .. } = &mut captures[0] else {
                    unreachable!()
                };
                *error = "x".repeat(2049);
            }
            _ => {}
        }
        let mut bytes = serde_json::to_vec(&Frame {
            schemaVersion: 1,
            sequence: 0,
            body: Output::Routes(&captures),
        })
        .unwrap();
        bytes.push(b'\n');
        let mut decoder = Decoder::new(&input, now);
        let result = decoder.consume(&bytes, &mut |_| {
            panic!("routes cannot emit packet progress")
        });
        assert_eq!(result.is_ok(), failure == 0);
        if failure == 0 {
            assert!(matches!(decoder.finish().unwrap(), Body::Routes(_)));
        }
    }
}

#[test]
fn framedProbesRequireExactTerminalAgreementAndTolerateArbitraryChunks() {
    let input = input();
    let now = crate::watchdog::nowUnixMs().unwrap();
    let bytes = stream(&input, now);
    for size in [1, 3, 37, bytes.len()] {
        let mut decoder = Decoder::new(&input, now);
        let mut count = 0;
        for chunk in bytes.chunks(size) {
            decoder
                .consume(chunk, &mut |_| {
                    count += 1;
                    Ok(())
                })
                .unwrap();
        }
        assert!(matches!(decoder.finish().unwrap(), Body::Packet(_)));
        assert_eq!(count, 1);
    }
}

#[test]
fn malformedFramesAndChangedFrozenEvidenceAreRefused() {
    let input = input();
    let now = crate::watchdog::nowUnixMs().unwrap();
    let bytes = stream(&input, now);
    let lines: Vec<_> = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .collect();
    for failure in 0..14 {
        let mut first: serde_json::Value = serde_json::from_slice(lines[0]).unwrap();
        let mut last: serde_json::Value = serde_json::from_slice(lines[1]).unwrap();
        match failure {
            0 => first["schemaVersion"] = 2.into(),
            1 => first["sequence"] = 1.into(),
            2 => first["extra"] = true.into(),
            3 => {
                first["body"]["sample"]
                    .as_object_mut()
                    .unwrap()
                    .remove("control");
            }
            4 => first["body"]["sample"]["packetBytes"] = 9001.into(),
            5 => first["body"]["sample"]["sequence"] = 1.into(),
            6 => first["body"]["sample"]["timestampUnixMs"] = (now - 1).into(),
            7 => first["body"]["sample"]["dontFragment"] = false.into(),
            8 => last["body"]["packet"]["plan"]["source"] = "127.0.0.2".into(),
            9 => last["body"]["packet"]["samples"][0]["echo"]["rttMs"] = 2.into(),
            10 => {
                last["body"]["packet"]["samples"] = serde_json::json!([]);
                last["body"]["packet"]["requestedIpv4Bytes"] = 0.into();
            }
            11 => first["body"] = serde_json::json!({"routes":[]}),
            12 => first["body"]["sample"]["echo"]["rttUnitMs"] = 0.into(),
            _ => last["sequence"] = 0.into(),
        }
        let mut changed = serde_json::to_vec(&first).unwrap();
        changed.push(b'\n');
        changed.extend(serde_json::to_vec(&last).unwrap());
        changed.push(b'\n');
        let mut decoder = Decoder::new(&input, now);
        assert!(
            decoder.consume(&changed, &mut |_| Ok(())).is_err(),
            "{failure}"
        );
    }
    for changed in [
        b"{\"schemaVersion\":1,\"schemaVersion\":1}\n".to_vec(),
        vec![b'x'; FRAME_BYTES + 1],
        vec![b'x'; STREAM_BYTES + 1],
    ] {
        assert!(
            Decoder::new(&input, now)
                .consume(&changed, &mut |_| Ok(()))
                .is_err()
        );
    }
    let mut decoder = Decoder::new(&input, now);
    decoder.consume(&bytes, &mut |_| Ok(())).unwrap();
    assert!(decoder.consume(b"x", &mut |_| Ok(())).is_err());
    let mut decoder = Decoder::new(&input, now);
    decoder
        .consume(&bytes[..bytes.len() - 1], &mut |_| Ok(()))
        .unwrap();
    assert!(decoder.finish().is_err());
}

#[test]
fn byteCapsAndRejectedConsumersCannotInventAdditionalProgress() {
    let now = crate::watchdog::nowUnixMs().unwrap();
    let mut input = input();
    let Request::Packet { limits, .. } = &mut input else {
        unreachable!()
    };
    limits.maximumRequestedIpv4Bytes = 1;
    assert!(
        Decoder::new(&input, now)
            .consume(&stream(&input, now), &mut |_| Ok(()))
            .is_err()
    );
    let input = super::tests::input();
    let mut decoder = Decoder::new(&input, now);
    assert!(
        decoder
            .consume(&stream(&input, now), &mut |_| Err("fixture refused".into()))
            .is_err()
    );
    assert_eq!(decoder.samples.len(), 1);
    assert!(decoder.result.is_none());
}

fn image() -> std::path::PathBuf {
    let path = std::path::PathBuf::from(
        std::env::var_os("EPP_TRANSFER_WORKER_IMAGE").expect("set the built optional worker image"),
    );
    assert!(path.is_absolute() && path.is_file());
    path
}

#[test]
#[ignore]
fn isolatedReadWorkerCapturesLoopbackRoutesAndActualSourceBoundPackets() {
    let image = image();
    let cancelled = AtomicBool::new(false);
    let targets: Vec<_> = (1..=routing::MAX_DESTINATIONS)
        .map(|index| routing::Address {
            ip: format!("127.0.0.{index}").parse().unwrap(),
            scopeId: 0,
        })
        .collect();
    Request::Routes {
        targets: targets.clone(),
    }
    .validate()
    .unwrap();
    let mut excessive = targets.clone();
    excessive.push(routing::Address {
        ip: "127.0.0.200".parse().unwrap(),
        scopeId: 0,
    });
    assert!(Request::Routes { targets: excessive }.validate().is_err());
    let routes = routesUsing(&image, &targets, &cancelled).unwrap();
    assert_eq!(routes.len(), targets.len());
    for (route, target) in routes.iter().zip(&targets) {
        assert!(
            matches!(route, routing::Capture::Captured { snapshot } if snapshot.destination == *target)
        );
    }
    let Request::Packet { plan, limits } = input() else {
        unreachable!()
    };
    let mut count = 0;
    let report = diagnoseUsing(&image, plan, limits, &cancelled, |_| {
        count += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(
        report.outcome,
        Outcome::TestedLimitReached,
        "{}",
        serde_json::to_string(&report).unwrap()
    );
    assert_eq!(count, 10);
    assert_eq!(report.requestedIpv4Bytes, 5088);
    report.validate().unwrap();
}

#[test]
#[ignore]
fn isolatedReadWorkerDeadlineAndConsumerRefusalPreserveOnlyTheValidatedPrefix() {
    let image = image();
    let Request::Packet { mut plan, limits } = input() else {
        unreachable!()
    };
    plan.intervalMs = 250;
    plan.budgetMs = 1000;
    let started = Instant::now();
    let report = diagnoseUsing(&image, plan, limits, &AtomicBool::new(false), |_| Ok(())).unwrap();
    assert_ne!(report.outcome, Outcome::TestedLimitReached);
    assert!(report.confirmedBoundaryBytes.is_none());
    assert!(report.error.as_ref().unwrap().contains("process deadline"));
    assert!(started.elapsed() < Duration::from_secs(4));
    report.validate().unwrap();
    let Request::Packet { plan, limits } = input() else {
        unreachable!()
    };
    let mut count = 0;
    let report = diagnoseUsing(&image, plan, limits, &AtomicBool::new(false), |_| {
        count += 1;
        Err("fixture consumer refused".into())
    })
    .unwrap();
    assert_eq!(count, 1);
    assert_eq!(report.samples.len(), 1);
    assert_eq!(report.requestedIpv4Bytes, 84);
    assert!(
        report
            .error
            .as_ref()
            .unwrap()
            .contains("fixture consumer refused")
    );
    report.validate().unwrap();
}

#[test]
#[ignore]
fn isolatedReadWorkerIsStoppedBeforeConsumerErrorOrUnwindReturns() {
    use std::{
        os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
        panic::{AssertUnwindSafe, catch_unwind},
    };
    use windows_sys::Win32::{
        Foundation::WAIT_OBJECT_0,
        System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject},
    };
    let image = image();
    for panic in [false, true] {
        let input = input();
        let (child, _mapping) = spawn(&image, &input).unwrap();
        let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, child.id()) };
        assert!(!handle.is_null());
        let process = unsafe { OwnedHandle::from_raw_handle(handle) };
        let mut decoder = Decoder::new(&input, crate::watchdog::nowUnixMs().unwrap());
        let started = Instant::now();
        let result = catch_unwind(AssertUnwindSafe(|| {
            child.stream(
                STREAM_BYTES,
                || {
                    if started.elapsed() < Duration::from_secs(5) {
                        Ok(())
                    } else {
                        Err("fixture deadline".into())
                    }
                },
                |bytes| {
                    decoder.consume(bytes, &mut |_| {
                        assert!(!panic, "fixture consumer unwind");
                        Err("fixture consumer refused".into())
                    })
                },
            )
        }));
        if panic {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert_eq!(
            unsafe { WaitForSingleObject(process.as_raw_handle(), 0) },
            WAIT_OBJECT_0
        );
        assert_eq!(decoder.samples.len(), 1);
    }
}
