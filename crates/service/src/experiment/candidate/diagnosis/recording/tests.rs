use super::*;
use crate::experiment::{baseline::tests::Database, candidate::diagnosis::tests::fixture};
use epp_core::packet_size::Probe;

fn prepared(database: &mut Connection) -> (store::Recorder, packet_size::Plan) {
    let (plan, mut backend) = fixture();
    let mut recorder = store::Recorder::start(database, plan.clone()).unwrap();
    let before = backend
        .policy(plan.adapterGuid, &AtomicBool::new(false))
        .unwrap();
    let routes = backend
        .routes(&plan.targets, &AtomicBool::new(false))
        .unwrap();
    let packet = packet_size::Plan {
        source: "192.0.2.2".parse().unwrap(),
        destination: match plan.targets[0].ip {
            std::net::IpAddr::V4(ip) => ip,
            _ => unreachable!(),
        },
        interfaceMtu: 1500,
        timeoutMs: 750,
        intervalMs: 75,
        budgetMs: 5000,
    };
    recorder
        .append(
            database,
            Observation::Context {
                before: Box::new(before),
                routes,
            },
        )
        .unwrap();
    recorder
        .append(
            database,
            Observation::Target {
                index: 0,
                plan: packet.clone(),
                limits: Limits::default(),
            },
        )
        .unwrap();
    (recorder, packet)
}

fn sample(plan: &packet_size::Plan) -> Sample {
    let (_, mut backend) = fixture();
    Sample {
        sequence: 0,
        timestampUnixMs: crate::watchdog::nowUnixMs().unwrap(),
        packetBytes: 84,
        control: true,
        dontFragment: true,
        echo: backend
            .measure(plan, 84, Duration::from_millis(750))
            .unwrap(),
    }
}

#[test]
fn collectedContextSamplesAndFinalEvidenceSurviveDatabaseReopen() {
    let storage = Database::new();
    let mut database = storage.open();
    let (plan, mut backend) = fixture();
    let result = collectUsing(
        &mut database,
        plan,
        &AtomicBool::new(false),
        |_, _| Ok(()),
        &mut backend,
    )
    .unwrap();
    assert!(matches!(
        result.collection,
        Collection::Completed { proposal: None, .. }
    ));
    assert_eq!(backend.probes, 20);
    let expected = serde_json::to_value(&result.collection).unwrap();
    drop(database);
    let database = storage.open();
    let records = history(&database, 1).unwrap();
    assert_eq!(records[0].header.id, result.recordingId);
    assert_eq!(records[0].header.execution, "recordedDiagnosticWorkerV1");
    assert_eq!(records[0].state, State::Finalized);
    assert_eq!(records[0].events.len(), 25);
    assert_eq!(
        serde_json::to_value(records[0].result.as_ref().unwrap()).unwrap(),
        expected
    );
    assert!(matches!(
        records[0].events[0].observation,
        Observation::Context { .. }
    ));
}

#[test]
fn savedBoundaryIsAReadOnlySummaryAndChangedFinalEvidenceIsRefused() {
    let storage = Database::new();
    let mut database = storage.open();
    let (plan, mut backend) = fixture();
    backend.cutoff = 1427;
    collectUsing(
        &mut database,
        plan,
        &AtomicBool::new(false),
        |_, _| Ok(()),
        &mut backend,
    )
    .unwrap();
    let records = history(&database, 1).unwrap();
    let Some(SavedCollection::Completed {
        proposal: Some(summary),
        ..
    }) = &records[0].result
    else {
        panic!("missing saved proposal")
    };
    assert_eq!(summary.proposedMtu, 1427);
    let original = serde_json::to_value(records[0].result.as_ref().unwrap()).unwrap();
    assert!(original["proposal"].get("deadline").is_none());
    for failure in 0..4 {
        let mut result = original.clone();
        match failure {
            0 => result["proposal"]["proposedMtu"] = 1400.into(),
            1 => result["evidence"]["reports"][0]["samples"][0]["echo"]["rttMs"] = 2.into(),
            2 => result["evidence"]["reports"][0]["requestedIpv4Bytes"] = u64::MAX.into(),
            _ => result["unexpected"] = true.into(),
        }
        let value = serde_json::to_string(&result).unwrap();
        let (headerHash, metadata): (String, String) = database
            .query_row(
                "SELECT header_sha256,metadata_json FROM diagnostic_recordings",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let mut metadata: serde_json::Value = serde_json::from_str(&metadata).unwrap();
        metadata["resultSha256"] = epp_core::backups::checksum(&value).into();
        let metadata = serde_json::to_string(&metadata).unwrap();
        let checksum = hash(&(
            "diagnosis-state-v1",
            records[0].header.id,
            &headerHash,
            &metadata,
        ))
        .unwrap();
        database.execute("UPDATE diagnostic_recordings SET result_json=?1,metadata_json=?2,metadata_sha256=?3", rusqlite::params![value, metadata, checksum]).unwrap();
        assert!(history(&database, 1).is_err(), "{failure}");
    }
}

#[test]
fn recordedCollectionSharesTheExactRemainingByteAllowanceAcrossTargets() {
    let storage = Database::new();
    let mut database = storage.open();
    let (mut plan, mut backend) = fixture();
    plan.maximumRequestedIpv4Bytes = 5340;
    let result = collectUsing(
        &mut database,
        plan,
        &AtomicBool::new(false),
        |_, _| Ok(()),
        &mut backend,
    )
    .unwrap();
    assert!(matches!(
        result.collection,
        Collection::Stopped {
            reason: StopReason::TrafficLimit,
            ..
        }
    ));
    assert_eq!(backend.probes, 13);
    let records = history(&database, 1).unwrap();
    assert_eq!(records[0].state, State::Finalized);
    assert_eq!(records[0].events.len(), 18);
    let samples: Vec<_> = records[0]
        .events
        .iter()
        .filter_map(|event| match &event.observation {
            Observation::Sample { sample } => Some(sample),
            _ => None,
        })
        .collect();
    assert_eq!(samples.len(), 13);
    assert_eq!(
        samples.iter().map(|sample| sample.packetBytes).sum::<u32>(),
        5340
    );
}

#[test]
fn observerAndStorageFailuresStopAfterOneProbeAndKeepCommittedEvidence() {
    for storageFailure in [false, true] {
        let storage = Database::new();
        let mut database = storage.open();
        let (plan, mut backend) = fixture();
        if storageFailure {
            let recorder = store::Recorder::start(&mut database, plan.clone()).unwrap();
            let mut recorder = recorder;
            recorder
                .interrupt(&mut database, "fixture schema setup")
                .unwrap();
            database.execute_batch("CREATE TRIGGER refuse_probe BEFORE INSERT ON diagnostic_recording_events WHEN json_extract(NEW.payload_json,'$.observation.kind')='sample' BEGIN SELECT RAISE(ABORT,'fixture sample write refused'); END;").unwrap();
        }
        let mut delivered = 0;
        let result = collectUsing(
            &mut database,
            plan,
            &AtomicBool::new(false),
            |_, _| {
                delivered += 1;
                Err("fixture observer refused".into())
            },
            &mut backend,
        )
        .unwrap();
        assert!(matches!(result.collection, Collection::Stopped { .. }));
        assert_eq!(backend.probes, 1);
        let records = history(&database, 1).unwrap();
        assert_eq!(records[0].state, State::Finalized);
        let Some(SavedCollection::Stopped { evidence, .. }) = &records[0].result else {
            panic!("missing stopped evidence")
        };
        assert_eq!(evidence.reports[0].samples.len(), 1);
        assert_eq!(evidence.reports[0].requestedIpv4Bytes, 84);
        assert_eq!(records[0].events.len(), if storageFailure { 2 } else { 4 });
        assert_eq!(delivered, usize::from(!storageFailure));
        if storageFailure {
            assert!(
                records[0]
                    .detail
                    .as_ref()
                    .unwrap()
                    .contains("sample write refused")
            );
        }
    }
}

#[test]
fn storageAndCancellationGatesRunBeforeAnyCaptureOrProbe() {
    let storage = Database::new();
    let mut database = storage.open();
    let (plan, mut backend) = fixture();
    assert!(
        collectUsing(
            &mut database,
            plan.clone(),
            &AtomicBool::new(true),
            |_, _| Ok(()),
            &mut backend
        )
        .is_err()
    );
    assert!(history(&database, 1).unwrap().is_empty());
    database
        .pragma_update(None, "synchronous", "NORMAL")
        .unwrap();
    assert!(
        collectUsing(
            &mut database,
            plan,
            &AtomicBool::new(false),
            |_, _| Ok(()),
            &mut backend
        )
        .is_err()
    );
    assert_eq!(backend.probes, 0);
    assert!(history(&database, 1).unwrap().is_empty());
    assert!(history(&database, 0).is_err());
    assert!(history(&database, 51).is_err());
}

#[test]
fn activeOwnerCorruptionAndInvalidEventsCannotBeBypassed() {
    for failure in 0..6 {
        let storage = Database::new();
        let mut database = storage.open();
        let (mut recorder, plan) = prepared(&mut database);
        assert!(store::Recorder::start(&mut database, recorder.header.plan.clone()).is_err());
        match failure {
            0 => {
                let mut sample = sample(&plan);
                sample.sequence = 1;
                assert!(
                    recorder
                        .append(&mut database, Observation::Sample { sample })
                        .is_err()
                );
                assert_eq!(history(&database, 1).unwrap()[0].events.len(), 2);
            }
            1 => {
                let mut sample = sample(&plan);
                sample.packetBytes = 9001;
                assert!(
                    recorder
                        .append(&mut database, Observation::Sample { sample })
                        .is_err()
                );
                assert_eq!(history(&database, 1).unwrap()[0].events.len(), 2);
            }
            2 => {
                database
                    .execute(
                        "UPDATE diagnostic_recording_events SET payload_json='{}'",
                        [],
                    )
                    .unwrap();
                assert!(history(&database, 1).is_err());
            }
            3 => {
                database
                    .execute("DELETE FROM diagnostic_recording_events", [])
                    .unwrap();
                assert!(history(&database, 1).is_err());
            }
            4 => {
                database
                    .execute("UPDATE diagnostic_recordings SET metadata_json='{}'", [])
                    .unwrap();
                assert!(history(&database, 1).is_err());
            }
            _ => {
                database
                    .execute("UPDATE diagnostic_recordings SET header_json='{}'", [])
                    .unwrap();
                assert!(history(&database, 1).is_err());
            }
        }
        if matches!(failure, 2 | 3) {
            assert!(
                recorder
                    .interrupt(&mut database, "fixture corruption")
                    .is_err()
            );
        } else {
            assert!(
                recorder
                    .append(
                        &mut database,
                        Observation::Sample {
                            sample: sample(&plan)
                        }
                    )
                    .is_err()
            );
        }
    }
}

#[test]
fn failedFinalCommitLeavesTheRecordingUnfinishedAndBlocksAnotherOwner() {
    let storage = Database::new();
    let mut database = storage.open();
    let (plan, mut backend) = fixture();
    let recorder = store::Recorder::start(&mut database, plan.clone()).unwrap();
    let mut recorder = recorder;
    recorder
        .interrupt(&mut database, "fixture schema setup")
        .unwrap();
    database.execute_batch("CREATE TRIGGER refuse_result BEFORE UPDATE ON diagnostic_recordings WHEN NEW.state='finalized' BEGIN SELECT RAISE(ABORT,'fixture final commit refused'); END;").unwrap();
    let error = collectUsing(
        &mut database,
        plan.clone(),
        &AtomicBool::new(false),
        |_, _| Ok(()),
        &mut backend,
    )
    .err()
    .unwrap()
    .to_string();
    assert!(error.contains("final commit refused"));
    let records = history(&database, 1).unwrap();
    assert_eq!(records[0].state, State::Recording);
    assert!(records[0].result.is_none());
    assert_eq!(records[0].events.len(), 25);
    assert!(store::Recorder::start(&mut database, plan).is_err());
}

#[test]
#[ignore]
fn recordingOwnerFixture() {
    use std::io::Write;
    let path = std::env::var_os("EPP_DIAGNOSIS_RECORDING_PATH").expect("fixture database path");
    let mut database = epp_core::storage::openDatabase(std::path::Path::new(&path)).unwrap();
    let (mut recorder, plan) = prepared(&mut database);
    recorder
        .append(
            &mut database,
            Observation::Sample {
                sample: sample(&plan),
            },
        )
        .unwrap();
    if std::env::var("EPP_DIAGNOSIS_UNCOMMITTED").unwrap() == "true" {
        database
            .execute_batch("BEGIN IMMEDIATE; DELETE FROM diagnostic_recording_events;")
            .unwrap();
    }
    println!("diagnosis-owner-ready");
    std::io::stdout().flush().unwrap();
    loop {
        std::thread::park();
    }
}

#[test]
fn killedOwnerPreservesCommittedSamplesAndDiscardsAnUncommittedTail() {
    use std::{
        io::{BufRead, BufReader},
        os::windows::process::CommandExt,
        process::{Child, Command, Stdio},
    };
    struct Owner(Child);
    impl Drop for Owner {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    for uncommitted in [false, true] {
        let storage = Database::new();
        let database = storage.open();
        let path = database.path().unwrap().to_owned();
        drop(database);
        let mut owner = Owner(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "experiment::candidate::diagnosis::recording::tests::recordingOwnerFixture",
                    "--nocapture",
                ])
                .env("EPP_DIAGNOSIS_RECORDING_PATH", path)
                .env("EPP_DIAGNOSIS_UNCOMMITTED", uncommitted.to_string())
                .creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW)
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let output = owner.0.stdout.take().unwrap();
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(output).lines().take(16) {
                if line.unwrap() == "diagnosis-owner-ready" {
                    sender.send(()).unwrap();
                    return;
                }
            }
        });
        receiver.recv_timeout(Duration::from_secs(15)).unwrap();
        owner.0.kill().unwrap();
        owner.0.wait().unwrap();
        reader.join().unwrap();
        let mut database = storage.open();
        let records = history(&database, 1).unwrap();
        assert_eq!(records[0].state, State::Recording);
        assert_eq!(records[0].events.len(), 3);
        let (plan, _) = fixture();
        let mut next = store::Recorder::start(&mut database, plan).unwrap();
        let records = history(&database, 2).unwrap();
        assert_eq!(records[1].state, State::Interrupted);
        assert_eq!(records[1].events.len(), 3);
        assert!(records[1].result.is_none());
        assert!(records[1].detail.as_ref().unwrap().contains("Owner exited"));
        next.interrupt(&mut database, "fixture finished").unwrap();
    }
}
