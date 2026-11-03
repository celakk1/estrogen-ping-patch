use super::*;
use crate::transfer_worker::tests::{input, response};

fn observation(download: u64, active: u64, elapsed: u64) -> Observation {
    Observation {
        elapsedMicros: elapsed,
        counters: Counters {
            downloadBytesRead: download,
            uploadBodyBytesProvided: 0,
            activeRequests: active,
        },
    }
}

fn line(sequence: u32, event: Event) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&Frame {
        version: FRAME_VERSION,
        sequence,
        event,
    })
    .unwrap();
    bytes.push(b'\n');
    bytes
}

fn completed(input: &Request) -> Vec<u8> {
    let mut bytes = line(0, Event::Progress(observation(10, 2, 100)));
    bytes.extend(line(1, Event::Progress(observation(2000, 2, 500_000))));
    bytes.extend(line(2, Event::Progress(observation(4097, 0, 1_100_000))));
    bytes.extend(line(3, Event::Result(Box::new(response(input)))));
    bytes
}

#[test]
fn framesSurviveArbitrarySplitsAndRemainProvisionalUntilFinish() {
    let input = input("127.0.0.1:8080".parse().unwrap(), Direction::Download);
    let bytes = completed(&input);
    for size in [1, 7, 4096, bytes.len()] {
        let started = Instant::now();
        let mut decoder = Decoder::new(&input);
        let mut updates = Vec::new();
        for chunk in bytes.chunks(size) {
            decoder
                .consume(chunk, &mut |update| {
                    assert!(update.receivedAt >= started);
                    updates.push(update.observation);
                    Ok(())
                })
                .unwrap();
        }
        assert_eq!(
            updates,
            [
                observation(10, 2, 100),
                observation(2000, 2, 500_000),
                observation(4097, 0, 1_100_000)
            ]
        );
        assert_eq!(decoder.finish().unwrap().acceptedPayloadBytes, 4097);
    }
}

#[test]
fn encoderDoesNotInventProgressWhileCountersAreUnchanged() {
    let input = input("127.0.0.1:8080".parse().unwrap(), Direction::Download);
    let progress = TransferProgress::default();
    let mut encoder = Encoder::new(Vec::new());
    let started = Instant::now();
    encoder.progress(&progress, started).unwrap();
    assert!(encoder.output.is_empty());
    progress.downloadBytesRead.store(4097, Ordering::SeqCst);
    encoder.progress(&progress, started).unwrap();
    let length = encoder.output.len();
    encoder.progress(&progress, started).unwrap();
    assert_eq!(encoder.output.len(), length);
    encoder.finish(response(&input).result).unwrap();
    let mut decoder = Decoder::new(&input);
    let mut count = 0;
    decoder
        .consume(&encoder.output, &mut |_| {
            count += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(count, 1);
    decoder.finish().unwrap();
}

#[test]
fn refusesCounterTimeDirectionAndActivityDrift() {
    let input = input("127.0.0.1:8080".parse().unwrap(), Direction::Download);
    let first = observation(10, 2, 100);
    let mut invalid = vec![
        first,
        observation(9, 2, 101),
        observation(4098, 2, 101),
        observation(10, 3, 101),
        observation(11, 2, 99),
        observation(11, 2, 4_000_001),
        observation(11, u64::MAX, 101),
    ];
    let mut opposite = observation(11, 2, 101);
    opposite.counters.uploadBodyBytesProvided = 1;
    invalid.push(opposite);
    for next in invalid {
        let mut decoder = Decoder::new(&input);
        decoder
            .consume(&line(0, Event::Progress(first)), &mut |_| Ok(()))
            .unwrap();
        assert!(
            decoder
                .consume(&line(1, Event::Progress(next)), &mut |_| Ok(()))
                .is_err(),
            "{next:?}"
        );
    }
    let mut decoder = Decoder::new(&input);
    for (index, active) in [2, 0, 2].into_iter().enumerate() {
        let result = decoder.consume(
            &line(
                index as u32,
                Event::Progress(observation(index as u64, active, index as u64)),
            ),
            &mut |_| Ok(()),
        );
        assert_eq!(result.is_err(), index == 2);
    }
}

#[test]
fn rejectsBrokenFramingFieldsSequenceAndTerminalCounters() {
    let input = input("127.0.0.1:8080".parse().unwrap(), Direction::Download);
    for mut value in [
        serde_json::json!({"version":2,"sequence":0,"event":{"kind":"progress","data":observation(1,1,1)}}),
        serde_json::json!({"version":1,"sequence":1,"event":{"kind":"progress","data":observation(1,1,1)}}),
    ] {
        let mut bytes = serde_json::to_vec(&value).unwrap();
        bytes.push(b'\n');
        assert!(
            Decoder::new(&input)
                .consume(&bytes, &mut |_| Ok(()))
                .is_err()
        );
        value["version"] = 1.into();
        value["sequence"] = 0.into();
        value["extra"] = true.into();
        let mut bytes = serde_json::to_vec(&value).unwrap();
        bytes.push(b'\n');
        assert!(
            Decoder::new(&input)
                .consume(&bytes, &mut |_| Ok(()))
                .is_err()
        );
    }
    let duplicate=b"{\"version\":1,\"version\":1,\"sequence\":0,\"event\":{\"kind\":\"progress\",\"data\":{\"elapsedMicros\":1,\"counters\":{\"downloadBytesRead\":1,\"uploadBodyBytesProvided\":0,\"activeRequests\":1}}}}\n";
    assert!(
        Decoder::new(&input)
            .consume(duplicate, &mut |_| Ok(()))
            .is_err()
    );
    assert!(
        Decoder::new(&input)
            .consume(
                &line(0, Event::Result(Box::new(response(&input)))),
                &mut |_| Ok(())
            )
            .is_err()
    );
    let mut decoder = Decoder::new(&input);
    decoder
        .consume(&completed(&input), &mut |_| Ok(()))
        .unwrap();
    assert!(decoder.consume(b" ", &mut |_| Ok(())).is_err());
    let mut decoder = Decoder::new(&input);
    decoder.consume(b"{", &mut |_| Ok(())).unwrap();
    assert!(decoder.finish().is_err());
    assert!(Decoder::new(&input).finish().is_err());
}

#[test]
fn frameBudgetsAndConsumerFailureStopDecoding() {
    let input = input("127.0.0.1:8080".parse().unwrap(), Direction::Download);
    assert!(
        Decoder::new(&input)
            .consume(&vec![b' '; FRAME_BYTES + 1], &mut |_| Ok(()))
            .is_err()
    );
    assert!(
        Decoder::new(&input)
            .consume(&vec![b' '; STREAM_BYTES + 1], &mut |_| Ok(()))
            .is_err()
    );
    let mut decoder = Decoder::new(&input);
    for index in 0..MAX_FRAMES {
        decoder
            .consume(
                &line(
                    index,
                    Event::Progress(observation(u64::from(index) + 1, 0, u64::from(index))),
                ),
                &mut |_| Ok(()),
            )
            .unwrap();
    }
    assert!(
        decoder
            .consume(
                &line(MAX_FRAMES, Event::Progress(observation(4097, 0, 4097))),
                &mut |_| Ok(())
            )
            .is_err()
    );
    let error = Decoder::new(&input)
        .consume(&line(0, Event::Progress(observation(1, 1, 1))), &mut |_| {
            Err("consumer refused progress".into())
        })
        .unwrap_err();
    assert!(error.to_string().contains("consumer refused"));
}

#[test]
fn preservesFailedTransferResultsAndReadableStartupDiagnostics() {
    let input = input("127.0.0.1:8080".parse().unwrap(), Direction::Download);
    let mut response = response(&input);
    response.result.status = TransferStatus::NetworkError;
    response.result.acceptedPayloadBytes = 0;
    response.result.applicationGoodputMbps = None;
    for stream in &mut response.result.streams {
        stream.status = TransferStatus::NetworkError;
        stream.acceptedPayloadBytes = 0;
        stream.downloadBytesRead = 0;
        stream.remoteAddress = None;
        stream.httpStatus = None;
        stream.error = Some("fixture connection refused".into());
    }
    let mut decoder = Decoder::new(&input);
    decoder
        .consume(&line(0, Event::Result(Box::new(response))), &mut |_| {
            panic!("no payload progress should be invented")
        })
        .unwrap();
    let result = decoder.finish().unwrap();
    assert_eq!(result.status, TransferStatus::NetworkError);
    assert_eq!(
        result.streams[0].error.as_deref(),
        Some("fixture connection refused")
    );
    let error = Decoder::new(&input)
        .consume(
            b"Dedicated service error: fixture startup permission denied.\x1b\n",
            &mut |_| Ok(()),
        )
        .unwrap_err()
        .to_string();
    assert!(error.contains("fixture startup permission denied"));
    assert!(!error.contains('\x1b'));
    assert!(error.len() < 1024);
}
