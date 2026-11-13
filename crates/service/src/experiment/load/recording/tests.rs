use super::*;
use crate::experiment::{
    baseline::tests::Database,
    load::tests::{fixture, plan},
};

fn prepared(database: &mut Connection) -> (Recorder, SessionRun) {
    let (scope, policy, routes) = fixture();
    let plan = plan(&scope);
    let header = Header::capture(
        &scope,
        &plan,
        Configuration::Original,
        None,
        &(policy, routes),
    )
    .unwrap();
    let run = session::runSourceBoundSessionWithRunner(
        scope.config,
        scope.sessionPlan,
        scope.bindings,
        &AtomicBool::new(true),
        |_| {},
        &Runner,
    )
    .unwrap();
    (Recorder::start(database, header).unwrap(), run)
}

fn idle(header: &Header) -> SessionProgress {
    SessionProgress {
        providerIndex: 0,
        providerCount: header.sessionPlan.providers.len(),
        phase: session::Phase::Idle,
        downloadBytesRead: 0,
        uploadBodyBytesProvided: 0,
        sample: None,
    }
}

#[test]
fn earlierRecordedExecutionRemainsReadableWithoutUpgradingItsCohort() {
    let storage = Database::new();
    let mut database = storage.open();
    let (scope, policy, routes) = fixture();
    let plan = plan(&scope);
    let mut header = Header::capture(
        &scope,
        &plan,
        Configuration::Original,
        None,
        &(policy, routes),
    )
    .unwrap();
    let mut run = session::runSourceBoundSessionWithRunner(
        scope.config,
        scope.sessionPlan,
        scope.bindings,
        &AtomicBool::new(true),
        |_| {},
        &Runner,
    )
    .unwrap();
    let currentCohort = header.experiment.comparison.cohortSha256.clone();
    header.execution = TransferExecution::RecordedRestrictedWorkerV1;
    run.transferExecution = Some(header.execution);
    header.experiment.comparison.cohortSha256 =
        comparisonLoad::cohortSha256(&run, &header.selections).unwrap();
    assert_ne!(header.experiment.comparison.cohortSha256, currentCohort);
    let legacyCohort = header.experiment.comparison.cohortSha256.clone();
    let mut recorder = Recorder::start(&mut database, header).unwrap();
    recorder
        .append(&mut database, idle(&recorder.header), nowUnixMs().unwrap())
        .unwrap();
    recorder.finish(&mut database, &mut run, None).unwrap();
    drop(database);
    let database = storage.open();
    let saved = history(&database, 1).unwrap();
    assert_eq!(
        saved[0].header.execution,
        TransferExecution::RecordedRestrictedWorkerV1
    );
    assert_eq!(
        saved[0].header.experiment.comparison.cohortSha256,
        legacyCohort
    );
    assert_eq!(saved[0].runId, Some(run.id));
}

#[test]
fn fullMultiProviderHeaderSurvivesDurableReadbackWithoutTruncatingRules() {
    let storage = Database::new();
    let mut database = storage.open();
    let (scope, policy, mut routes) = crate::experiment::load::tests::wideFixture(3, 6);
    for route in &mut routes {
        let routing::Capture::Captured { snapshot } = route else {
            unreachable!()
        };
        snapshot.linkStatistics = Some(Box::new(crate::routing::tests::statistics(
            snapshot.capturedAtUnixMs,
        )));
    }
    let plan = plan(&scope);
    let header = Header::capture(
        &scope,
        &plan,
        Configuration::Original,
        None,
        &(policy, routes),
    )
    .unwrap();
    let bytes = payload(&header, HEADER_BYTES).unwrap();
    assert!(bytes.len() > 131_072);
    assert!(bytes.len() <= 1024 * 1024);
    let mut recorder = Recorder::start(&mut database, header).unwrap();
    let id = recorder.header.id;
    recorder
        .abort(&mut database, "fixture collection not started")
        .unwrap();
    drop(database);
    let database = storage.open();
    let records = history(&database, 1).unwrap();
    assert_eq!(records[0].header.id, id);
    assert_eq!(records[0].header.selections.len(), 438);
    assert_eq!(records[0].header.experiment.comparison.metrics.len(), 438);
    assert!(records[0].header.routesBefore.iter().all(|route| matches!(route, routing::Capture::Captured { snapshot } if snapshot.linkStatistics.as_ref().is_some_and(|statistics| statistics.receivedOctets == "9007199254740993"))));
    assert_eq!(records[0].state, State::Interrupted);
}

#[test]
fn progressAndFinalReportSurviveDatabaseReopen() {
    let storage = Database::new();
    let mut database = storage.open();
    let (mut recorder, mut run) = prepared(&mut database);
    recorder
        .append(&mut database, idle(&recorder.header), nowUnixMs().unwrap())
        .unwrap();
    recorder
        .finish(&mut database, &mut run, Some("fixture cancelled"))
        .unwrap();
    drop(database);
    let database = storage.open();
    let records = history(&database, 10).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].state, State::Finalized);
    assert_eq!(records[0].runId, Some(run.id));
    assert_eq!(records[0].events.len(), 1);
    assert_eq!(records[0].detail.as_deref(), Some("fixture cancelled"));
}

#[test]
fn emptyHistoryDoesNotCreateTablesAndALiveOwnerBlocksAnotherRecording() {
    let storage = Database::new();
    let mut database = storage.open();
    assert!(history(&database, 100).unwrap().is_empty());
    let count: u32 = database
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'adapter_load_recording%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
    let (mut recorder, _) = prepared(&mut database);
    assert!(
        initialize(&mut database)
            .unwrap_err()
            .to_string()
            .contains("still alive")
    );
    assert_eq!(history(&database, 100).unwrap()[0].state, State::Recording);
    recorder.abort(&mut database, "fixture stopped").unwrap();
    assert!(
        recorder
            .append(&mut database, idle(&recorder.header), nowUnixMs().unwrap())
            .is_err()
    );
    let (mut next, _) = prepared(&mut database);
    next.abort(&mut database, "fixture cleanup").unwrap();
    assert_eq!(history(&database, 100).unwrap().len(), 2);
}

#[test]
fn failedAppendAndFinalizationCannotCommitPartialRowsOrInventAReport() {
    let storage = Database::new();
    let mut database = storage.open();
    let (mut recorder, mut run) = prepared(&mut database);
    database.execute_batch("CREATE TRIGGER refuse_progress BEFORE INSERT ON adapter_load_recording_events BEGIN SELECT RAISE(ABORT,'fixture refused progress'); END;").unwrap();
    assert!(
        recorder
            .append(&mut database, idle(&recorder.header), nowUnixMs().unwrap())
            .is_err()
    );
    assert!(history(&database, 1).unwrap()[0].events.is_empty());
    database.execute_batch("DROP TRIGGER refuse_progress; CREATE TRIGGER refuse_finish BEFORE UPDATE ON adapter_load_recordings WHEN NEW.state='finalized' BEGIN SELECT RAISE(ABORT,'fixture refused finalization'); END;").unwrap();
    assert!(recorder.finish(&mut database, &mut run, None).is_err());
    assert_eq!(
        database
            .query_row::<u32, _, _>("SELECT COUNT(*) FROM load_sessions", [], |row| row.get(0))
            .unwrap(),
        0
    );
    assert_eq!(history(&database, 1).unwrap()[0].state, State::Recording);
    database
        .execute_batch("DROP TRIGGER refuse_finish")
        .unwrap();
    recorder.abort(&mut database, "fixture cleanup").unwrap();
}

#[test]
fn boundsClockAndPhaseFailuresLeaveTheCommittedPrefixUnchanged() {
    let storage = Database::new();
    let mut database = storage.open();
    let (mut recorder, _) = prepared(&mut database);
    let time = nowUnixMs().unwrap();
    recorder
        .append(&mut database, idle(&recorder.header), time)
        .unwrap();
    let mut download = idle(&recorder.header);
    download.phase = session::Phase::Download;
    download.downloadBytesRead = 1024;
    recorder
        .append(&mut database, download.clone(), time)
        .unwrap();
    for failure in 0..7 {
        let mut update = download.clone();
        let mut capturedAt = time;
        match failure {
            0 => update.providerIndex = usize::MAX,
            1 => update.providerCount += 1,
            2 => {
                update.downloadBytesRead = recorder.header.sessionPlan.downloadBytesPerProvider + 1
            }
            3 => update.uploadBodyBytesProvided = 1,
            4 => update.downloadBytesRead = 1023,
            5 => update = idle(&recorder.header),
            _ => capturedAt = time - 1,
        }
        assert!(
            recorder.append(&mut database, update, capturedAt).is_err(),
            "{failure}"
        );
    }
    assert!(
        recorder
            .append(
                &mut database,
                download,
                recorder.header.experiment.expiresAtUnixMs
            )
            .is_err()
    );
    assert_eq!(history(&database, 1).unwrap()[0].events.len(), 2);
    recorder.metadata.eventCount = MAX_EVENTS;
    assert!(
        recorder
            .append(&mut database, idle(&recorder.header), time)
            .is_err()
    );
    assert_eq!(history(&database, 1).unwrap()[0].events.len(), 2);
    recorder.metadata.eventCount = 2;
    recorder.metadata.eventBytes = RECORDING_BYTES;
    assert!(
        recorder
            .append(
                &mut database,
                recorder.last.as_ref().unwrap().progress.clone(),
                time
            )
            .unwrap_err()
            .to_string()
            .contains("8 MiB")
    );
    assert_eq!(history(&database, 1).unwrap()[0].events.len(), 2);
}

#[test]
fn unsafeStorageAndOversizedHistoryAreRefused() {
    let mut memory = epp_core::storage::openDatabase(std::path::Path::new(":memory:")).unwrap();
    assert!(initialize(&mut memory).is_err());
    let storage = Database::new();
    let mut database = storage.open();
    let (mut recorder, _) = prepared(&mut database);
    database.pragma_update(None, "synchronous", "OFF").unwrap();
    assert!(
        recorder
            .append(&mut database, idle(&recorder.header), nowUnixMs().unwrap())
            .is_err()
    );
    assert!(history(&database, 1).unwrap()[0].events.is_empty());
    database.pragma_update(None, "synchronous", "FULL").unwrap();
    database
        .execute(
            "UPDATE adapter_load_recordings SET header_json=CAST(zeroblob(?1) AS TEXT)",
            [HISTORY_BYTES as i64 + 1],
        )
        .unwrap();
    assert!(
        history(&database, 1)
            .unwrap_err()
            .to_string()
            .contains("32 MiB")
    );
}

#[test]
fn reusedPidCannotKeepADeadRecordingActive() {
    let storage = Database::new();
    let mut database = storage.open();
    let (mut recorder, _) = prepared(&mut database);
    let creationTime = recorder
        .header
        .owner
        .creationTime100ns
        .parse::<u64>()
        .unwrap();
    recorder.header.owner.creationTime100ns = (creationTime - 1).to_string();
    let header = payload(&recorder.header, HEADER_BYTES).unwrap();
    let headerSha256 = checksum(&header);
    recorder.metadata.headSha256 = headerSha256.clone();
    let metadata = payload(&recorder.metadata, 8192).unwrap();
    let metadataSha256 = stateChecksum(recorder.header.id, &headerSha256, &metadata).unwrap();
    database.execute("UPDATE adapter_load_recordings SET header_json=?1,header_sha256=?2,metadata_json=?3,metadata_sha256=?4", params![header,headerSha256,metadata,metadataSha256]).unwrap();
    initialize(&mut database).unwrap();
    assert_eq!(history(&database, 1).unwrap()[0].state, State::Interrupted);
}

#[test]
fn eventReadbackAndHashChainsRefuseCorruptionBeforeCompletion() {
    for corruption in 0..4 {
        let storage = Database::new();
        let mut database = storage.open();
        let (mut recorder, mut run) = prepared(&mut database);
        recorder
            .append(&mut database, idle(&recorder.header), nowUnixMs().unwrap())
            .unwrap();
        match corruption {
            0 => database
                .execute(
                    "UPDATE adapter_load_recording_events SET payload_json='{}'",
                    [],
                )
                .unwrap(),
            1 => database
                .execute("DELETE FROM adapter_load_recording_events", [])
                .unwrap(),
            2 => database
                .execute("UPDATE adapter_load_recordings SET metadata_json='{}'", [])
                .unwrap(),
            _ => database
                .execute("UPDATE adapter_load_recordings SET header_json='{}'", [])
                .unwrap(),
        };
        assert!(history(&database, 1).is_err());
        assert!(recorder.finish(&mut database, &mut run, None).is_err());
        assert_eq!(
            database
                .query_row::<u32, _, _>("SELECT COUNT(*) FROM load_sessions", [], |row| row.get(0))
                .unwrap(),
            0
        );
    }
    let storage = Database::new();
    let mut database = storage.open();
    let (mut recorder, _) = prepared(&mut database);
    database.execute_batch("CREATE TRIGGER corrupt_progress AFTER INSERT ON adapter_load_recording_events BEGIN UPDATE adapter_load_recording_events SET payload_json='{}'; END;").unwrap();
    assert!(
        recorder
            .append(&mut database, idle(&recorder.header), nowUnixMs().unwrap())
            .unwrap_err()
            .to_string()
            .contains("Committed load progress")
    );
}

#[test]
fn finalReportsCannotChangeRecordedScopeOrPreviouslySavedProbes() {
    for failure in 0..7 {
        let storage = Database::new();
        let mut database = storage.open();
        let (mut recorder, mut run) = prepared(&mut database);
        recorder
            .append(&mut database, idle(&recorder.header), nowUnixMs().unwrap())
            .unwrap();
        let endpoint = &recorder.header.sessionPlan.latencyEndpoints[0];
        let sample = session::LatencySample {
            providerIndex: 0,
            phase: session::Phase::Idle,
            sample: epp_core::benchmark::Sample {
                endpointId: endpoint.id.clone(),
                address: endpoint.address.clone(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                connectMs: None,
                error: None,
                echo: Some(epp_core::icmp::EchoOutcome {
                    status: epp_core::icmp::EchoStatus::Reply,
                    rttMs: Some(10),
                    rttUnitMs: 1,
                    callDurationMs: 10.0,
                    responder: Some(endpoint.address.parse().unwrap()),
                    responderScopeId: None,
                    nativeCode: Some(0),
                }),
                dns: None,
            },
            inFlightRequestsAtStart: 0,
            inFlightRequestsAtEnd: 0,
            payloadProgressDuringProbe: 0,
        };
        let mut update = idle(&recorder.header);
        update.sample = Some(sample.clone());
        recorder
            .append(&mut database, update, nowUnixMs().unwrap())
            .unwrap();
        run.latencySamples.push(sample);
        match failure {
            0 => run.plan.streams += 1,
            1 => run.appVersion = "unexpected".into(),
            2 => run.transferExecution = Some(TransferExecution::RestrictedWorkerV2),
            3 => run.sourceBindings = None,
            4 => run.latencySamples[0].sample.echo.as_mut().unwrap().rttMs = Some(1),
            5 => run.latencySamples.clear(),
            _ => {
                recorder.finish(&mut database, &mut run, None).unwrap();
                assert_eq!(history(&database, 1).unwrap()[0].events.len(), 2);
                database
                    .execute("UPDATE load_sessions SET report_json='{}'", [])
                    .unwrap();
                assert!(history(&database, 1).is_err());
                continue;
            }
        }
        assert!(recorder.finish(&mut database, &mut run, None).is_err());
        assert_eq!(
            database
                .query_row::<u32, _, _>("SELECT COUNT(*) FROM load_sessions", [], |row| row.get(0))
                .unwrap(),
            0
        );
        assert_eq!(history(&database, 1).unwrap()[0].state, State::Recording);
    }
}

#[test]
#[ignore]
fn recordingOwnerFixture() {
    use std::io::Write;
    let path = std::path::PathBuf::from(std::env::var_os("EPP_LOAD_RECORDING_PATH").unwrap());
    assert!(path.is_absolute());
    let mut database = epp_core::storage::openDatabase(&path).unwrap();
    let (mut recorder, _) = prepared(&mut database);
    let time = nowUnixMs().unwrap();
    recorder
        .append(&mut database, idle(&recorder.header), time)
        .unwrap();
    let mut update = idle(&recorder.header);
    update.phase = session::Phase::Download;
    update.downloadBytesRead = 1024;
    recorder
        .append(&mut database, update.clone(), time)
        .unwrap();
    if std::env::var("EPP_LOAD_RECORDING_UNCOMMITTED").unwrap() == "true" {
        update.downloadBytesRead = 2048;
        let event = Event {
            sequence: 2,
            capturedAtUnixMs: time,
            progress: update,
        };
        let value = payload(&event, EVENT_BYTES).unwrap();
        let sha256 =
            eventChecksum(recorder.header.id, &recorder.metadata.headSha256, &value).unwrap();
        let mut metadata = recorder.metadata.clone();
        metadata.eventCount += 1;
        metadata.eventBytes += value.len() as u64;
        metadata.headSha256 = sha256.clone();
        let transaction = database
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        transaction
            .execute(
                "INSERT INTO adapter_load_recording_events VALUES(?1,?2,?3,?4)",
                params![
                    recorder.header.id.to_string(),
                    event.sequence,
                    value,
                    sha256
                ],
            )
            .unwrap();
        recorder.update(&transaction, &metadata).unwrap();
        println!("recording-ready");
        std::io::stdout().flush().unwrap();
        std::thread::sleep(Duration::from_secs(60));
        drop(transaction);
    } else {
        println!("recording-ready");
        std::io::stdout().flush().unwrap();
        std::thread::sleep(Duration::from_secs(60));
    }
}

#[test]
fn killedOwnersPreserveOnlyCommittedProgressWithoutResuming() {
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
                    "experiment::load::recording::tests::recordingOwnerFixture",
                    "--nocapture",
                ])
                .env("EPP_LOAD_RECORDING_PATH", path)
                .env("EPP_LOAD_RECORDING_UNCOMMITTED", uncommitted.to_string())
                .creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW)
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let output = owner.0.stdout.take().unwrap();
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let reader = std::thread::spawn(move || {
            let mut bytes = 0;
            for line in BufReader::new(output).lines() {
                let line = line.unwrap();
                bytes += line.len();
                assert!(bytes <= 8192);
                if line == "recording-ready" {
                    sender.send(()).unwrap();
                    return;
                }
            }
            panic!("recording owner exited before readiness");
        });
        receiver.recv_timeout(Duration::from_secs(10)).unwrap();
        reader.join().unwrap();
        let mut database = storage.open();
        let records = history(&database, 1).unwrap();
        assert_eq!(records[0].state, State::Recording);
        assert_eq!(records[0].events.len(), 2);
        assert_eq!(records[0].events[1].progress.downloadBytesRead, 1024);
        if !uncommitted {
            assert!(
                initialize(&mut database)
                    .unwrap_err()
                    .to_string()
                    .contains("still alive")
            );
        }
        owner.0.kill().unwrap();
        owner.0.wait().unwrap();
        initialize(&mut database).unwrap();
        let records = history(&database, 1).unwrap();
        assert_eq!(records[0].state, State::Interrupted);
        assert_eq!(records[0].events.len(), 2);
        assert_eq!(records[0].runId, None);
        assert_eq!(
            database
                .query_row::<u32, _, _>("SELECT COUNT(*) FROM load_sessions", [], |row| row.get(0))
                .unwrap(),
            0
        );
        initialize(&mut database).unwrap();
        assert_eq!(history(&database, 1).unwrap()[0].events.len(), 2);
    }
}
