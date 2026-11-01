use super::*;
use crate::{recovery::WritePurpose, watchdog::tests::fixture};

#[test]
fn automaticTrialMeasuresRealLocalTcpWhileAppliedAndVerifiesOriginalAfterward() {
    let mut fixture = fixture();
    let first = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let second = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoints = [first.local_addr().unwrap(), second.local_addr().unwrap()];
    let report = execute(
        &mut fixture.journal,
        &mut fixture.backend,
        fixture.document.clone(),
        &AtomicBool::new(false),
        Policy::default(),
        |control| {
            let mut timings = Vec::new();
            for _ in 0..3 {
                for endpoint in endpoints {
                    control.heartbeat()?;
                    let start = std::time::Instant::now();
                    let _connection = std::net::TcpStream::connect_timeout(
                        &endpoint,
                        Duration::from_millis(100),
                    )?;
                    timings.push(start.elapsed().as_secs_f64() * 1000.0);
                }
            }
            Ok(timings)
        },
    )
    .unwrap();
    assert_eq!(report.outcome, Outcome::Completed);
    assert_eq!(report.measurement.unwrap().len(), 6);
    assert_eq!(fixture.backend.native.settings.nlMtu, 1500);
    assert_eq!(
        fixture.backend.writes,
        [WritePurpose::Apply, WritePurpose::Restore]
    );
    assert!(report.watchdog.unwrap().originalVerified());
    assert!(fixture.journal.pendingRecovery().unwrap().is_empty());
}

#[test]
fn measurementFailureOrPanicAlwaysWaitsForVerifiedRollback() {
    for panics in [true, false] {
        let mut fixture = fixture();
        let report = execute::<u32, _>(
            &mut fixture.journal,
            &mut fixture.backend,
            fixture.document.clone(),
            &AtomicBool::new(false),
            Policy::default(),
            |_| {
                if panics {
                    panic!("fixture measurement worker panic");
                }
                Err("fixture measurement failed".into())
            },
        )
        .unwrap();
        assert_eq!(report.outcome, Outcome::MeasurementFailed);
        assert!(report.measurement.is_none());
        assert_eq!(fixture.backend.native.settings.nlMtu, 1500);
        assert!(report.watchdog.unwrap().originalVerified());
    }
}

#[test]
fn automaticRollbackWhileCollectorStallsInvalidatesItsLaterSuccessfulReturn() {
    let mut fixture = fixture();
    let report = execute(
        &mut fixture.journal,
        &mut fixture.backend,
        fixture.document.clone(),
        &AtomicBool::new(false),
        Policy {
            heartbeatTimeout: Duration::from_millis(50),
            verificationInterval: Duration::from_millis(50),
            pollInterval: Duration::from_millis(10),
        },
        |_| {
            std::thread::sleep(Duration::from_millis(150));
            Ok(42)
        },
    )
    .unwrap();
    assert_eq!(report.outcome, Outcome::Interrupted);
    assert_eq!(report.measurement, Some(42));
    let watch = report.watchdog.unwrap();
    assert_eq!(watch.trigger, Trigger::HeartbeatLost);
    assert!(watch.originalVerified());
    assert_eq!(fixture.backend.native.settings.nlMtu, 1500);
}

#[test]
fn failedRestoreNeverBecomesACompletedTrialDespiteSuccessfulMeasurements() {
    let mut fixture = fixture();
    fixture.backend.failRestore = true;
    let report = execute(
        &mut fixture.journal,
        &mut fixture.backend,
        fixture.document.clone(),
        &AtomicBool::new(false),
        Policy::default(),
        |_| Ok(42),
    )
    .unwrap();
    assert_eq!(report.outcome, Outcome::RecoveryRequired);
    assert_eq!(fixture.backend.native.settings.nlMtu, 1400);
    assert_eq!(fixture.journal.pendingRecovery().unwrap().len(), 1);
}

#[test]
fn anApplyPanicAfterTheWriteStillRestoresBeforeReturning() {
    let mut fixture = fixture();
    fixture.backend.panicAfterApply = true;
    let report = execute(
        &mut fixture.journal,
        &mut fixture.backend,
        fixture.document.clone(),
        &AtomicBool::new(false),
        Policy::default(),
        |_| Ok(42),
    )
    .unwrap();
    assert_eq!(report.outcome, Outcome::ApplyFailed);
    assert!(report.measurement.is_none());
    assert!(report.recovery.unwrap().originalMtuVerified);
    assert_eq!(fixture.backend.native.settings.nlMtu, 1500);
    assert!(fixture.journal.pendingRecovery().unwrap().is_empty());
}

#[test]
fn noCollectorStartsForDeniedPermissionInvalidPolicyOrPendingRecovery() {
    let mut fixture = fixture();
    fixture.backend.allow = false;
    let report = execute(
        &mut fixture.journal,
        &mut fixture.backend,
        fixture.document.clone(),
        &AtomicBool::new(false),
        Policy::default(),
        |_| -> ServiceResult<()> {
            panic!("collector must not start");
        },
    )
    .unwrap();
    assert_eq!(report.outcome, Outcome::ApplyFailed);
    assert!(fixture.backend.writes.is_empty());
    let mut fixture = crate::watchdog::tests::fixture();
    assert!(
        execute(
            &mut fixture.journal,
            &mut fixture.backend,
            fixture.document.clone(),
            &AtomicBool::new(false),
            Policy {
                pollInterval: Duration::ZERO,
                ..Policy::default()
            },
            |_| Ok(42)
        )
        .is_err()
    );
    fixture
        .journal
        .prepare(fixture.document.clone(), nowUnixMs().unwrap())
        .unwrap();
    assert!(
        execute(
            &mut fixture.journal,
            &mut fixture.backend,
            fixture.document.clone(),
            &AtomicBool::new(false),
            Policy::default(),
            |_| Ok(42)
        )
        .is_err()
    );
    assert!(fixture.backend.writes.is_empty());
}
