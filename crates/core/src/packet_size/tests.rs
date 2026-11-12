use super::*;

pub(super) fn plan() -> Plan {
    Plan {
        source: Ipv4Addr::LOCALHOST,
        destination: Ipv4Addr::LOCALHOST,
        interfaceMtu: 1500,
        timeoutMs: 100,
        intervalMs: 25,
        budgetMs: 20_000,
    }
}

fn reply(plan: &Plan) -> EchoOutcome {
    EchoOutcome {
        status: EchoStatus::Reply,
        rttMs: Some(1),
        rttUnitMs: 1,
        callDurationMs: 1.0,
        responder: Some(plan.destination.into()),
        responderScopeId: None,
        nativeCode: Some(0),
    }
}

struct Fixture {
    cutoff: u32,
    largeTimeout: bool,
    missingSmall: bool,
    inconsistent: bool,
    changeBoundary: bool,
    delay: bool,
    largeCalls: usize,
    boundaryCalls: usize,
}

impl Fixture {
    fn new(cutoff: u32) -> Self {
        Self {
            cutoff,
            largeTimeout: false,
            missingSmall: false,
            inconsistent: false,
            changeBoundary: false,
            delay: false,
            largeCalls: 0,
            boundaryCalls: 0,
        }
    }
}

impl Probe for Fixture {
    fn measure(&mut self, plan: &Plan, bytes: u32, timeout: Duration) -> AppResult<EchoOutcome> {
        assert!((1..=u128::from(plan.timeoutMs)).contains(&timeout.as_millis()));
        if self.delay {
            std::thread::sleep(Duration::from_millis(1050));
        }
        if bytes == CONTROL_BYTES && self.missingSmall {
            return Ok(EchoOutcome::unavailable(EchoStatus::TimedOut));
        }
        if bytes > CONTROL_BYTES {
            self.largeCalls += 1;
        }
        if bytes == self.cutoff {
            self.boundaryCalls += 1;
        }
        if self.largeTimeout && bytes > CONTROL_BYTES {
            return Ok(EchoOutcome {
                nativeCode: Some(11010),
                ..EchoOutcome::unavailable(EchoStatus::TimedOut)
            });
        }
        let tooBig = bytes > self.cutoff
            || (self.changeBoundary && bytes == self.cutoff && self.boundaryCalls > 3);
        if tooBig && !(self.inconsistent && self.largeCalls.is_multiple_of(2)) {
            return Ok(EchoOutcome {
                nativeCode: Some(PACKET_TOO_BIG),
                ..EchoOutcome::unavailable(EchoStatus::IpError)
            });
        }
        Ok(reply(plan))
    }
}

#[test]
fn successfulFullSizeRequestsDoNotInventASmallerMtu() {
    let report = diagnose(
        plan(),
        &mut Fixture::new(1500),
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap();
    assert_eq!(report.outcome, Outcome::TestedLimitReached);
    report.validate().unwrap();
    assert_eq!(report.largestSuccessfulBytes, Some(1500));
    assert!(report.confirmedBoundaryBytes.is_none());
    assert!(report.smallestTooBigBytes.is_none());
    assert_eq!(report.samples.len(), 10);
    assert_eq!(
        report.requestedIpv4Bytes,
        report
            .samples
            .iter()
            .map(|sample| u64::from(sample.packetBytes))
            .sum::<u64>()
    );
    assert!(report.samples.iter().all(|sample| sample.dontFragment));
}

#[test]
fn explicitTooBigResponsesBracketAndReconfirmAnExactNonPresetBoundary() {
    let report = diagnose(
        plan(),
        &mut Fixture::new(1427),
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap();
    assert_eq!(report.outcome, Outcome::SizeBoundaryObserved);
    report.validate().unwrap();
    assert_eq!(report.confirmedBoundaryBytes, Some(1427));
    assert_eq!(report.largestSuccessfulBytes, Some(1427));
    assert_eq!(report.smallestTooBigBytes, Some(1428));
    assert!(report.samples.len() <= MAX_PROBES);
    assert_eq!(
        report
            .samples
            .iter()
            .filter(|sample| sample.packetBytes == 1427 && !sample.control)
            .count(),
        6
    );
    assert!(report.requestedIpv4Bytes <= MAX_PROBES as u64 * u64::from(MAX_PACKET_BYTES));
}

#[test]
fn sizeDependentTimeoutsAreInconclusiveAndNeverDriveTheBinarySearch() {
    let mut probe = Fixture::new(1500);
    probe.largeTimeout = true;
    let report = diagnose(plan(), &mut probe, &AtomicBool::new(false), |_| {}).unwrap();
    assert_eq!(report.outcome, Outcome::Inconclusive);
    assert_eq!(probe.largeCalls, 1);
    assert!(report.confirmedBoundaryBytes.is_none());
    assert!(report.smallestTooBigBytes.is_none());
}

#[test]
fn missingControlsAndInconsistentErrorsCannotEstablishABoundary() {
    let mut missing = Fixture::new(1400);
    missing.missingSmall = true;
    let report = diagnose(plan(), &mut missing, &AtomicBool::new(false), |_| {}).unwrap();
    assert_eq!(report.outcome, Outcome::SmallPacketsUnavailable);
    assert_eq!(missing.largeCalls, 0);
    let mut inconsistent = Fixture::new(1400);
    inconsistent.inconsistent = true;
    let report = diagnose(plan(), &mut inconsistent, &AtomicBool::new(false), |_| {}).unwrap();
    assert_eq!(report.outcome, Outcome::Inconclusive);
    assert!(report.confirmedBoundaryBytes.is_none());
}

#[test]
fn aBoundaryThatChangesDuringConfirmationStaysInconclusive() {
    let mut probe = Fixture::new(1427);
    probe.changeBoundary = true;
    let report = diagnose(plan(), &mut probe, &AtomicBool::new(false), |_| {}).unwrap();
    assert_eq!(report.outcome, Outcome::Inconclusive);
    assert!(report.confirmedBoundaryBytes.is_none());
}

#[test]
fn cancellationAndTimeBudgetsPreservePartialSamplesWithoutExtraRequests() {
    let cancel = AtomicBool::new(false);
    let report = diagnose(plan(), &mut Fixture::new(1500), &cancel, |sample| {
        if sample.sequence == 2 {
            cancel.store(true, Ordering::SeqCst);
        }
    })
    .unwrap();
    assert_eq!(report.outcome, Outcome::Cancelled);
    assert_eq!(report.samples.len(), 3);
    let mut short = plan();
    short.budgetMs = 1000;
    let mut slow = Fixture::new(1500);
    slow.delay = true;
    let report = diagnose(short, &mut slow, &AtomicBool::new(false), |_| {}).unwrap();
    assert_eq!(report.outcome, Outcome::BudgetExpired);
    assert_eq!(report.samples.len(), 1);
}

#[test]
fn malformedSuccessEvidenceAndUnsafePlansAreRejected() {
    let plan = plan();
    let mut bad = reply(&plan);
    bad.rttMs = None;
    assert_eq!(classify(&plan, &bad), Classification::Unknown);
    bad = reply(&plan);
    bad.responder = Some(Ipv4Addr::new(127, 0, 0, 2).into());
    assert_eq!(classify(&plan, &bad), Classification::Unknown);
    for address in [
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::BROADCAST,
        Ipv4Addr::new(224, 0, 0, 1),
    ] {
        let mut invalid = plan.clone();
        invalid.destination = address;
        assert!(invalid.validate().is_err());
    }
    let mut invalid = plan.clone();
    invalid.interfaceMtu = 575;
    assert!(invalid.validate().is_err());
}

#[test]
fn storedConclusionsRequireTheFullMatchingConfirmationSequence() {
    let report = diagnose(
        plan(),
        &mut Fixture::new(1427),
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap();
    let value = serde_json::to_value(&report).unwrap();
    for field in [
        "confirmedBoundaryBytes",
        "largestSuccessfulBytes",
        "requestedIpv4Bytes",
    ] {
        let mut changed = value.clone();
        changed[field] = serde_json::json!(1000);
        assert!(
            serde_json::from_value::<Report>(changed)
                .unwrap()
                .validate()
                .is_err(),
            "{field}"
        );
    }
    let mut changed = value.clone();
    changed["samples"][4]["packetBytes"] = serde_json::json!(1400);
    assert!(
        serde_json::from_value::<Report>(changed)
            .unwrap()
            .validate()
            .is_err()
    );
    let mut changed = value;
    changed["samples"].as_array_mut().unwrap().pop();
    changed["requestedIpv4Bytes"] = serde_json::json!(report.requestedIpv4Bytes - 84);
    assert!(
        serde_json::from_value::<Report>(changed)
            .unwrap()
            .validate()
            .is_err()
    );
}

#[test]
fn minimumInterfaceMtuAndNativeLargeMtuSentinelsStayBounded() {
    let mut minimum = plan();
    minimum.interfaceMtu = MIN_SEARCH_BYTES;
    let report = diagnose(
        minimum,
        &mut Fixture::new(575),
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap();
    assert_eq!(report.outcome, Outcome::Inconclusive);
    assert!(report.confirmedBoundaryBytes.is_none());
    let mut large = plan();
    large.interfaceMtu = u32::MAX;
    let report = diagnose(
        large,
        &mut Fixture::new(9000),
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap();
    report.validate().unwrap();
    assert_eq!(report.maximumTestedBytes, 9000);
    assert_eq!(report.plan.interfaceMtu, u32::MAX);
}

#[cfg(windows)]
#[test]
fn nativeWindowsSourceBoundDfProbesReturnTheRequestedLoopbackPayloadSizes() {
    let mut plan = plan();
    plan.interfaceMtu = 65535;
    plan.timeoutMs = 500;
    let mut probe = NativeProbe::default();
    for bytes in [84, 576, 1500, 9000, 84] {
        let echo = probe
            .measure(&plan, bytes, Duration::from_millis(500))
            .unwrap();
        assert_eq!(echo.status, EchoStatus::Reply, "{bytes} bytes: {echo:?}");
        assert_eq!(echo.responder, Some(Ipv4Addr::LOCALHOST.into()));
        assert_eq!(echo.nativeCode, Some(0));
    }
}

#[test]
fn explicitResourceLimitsStopBeforeTheNextProbeAndPermitExactCompletion() {
    struct Counting {
        fixture: Fixture,
        calls: usize,
    }
    impl Probe for Counting {
        fn measure(
            &mut self,
            plan: &Plan,
            bytes: u32,
            timeout: Duration,
        ) -> AppResult<EchoOutcome> {
            self.calls += 1;
            self.fixture.measure(plan, bytes, timeout)
        }
    }
    for (maximumProbes, maximumRequestedIpv4Bytes, completed) in [
        (10, 5088, true),
        (9, 5088, false),
        (10, 5087, false),
        (10, 1, false),
    ] {
        let mut probe = Counting {
            fixture: Fixture::new(1500),
            calls: 0,
        };
        let report = diagnoseWithLimits(
            plan(),
            Limits {
                maximumProbes,
                maximumRequestedIpv4Bytes,
            },
            &mut probe,
            &AtomicBool::new(false),
            |_| {},
        )
        .unwrap();
        report.validate().unwrap();
        assert_eq!(probe.calls, report.samples.len());
        assert!(report.samples.len() <= maximumProbes);
        assert!(report.requestedIpv4Bytes <= maximumRequestedIpv4Bytes);
        assert_eq!(
            report.outcome,
            if completed {
                Outcome::TestedLimitReached
            } else {
                Outcome::BudgetExpired
            }
        );
    }
    for limits in [
        Limits {
            maximumProbes: 0,
            ..Limits::default()
        },
        Limits {
            maximumProbes: 145,
            ..Limits::default()
        },
        Limits {
            maximumRequestedIpv4Bytes: 0,
            ..Limits::default()
        },
        Limits {
            maximumRequestedIpv4Bytes: 1_296_001,
            ..Limits::default()
        },
    ] {
        let mut probe = Counting {
            fixture: Fixture::new(1500),
            calls: 0,
        };
        assert!(
            diagnoseWithLimits(plan(), limits, &mut probe, &AtomicBool::new(false), |_| {})
                .is_err()
        );
        assert_eq!(probe.calls, 0);
    }
}
