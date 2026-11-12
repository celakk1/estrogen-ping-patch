use super::*;
use epp_core::icmp::{EchoOutcome, EchoStatus};

struct Fixture {
    policy: policy::Capture,
    routes: Vec<routing::Capture>,
    cutoff: u32,
    policies: usize,
    routeCalls: usize,
    probes: usize,
    refuseFinal: bool,
    driftFinal: bool,
    staleBefore: bool,
}

fn fixture() -> (Plan, Fixture) {
    let (_, _, _, _, policy, routes) = crate::experiment::baseline::tests::evidence();
    let targets = routes
        .iter()
        .map(|capture| match capture {
            routing::Capture::Captured { snapshot } => snapshot.destination.clone(),
            _ => panic!("fixture route unavailable"),
        })
        .collect();
    (
        Plan {
            adapterGuid: policy.native.adapterGuid,
            targets,
            maximumDurationMs: 60_000,
            maximumProbes: 288,
            maximumRequestedIpv4Bytes: 2_592_000,
        },
        Fixture {
            policy,
            routes,
            cutoff: 1500,
            policies: 0,
            routeCalls: 0,
            probes: 0,
            refuseFinal: false,
            driftFinal: false,
            staleBefore: false,
        },
    )
}

impl Probe for Fixture {
    fn measure(
        &mut self,
        plan: &packet_size::Plan,
        bytes: u32,
        _: Duration,
    ) -> epp_core::AppResult<EchoOutcome> {
        self.probes += 1;
        assert_eq!(
            plan.source,
            "192.0.2.2".parse::<std::net::Ipv4Addr>().unwrap()
        );
        assert_eq!(plan.interfaceMtu, 1500);
        assert_eq!(plan.timeoutMs, 750);
        assert_eq!(plan.intervalMs, 75);
        let tooBig = bytes > self.cutoff;
        Ok(EchoOutcome {
            status: if tooBig {
                EchoStatus::IpError
            } else {
                EchoStatus::Reply
            },
            rttMs: if tooBig { None } else { Some(1) },
            rttUnitMs: 1,
            callDurationMs: 1.0,
            responder: if tooBig {
                None
            } else {
                Some(plan.destination.into())
            },
            responderScopeId: None,
            nativeCode: Some(if tooBig { 11009 } else { 0 }),
        })
    }
}

impl Backend for Fixture {
    fn policy(&mut self, adapterGuid: Uuid, _: &AtomicBool) -> ServiceResult<policy::Capture> {
        assert_eq!(adapterGuid, self.policy.native.adapterGuid);
        self.policies += 1;
        if self.refuseFinal && self.policies == 2 {
            return Err("fixture final policy unavailable".into());
        }
        let mut current = self.policy.clone();
        current.native.capturedAtUnixMs = crate::watchdog::nowUnixMs()?;
        if self.staleBefore && self.policies == 1 {
            current.native.capturedAtUnixMs -= 6000;
        }
        Ok(current)
    }
    fn routes(
        &mut self,
        targets: &[routing::Address],
        _: &AtomicBool,
    ) -> ServiceResult<Vec<routing::Capture>> {
        self.routeCalls += 1;
        assert_eq!(targets.len(), self.routes.len());
        let mut routes = self.routes.clone();
        for route in &mut routes {
            if let routing::Capture::Captured { snapshot } = route {
                snapshot.capturedAtUnixMs = crate::watchdog::nowUnixMs()?;
                if self.driftFinal && self.routeCalls == 2 {
                    snapshot.routeMetric += 1;
                }
            }
        }
        Ok(routes)
    }
}

#[test]
fn fullSizeCollectionCapturesItsOwnContextAndDoesNotInventAProposal() {
    let (plan, mut backend) = fixture();
    let mut delivered = 0;
    let collection = collectWithBackend(
        plan,
        &AtomicBool::new(false),
        |_, _| {
            delivered += 1;
            Ok(())
        },
        &mut backend,
    )
    .unwrap();
    let json = serde_json::to_value(&collection).unwrap();
    let Collection::Completed {
        evidence, proposal, ..
    } = collection
    else {
        panic!("{json}")
    };
    assert!(proposal.is_none());
    assert_eq!(evidence.reports.len(), 2);
    assert_eq!(backend.policies, 2);
    assert_eq!(backend.routeCalls, 2);
    assert_eq!(backend.probes, 20);
    assert_eq!(delivered, 20);
    assert_eq!(json["status"], "completed");
}

#[test]
fn completeControlledBoundariesProduceAnEvidenceBoundProposal() {
    let (plan, mut backend) = fixture();
    backend.cutoff = 1427;
    let collection =
        collectWithBackend(plan, &AtomicBool::new(false), |_, _| Ok(()), &mut backend).unwrap();
    let json = serde_json::to_value(&collection).unwrap();
    let Collection::Completed {
        evidence,
        proposal: Some(proposal),
        ..
    } = collection
    else {
        panic!("{json}")
    };
    assert_eq!(proposal.summary().proposedMtu, 1427);
    assert_eq!(proposal.summary().boundaryTargets.len(), 2);
    assert_eq!(evidence.reports.len(), 2);
    assert_eq!(json["proposal"]["proposedMtu"], 1427);
    assert!(json["proposal"].get("deadline").is_none());
}

#[test]
fn limitsCancellationAndObserverFailurePreserveTheRawPrefix() {
    for failure in 0..5 {
        let (mut plan, mut backend) = fixture();
        let cancelled = AtomicBool::new(false);
        match failure {
            0 => {
                backend.cutoff = 1427;
                plan.maximumProbes = 20;
                plan.maximumRequestedIpv4Bytes = 180_000;
            }
            1 => plan.maximumRequestedIpv4Bytes = 1,
            4 => plan.maximumRequestedIpv4Bytes = 5340,
            _ => {}
        }
        let mut delivered = 0;
        let collection = collectWithBackend(
            plan.clone(),
            &cancelled,
            |_, _| {
                delivered += 1;
                if delivered == 3 {
                    if failure == 2 {
                        cancelled.store(true, Ordering::SeqCst);
                    }
                    if failure == 3 {
                        return Err("fixture observer refused progress".into());
                    }
                }
                Ok(())
            },
            &mut backend,
        )
        .unwrap();
        let Collection::Stopped {
            reason, evidence, ..
        } = collection
        else {
            panic!("expected interrupted diagnosis")
        };
        assert_eq!(evidence.reports.len(), if failure == 4 { 2 } else { 1 });
        for report in &evidence.reports {
            report.validate().unwrap();
        }
        let samples: usize = evidence
            .reports
            .iter()
            .map(|report| report.samples.len())
            .sum();
        let bytes: u64 = evidence
            .reports
            .iter()
            .map(|report| report.requestedIpv4Bytes)
            .sum();
        assert_eq!(samples, backend.probes);
        assert!(samples <= plan.maximumProbes);
        assert!(bytes <= plan.maximumRequestedIpv4Bytes);
        if failure == 4 {
            assert_eq!((samples, bytes), (13, 5340));
        }
        assert!(evidence.after.is_none());
        assert_eq!(backend.policies, 1);
        assert_eq!(
            reason,
            match failure {
                0 | 4 => StopReason::TrafficLimit,
                1 => StopReason::TargetLimit,
                2 => StopReason::Cancelled,
                _ => StopReason::Failed,
            }
        );
    }
}

#[test]
fn finalCaptureFailureAndDriftKeepReportsWithoutAdmittingAProposal() {
    for drift in [false, true] {
        let (plan, mut backend) = fixture();
        backend.refuseFinal = !drift;
        backend.driftFinal = drift;
        let collection =
            collectWithBackend(plan, &AtomicBool::new(false), |_, _| Ok(()), &mut backend).unwrap();
        let Collection::Stopped {
            reason,
            evidence,
            detail,
            ..
        } = collection
        else {
            panic!("expected rejected final verification")
        };
        assert_eq!(reason, StopReason::Failed);
        assert_eq!(evidence.reports.len(), 2);
        assert_eq!(backend.probes, 20);
        assert_eq!(evidence.after.is_some(), drift);
        assert!(detail.contains(if drift {
            "routes changed"
        } else {
            "final policy unavailable"
        }));
    }
}

#[test]
fn invalidPlansAndPreCancellationCannotStartCapturesOrProbes() {
    let (mut plan, mut backend) = fixture();
    plan.targets[1] = plan.targets[0].clone();
    assert!(
        collectWithBackend(plan, &AtomicBool::new(false), |_, _| Ok(()), &mut backend).is_err()
    );
    let (plan, _) = fixture();
    let collection =
        collectWithBackend(plan, &AtomicBool::new(true), |_, _| Ok(()), &mut backend).unwrap();
    assert!(matches!(
        collection,
        Collection::Stopped {
            reason: StopReason::Cancelled,
            ..
        }
    ));
    assert_eq!(backend.policies, 0);
    assert_eq!(backend.routeCalls, 0);
    assert_eq!(backend.probes, 0);
}

#[test]
fn staleOriginalsAndBothDeadlineClocksBlockFurtherWork() {
    let (plan, mut backend) = fixture();
    backend.staleBefore = true;
    let collection =
        collectWithBackend(plan, &AtomicBool::new(false), |_, _| Ok(()), &mut backend).unwrap();
    assert!(matches!(
        collection,
        Collection::Stopped {
            reason: StopReason::Failed,
            ..
        }
    ));
    assert_eq!(backend.probes, 0);
    let cancelled = AtomicBool::new(false);
    let now = crate::watchdog::nowUnixMs().unwrap();
    let mut guard = Guard {
        cancelled: &cancelled,
        deadline: Instant::now(),
        expiresAtUnixMs: now + 10_000,
        highWaterUnixMs: now,
    };
    assert_eq!(guard.check().unwrap_err().0, StopReason::TimeLimit);
    guard.deadline = Instant::now() + Duration::from_secs(10);
    guard.expiresAtUnixMs = now;
    assert_eq!(guard.check().unwrap_err().0, StopReason::TimeLimit);
    guard.expiresAtUnixMs = now + 10_000;
    guard.highWaterUnixMs = now + 10_000;
    assert_eq!(guard.check().unwrap_err().0, StopReason::Failed);
}
