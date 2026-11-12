use super::*;
use epp_core::{
    icmp::{EchoOutcome, EchoStatus},
    packet_size::{self, Plan, Probe},
};
use std::{
    net::Ipv4Addr,
    sync::{OnceLock, atomic::AtomicBool},
    time::Duration,
};

struct Boundary(u32);

impl Probe for Boundary {
    fn measure(
        &mut self,
        plan: &Plan,
        bytes: u32,
        _: Duration,
    ) -> epp_core::AppResult<EchoOutcome> {
        if bytes > self.0 {
            return Ok(EchoOutcome {
                status: EchoStatus::IpError,
                rttMs: None,
                rttUnitMs: 1,
                callDurationMs: 1.0,
                responder: None,
                responderScopeId: None,
                nativeCode: Some(11009),
            });
        }
        Ok(EchoOutcome {
            status: EchoStatus::Reply,
            rttMs: Some(1),
            rttUnitMs: 1,
            callDurationMs: 1.0,
            responder: Some(plan.destination.into()),
            responderScopeId: None,
            nativeCode: Some(0),
        })
    }
}

fn fixture(cutoffs: [u32; 2]) -> (Vec<routing::Address>, Evidence, u64) {
    static REPORTS: OnceLock<Vec<(u32, String)>> = OnceLock::new();
    let reports = REPORTS.get_or_init(|| {
        [1500, 1427, 1379, 1279]
            .into_iter()
            .map(|cutoff| {
                let report = packet_size::diagnose(
                    Plan {
                        source: Ipv4Addr::LOCALHOST,
                        destination: Ipv4Addr::LOCALHOST,
                        interfaceMtu: 1500,
                        timeoutMs: 100,
                        intervalMs: 25,
                        budgetMs: 20_000,
                    },
                    &mut Boundary(cutoff),
                    &AtomicBool::new(false),
                    |_| {},
                )
                .unwrap();
                report.validate().unwrap();
                (cutoff, serde_json::to_string(&report).unwrap())
            })
            .collect()
    });
    let now = crate::watchdog::nowUnixMs().unwrap();
    let (_, _, _, _, mut before, mut routesBefore) = super::super::baseline::tests::evidence();
    before.native.capturedAtUnixMs = now - 20_000;
    let targets: Vec<_> = routesBefore
        .iter()
        .map(|route| match route {
            routing::Capture::Captured { snapshot } => snapshot.destination.clone(),
            _ => panic!("fixture route unavailable"),
        })
        .collect();
    let mut next = now - 19_000;
    let mut evidenceReports = Vec::new();
    for (index, cutoff) in cutoffs.into_iter().enumerate() {
        let mut report: Report =
            serde_json::from_str(&reports.iter().find(|(size, _)| *size == cutoff).unwrap().1)
                .unwrap();
        let first = report.startedAtUnixMs;
        report.finishedAtUnixMs = next + report.finishedAtUnixMs - first;
        for sample in &mut report.samples {
            sample.timestampUnixMs = next + sample.timestampUnixMs - first;
            if sample.echo.status == EchoStatus::Reply {
                sample.echo.responder = Some(targets[index].ip);
            }
        }
        report.startedAtUnixMs = next;
        report.plan.source = "192.0.2.2".parse().unwrap();
        let std::net::IpAddr::V4(destination) = targets[index].ip else {
            panic!("fixture family")
        };
        report.plan.destination = destination;
        report.validate().unwrap();
        next = report.finishedAtUnixMs + 1;
        evidenceReports.push(report);
    }
    let mut after = before.clone();
    after.native.capturedAtUnixMs = next + 1;
    for route in &mut routesBefore {
        if let routing::Capture::Captured { snapshot } = route {
            snapshot.capturedAtUnixMs = now - 19_001;
        }
    }
    let mut routesAfter = routesBefore.clone();
    for route in &mut routesAfter {
        if let routing::Capture::Captured { snapshot } = route {
            snapshot.capturedAtUnixMs = next;
        }
    }
    (
        targets,
        Evidence {
            before,
            routesBefore,
            reports: evidenceReports,
            after,
            routesAfter,
        },
        now,
    )
}

#[test]
fn derivesANonPresetMinimumAcrossTheCompleteCohort() {
    for (cutoffs, expected, boundaries) in [([1427, 1500], 1427, 1), ([1427, 1379], 1379, 2)] {
        let (targets, evidence, now) = fixture(cutoffs);
        let mut proposal = proposeMtu(&targets, &evidence, now).unwrap().unwrap();
        assert_eq!(proposal.summary().proposedMtu, expected);
        assert_eq!(proposal.summary().originalMtu, 1500);
        assert_eq!(proposal.summary().boundaryTargets.len(), boundaries);
        assert_eq!(proposal.summary().targets, targets);
        assert_eq!(proposal.summary().evidenceSha256.len(), 64);
        let mut current = evidence.after.clone();
        current.native.capturedAtUnixMs = now;
        let mut routes = evidence.routesAfter.clone();
        for route in &mut routes {
            if let routing::Capture::Captured { snapshot } = route {
                snapshot.capturedAtUnixMs = now;
            }
        }
        let document = proposal
            .checkpoint(&current, &routes, "S-1-5-21-1-2-3-1000", 120_000, now)
            .unwrap();
        document.validate().unwrap();
        assert_eq!(document.proposedMtu, expected);
        assert_eq!(document.nativeOriginal.as_ref().unwrap(), &current.native);
        assert_eq!(
            document.policyOriginal.as_ref().unwrap(),
            &current.evidence()
        );
        assert_eq!(document.leaseExpiresAtUnixMs, now + 120_000);
        super::super::measurement::AdapterScope::fromEvidence(
            document.clone(),
            targets.clone(),
            current,
            routes,
        )
        .unwrap();
        let mut consent = crate::consent::MtuConsent::new("S-1-5-21-1-2-3-1000").unwrap();
        let preview = consent
            .preview(document, "S-1-5-21-1-2-3-1000", now)
            .unwrap();
        assert_eq!(preview.proposedMtu, expected);
        assert!(!preview.allowRetention);
    }
}

#[test]
fn fullSizeSuccessNeverInventsAReductionAndUnsupportedBoundariesAreRefused() {
    let (targets, evidence, now) = fixture([1500, 1500]);
    assert!(proposeMtu(&targets, &evidence, now).unwrap().is_none());
    let (targets, evidence, now) = fixture([1427, 1279]);
    assert!(proposeMtu(&targets, &evidence, now).is_err());
}

#[test]
fn incompleteChangedOrStaleEvidenceCannotProduceACandidate() {
    for failure in 0..16 {
        let (mut targets, mut evidence, mut now) = fixture([1427, 1500]);
        match failure {
            0 => {
                targets.pop();
            }
            1 => targets[1] = targets[0].clone(),
            2 => {
                evidence.reports.pop();
            }
            3 => evidence.reports[0].outcome = Outcome::Inconclusive,
            4 => evidence.reports[0].samples[4].echo.nativeCode = Some(11010),
            5 => evidence.reports[0].plan.source = "192.0.2.3".parse().unwrap(),
            6 => evidence.reports[0].plan.interfaceMtu = 1492,
            7 => evidence.after.native.settings.nlMtu = 1492,
            8 => {
                evidence
                    .after
                    .active
                    .values
                    .get_mut("InterfaceMetric")
                    .unwrap()
                    .value = Some(99)
            }
            9 => {
                if let routing::Capture::Captured { snapshot } = &mut evidence.routesAfter[0] {
                    snapshot.routeMetric += 1;
                }
            }
            10 => now = evidence.before.native.capturedAtUnixMs + MAX_AGE_MS,
            11 => now = evidence.after.native.capturedAtUnixMs - 1,
            12 => evidence.reports[0].finishedAtUnixMs = evidence.after.native.capturedAtUnixMs + 1,
            13 => {
                if let routing::Capture::Captured { snapshot } = &mut evidence.routesBefore[0] {
                    snapshot.capturedAtUnixMs = evidence.reports[0].startedAtUnixMs + 1;
                }
            }
            14 => evidence.after.native.registryOrigins = None,
            _ => {
                evidence.reports[0].outcome = Outcome::ClockChanged;
                evidence.reports[0].confirmedBoundaryBytes = None;
                evidence.reports[0].finishedAtUnixMs = 1;
            }
        }
        assert!(proposeMtu(&targets, &evidence, now).is_err(), "{failure}");
    }
}

#[test]
fn preparingACheckpointRequiresFreshUnchangedContext() {
    for failure in 0..9 {
        let (targets, evidence, now) = fixture([1427, 1500]);
        let mut proposal = proposeMtu(&targets, &evidence, now).unwrap().unwrap();
        let mut current = evidence.after.clone();
        current.native.capturedAtUnixMs = now;
        let mut routes = evidence.routesAfter.clone();
        for route in &mut routes {
            if let routing::Capture::Captured { snapshot } = route {
                snapshot.capturedAtUnixMs = now;
            }
        }
        let mut at = now;
        let mut duration = 120_000;
        let mut owner = "S-1-5-21-1-2-3-1000";
        match failure {
            0 => at = proposal.summary().expiresAtUnixMs,
            1 => at = proposal.summary().diagnosedAtUnixMs - 1,
            2 => current.native.capturedAtUnixMs = now - 5001,
            3 => current.native.settings.metric += 1,
            4 => current.native.mediaConnectState = 2,
            5 => {
                if let routing::Capture::Captured { snapshot } = &mut routes[0] {
                    snapshot.capturedAtUnixMs = now - 5001;
                }
            }
            6 => duration = 300_001,
            7 => owner = "invalid",
            _ => {
                if let routing::Capture::Captured { snapshot } = &mut routes[0] {
                    snapshot.nextHop.ip = "192.0.2.4".parse().unwrap();
                }
            }
        }
        assert!(
            proposal
                .checkpoint(&current, &routes, owner, duration, at)
                .is_err(),
            "{failure}"
        );
    }
}

#[test]
fn clockRollbackAndMonotonicExpiryPermanentlyEndTheProposal() {
    for monotonic in [false, true] {
        let (targets, evidence, now) = fixture([1427, 1500]);
        let mut proposal = proposeMtu(&targets, &evidence, now).unwrap().unwrap();
        let mut current = evidence.after.clone();
        current.native.capturedAtUnixMs = now;
        let mut routes = evidence.routesAfter.clone();
        for route in &mut routes {
            if let routing::Capture::Captured { snapshot } = route {
                snapshot.capturedAtUnixMs = now;
            }
        }
        proposal
            .checkpoint(&current, &routes, "S-1-5-21-1-2-3-1000", 120_000, now + 1)
            .unwrap();
        if monotonic {
            proposal.deadline = Instant::now();
        }
        let at = if monotonic { now + 1 } else { now };
        assert!(
            proposal
                .checkpoint(&current, &routes, "S-1-5-21-1-2-3-1000", 120_000, at)
                .is_err()
        );
        proposal.deadline = Instant::now() + Duration::from_secs(60);
        assert!(
            proposal
                .checkpoint(&current, &routes, "S-1-5-21-1-2-3-1000", 120_000, now + 2)
                .is_err()
        );
    }
}
