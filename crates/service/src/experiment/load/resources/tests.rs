use super::*;
use crate::experiment::{
    baseline::tests::Database,
    load::tests::{fixture, plan, savedRaw},
};

fn stats(capture: &mut routing::Capture) -> &mut routing::LinkStatistics {
    let routing::Capture::Captured { snapshot } = capture else {
        panic!("fixture capture unavailable")
    };
    snapshot.linkStatistics.as_deref_mut().unwrap()
}

#[test]
fn everyReportedCounterGuardIsCountedOnceAndCanRejectAnOtherwiseImprovedCandidate() {
    for counter in 0..ADAPTER_GUARD_IDS.len() {
        let (scope, current, routes) = fixture();
        let plan = plan(&scope);
        let transferCount = scope.selections.len();
        let storage = Database::new();
        let mut database = storage.open();
        let mut collector = scope.bind(&mut database, plan.clone()).unwrap();
        let (run, mut before, mut after) = savedRaw(&mut collector, &current, &routes);
        let firstAfter = 2 * (before.1.len() as u64 - 1) + 1;
        for (afterBoundary, captures) in [(false, &mut before.1), (true, &mut after.1)] {
            for (index, capture) in captures.iter_mut().enumerate() {
                let stats = stats(capture);
                let advance = if afterBoundary {
                    firstAfter + index as u64
                } else {
                    index as u64 * 2
                };
                *match counter {
                    0 => &mut stats.receivedErrors,
                    1 => &mut stats.receivedDiscards,
                    2 => &mut stats.receivedUnknownProtocols,
                    3 => &mut stats.sentErrors,
                    _ => &mut stats.sentDiscards,
                } = (9_007_199_254_740_993u64 + advance).to_string();
            }
        }
        let measured = collector
            .acceptRaw(&run, &before, &after, Configuration::Original)
            .unwrap();
        let mut expected = vec![0.0; ADAPTER_GUARD_IDS.len()];
        expected[counter] = 1.0;
        assert_eq!(measured.values[transferCount..], expected);
        let payload: String = collector
            .database
            .query_row(
                "SELECT payload_json FROM adapter_load_measurements WHERE run_id=?1",
                [run.id],
                |row| row.get(0),
            )
            .unwrap();
        let receipt: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(receipt["schemaVersion"], 2);
        assert_eq!(receipt["adapterGuardPolicy"], "reported-counters-v1");
        assert_eq!(
            receipt["adapterGuardValues"],
            serde_json::to_value(&expected).unwrap()
        );
        let blocks: Vec<_> = (0..4)
            .map(|index| {
                let start = 1_800_000_000_000u64 + index * 90_000;
                let session = |offset: u64, candidate: bool| {
                    let mut result = measured.clone();
                    result.id = format!("resource-{index}-{offset}");
                    result.startedAtUnixMs = start + offset;
                    result.finishedAtUnixMs = start + offset + 28_000;
                    if candidate {
                        result.configurationSha256 =
                            plan.comparison.candidateConfigurationSha256.clone();
                        result.values[0] += 20.0;
                    } else {
                        result.values[transferCount..].fill(0.0);
                    }
                    result
                };
                comparison::MatchedBlock {
                    originalBefore: session(0, false),
                    candidate: session(28_000, true),
                    originalAfter: session(56_000, false),
                }
            })
            .collect();
        let report = comparison::analyze(&plan.comparison, &blocks).unwrap();
        assert_eq!(
            report.outcome,
            comparison::Outcome::Reject,
            "ignored {}",
            ADAPTER_GUARD_IDS[counter]
        );
    }
}

#[test]
fn missingResetStaleOrIncompatibleCountersPreserveRawWithoutIssuingAReceipt() {
    for failure in 0..14 {
        let (scope, current, routes) = fixture();
        let plan = plan(&scope);
        let storage = Database::new();
        let mut database = storage.open();
        let mut collector = scope.bind(&mut database, plan).unwrap();
        let (run, mut before, mut after) = savedRaw(&mut collector, &current, &routes);
        match failure {
            0 => {
                let routing::Capture::Captured { snapshot } = &mut before.1[0] else {
                    unreachable!()
                };
                snapshot.linkStatistics = None;
            }
            1 => {
                for capture in &mut after.1 {
                    stats(capture).receivedOctets = "1".into();
                }
            }
            2 => {
                for capture in &mut after.1 {
                    stats(capture).sentNonUnicastPackets = "0".into();
                }
            }
            3 => {
                for capture in &mut after.1 {
                    stats(capture).operStatus = 2;
                }
            }
            4 => {
                for capture in &mut after.1 {
                    stats(capture).interfaceType += 1;
                }
            }
            5 => {
                for capture in &mut after.1 {
                    stats(capture).receiveLinkSpeedBps = "2000000000".into();
                }
            }
            6 => {
                for capture in &mut after.1 {
                    stats(capture).transmitLinkSpeedBps = "0".into();
                }
            }
            7 => stats(&mut after.1[0]).queryStartedAtUnixMs -= 1,
            8 => {
                for capture in &mut after.1 {
                    stats(capture).sentOctets = "9007199254741001".into();
                }
            }
            9 => {
                for capture in &mut after.1 {
                    stats(capture).sentErrors = "1000000000001".into();
                }
            }
            10 => stats(&mut before.1[0]).queryElapsedNs = "-1".into(),
            11 => {
                for capture in &mut after.1 {
                    stats(capture).mediaConnectState = 0;
                }
            }
            12 => {
                let routing::Capture::Captured { snapshot } = &mut after.1[0] else {
                    unreachable!()
                };
                snapshot.adapterGuid = uuid::Uuid::new_v4();
            }
            _ => {
                after.1.pop();
            }
        }
        assert!(
            collector
                .acceptRaw(&run, &before, &after, Configuration::Original)
                .is_err(),
            "admitted failure {failure}"
        );
        let receipts: u32 = collector
            .database
            .query_row(
                "SELECT COUNT(*) FROM adapter_load_measurements",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(receipts, 0);
        let saved = epp_core::storage::loadSessionHistory(collector.database, 1).unwrap();
        assert_eq!(
            serde_json::to_value(&saved[0]).unwrap(),
            serde_json::to_value(&run).unwrap()
        );
    }
}

#[test]
fn requiredGuardRulesCannotBeRemovedRenamedReorderedOrScoredAsObjectives() {
    for failure in 0..8 {
        let (scope, _, _) = fixture();
        let mut plan = plan(&scope);
        let count = plan.comparison.metrics.len();
        match failure {
            0 => {
                plan.comparison.metrics.pop();
            }
            1 => plan.comparison.metrics.swap(count - 1, count - 2),
            2 => plan.comparison.metrics[count - 1].role = Role::Objective,
            3 => plan.comparison.metrics[count - 1].unit = Unit::Percent,
            4 => plan.comparison.metrics[count - 1].direction = Direction::HigherIsBetter,
            5 => plan.comparison.metrics[count - 1].resolution = 0.5,
            6 => plan.comparison.metrics[count - 1].id = "unreviewed-counter".into(),
            _ => {
                plan.comparison
                    .metrics
                    .push(plan.comparison.metrics[count - 1].clone());
            }
        }
        let storage = Database::new();
        let mut database = storage.open();
        assert!(scope.bind(&mut database, plan).is_err());
        let tables: u32 = database.query_row("SELECT COUNT(*) FROM sqlite_master WHERE name IN ('load_recordings','adapter_load_measurements')", [], |row| row.get(0)).unwrap();
        assert_eq!(tables, 0);
    }
}

#[test]
fn frozenResourceContextChangesCohortWhileCounterActivityDoesNot() {
    let (scope, _, mut routes) = fixture();
    let original = cohort(&scope.transferCohortSha256, &scope.adapterContext).unwrap();
    for capture in &mut routes {
        stats(capture).sentErrors = "5".into();
    }
    let context = AdapterContext::fromRoutes(&routes).unwrap();
    assert_eq!(
        cohort(&scope.transferCohortSha256, &context).unwrap(),
        original
    );
    for capture in &mut routes {
        stats(capture).receiveLinkSpeedBps = "2000000000".into();
    }
    let context = AdapterContext::fromRoutes(&routes).unwrap();
    assert_ne!(
        cohort(&scope.transferCohortSha256, &context).unwrap(),
        original
    );
}
