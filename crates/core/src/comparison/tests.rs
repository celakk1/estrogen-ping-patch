use super::*;

fn threshold(absolute: f64) -> Threshold {
    Threshold {
        absolute,
        relativeFraction: 0.0,
    }
}

pub(super) fn plan() -> Plan {
    Plan {
        maximumBlockDurationMs: 10_000,
        cohortSha256: "a".repeat(64),
        environmentSha256: "b".repeat(64),
        originalConfigurationSha256: "c".repeat(64),
        candidateConfigurationSha256: "d".repeat(64),
        metrics: vec![
            MetricRule {
                id: "server.median".into(),
                unit: Unit::Milliseconds,
                direction: Direction::LowerIsBetter,
                role: Role::Objective,
                resolution: 1.0,
                minimumImprovement: threshold(2.0),
                maximumRegression: threshold(3.0),
                maximumBaselineDrift: threshold(4.0),
            },
            MetricRule {
                id: "provider.download".into(),
                unit: Unit::MegabitsPerSecond,
                direction: Direction::HigherIsBetter,
                role: Role::Guard,
                resolution: 0.1,
                minimumImprovement: threshold(2.0),
                maximumRegression: threshold(5.0),
                maximumBaselineDrift: threshold(4.0),
            },
        ],
    }
}

fn blocks(count: usize) -> Vec<MatchedBlock> {
    let plan = plan();
    (0..count)
        .map(|index| {
            let start = 1000 + index as u64 * 1000;
            let session = |offset, configuration: &str, values| Session {
                id: format!("{index}-{offset}"),
                startedAtUnixMs: start + offset,
                finishedAtUnixMs: start + offset + 100,
                completed: true,
                cohortSha256: plan.cohortSha256.clone(),
                environmentSha256: plan.environmentSha256.clone(),
                configurationSha256: configuration.into(),
                values,
            };
            let variation = if index % 2 == 0 { -0.5 } else { 0.5 };
            MatchedBlock {
                originalBefore: session(0, &plan.originalConfigurationSha256, vec![30.0, 100.0]),
                candidate: session(
                    200,
                    &plan.candidateConfigurationSha256,
                    vec![25.0 + variation, 100.0 + variation],
                ),
                originalAfter: session(400, &plan.originalConfigurationSha256, vec![30.0, 100.0]),
            }
        })
        .collect()
}

#[test]
fn repeatedSessionBenefitIsExploratoryReproducibleAndAuditable() {
    let plan = plan();
    let blocks = blocks(12);
    let report = analyze(&plan, &blocks).unwrap();
    assert_eq!(report.outcome, Outcome::Promising);
    assert!(report.exploratory);
    assert_eq!(report.blockCount, 12);
    assert_eq!(report.resamples, 16384);
    assert_eq!(report.metrics[0].meanBenefit, 5.0);
    assert_eq!(report.metrics[1].meanBenefit, 0.0);
    let interval = report.metrics[0].benefitInterval.as_ref().unwrap();
    assert!(interval.lower > 4.5 && interval.upper < 5.5);
    assert!((interval.lower - (5.0 - 4.0 / 12.0)).abs() < 1e-12);
    assert!((interval.upper - (5.0 + 4.0 / 12.0)).abs() < 1e-12);
    assert_eq!(interval.nominalConfidence, 1.0 - 0.05 / 6.0);
    assert_eq!(
        serde_json::to_value(&report).unwrap(),
        serde_json::to_value(analyze(&plan, &blocks).unwrap()).unwrap()
    );
    let planAgain: Plan =
        serde_json::from_value(serde_json::to_value(&report.plan).unwrap()).unwrap();
    let blocksAgain: Vec<MatchedBlock> =
        serde_json::from_value(serde_json::to_value(&report.blocks).unwrap()).unwrap();
    assert_eq!(
        analyze(&planAgain, &blocksAgain).unwrap().evidenceSha256,
        report.evidenceSha256
    );
}

#[test]
fn bootstrapKeepsOppositeMetricsPairedAcrossEveryResample() {
    let first: Vec<_> = (0..12).map(|value| value as f64 - 5.0).collect();
    let second: Vec<_> = first.iter().map(|value| -value).collect();
    let intervals = bootstrap::intervals(&[first, second], [7; 32]);
    assert!((intervals[0].lower + intervals[1].upper).abs() < 1e-12);
    assert!((intervals[0].upper + intervals[1].lower).abs() < 1e-12);
}

#[test]
fn baselineRelativeThresholdUncertaintyIsResampledWithTheSameSessions() {
    let mut plan = plan();
    plan.metrics[0].minimumImprovement.relativeFraction = 0.01;
    let mut blocks = blocks(12);
    for (index, block) in blocks.iter_mut().enumerate() {
        let baseline = if index % 2 == 0 { 100.0 } else { 600.0 };
        block.originalBefore.values[0] = baseline;
        block.originalAfter.values[0] = baseline;
        block.candidate.values[0] = baseline - 5.0 + if index % 2 == 0 { -0.1 } else { 0.1 };
    }
    let report = analyze(&plan, &blocks).unwrap();
    assert_eq!(report.metrics[0].practicalThreshold, 4.0);
    assert_eq!(report.outcome, Outcome::Inconclusive);
}

#[test]
fn manyPacketsCannotReplaceRepeatedIndependentSessions() {
    let report = analyze(&plan(), &blocks(1)).unwrap();
    assert_eq!(report.outcome, Outcome::Inconclusive);
    assert_eq!(report.resamples, 0);
    assert!(
        report
            .metrics
            .iter()
            .all(|metric| metric.benefitInterval.is_none())
    );
    assert_eq!(
        analyze(&plan(), &blocks(11)).unwrap().outcome,
        Outcome::Inconclusive
    );
}

#[test]
fn driftInvalidatesTheWholeComparisonInsteadOfDroppingBadBlocks() {
    let mut blocks = blocks(12);
    blocks[5].originalAfter.values[0] = 50.0;
    let report = analyze(&plan(), &blocks).unwrap();
    assert_eq!(report.outcome, Outcome::Invalid);
    assert_eq!(report.metrics[0].driftedBlocks, vec![5]);
    assert_eq!(report.metrics[0].outcome, Outcome::Invalid);
    assert_eq!(report.blockCount, 12);
    assert_eq!(report.resamples, 0);
}

#[test]
fn oneHardRegressionRejectsDespiteABetterAverage() {
    let mut blocks = blocks(12);
    blocks[0].candidate.values[1] = 94.0;
    for block in &mut blocks[1..] {
        block.candidate.values[1] = 110.0;
    }
    let report = analyze(&plan(), &blocks).unwrap();
    assert!(report.metrics[1].meanBenefit > 0.0);
    assert_eq!(report.outcome, Outcome::Reject);
    assert_eq!(report.metrics[1].hardRegressionBlocks, vec![0]);
    assert_eq!(report.metrics[1].outcome, Outcome::Reject);
    let report = analyze(&plan(), &blocks[..1]).unwrap();
    assert_eq!(report.outcome, Outcome::Reject);
    assert_eq!(report.metrics[1].outcome, Outcome::Reject);
}

#[test]
fn smallNoisyOrDegenerateChangesCannotBecomePromising() {
    for mode in ["small", "noisy", "constant"] {
        let mut blocks = blocks(12);
        for (index, block) in blocks.iter_mut().enumerate() {
            block.candidate.values[0] = match mode {
                "small" => {
                    if index % 2 == 0 {
                        29.0
                    } else {
                        30.0
                    }
                }
                "noisy" => {
                    if index % 2 == 0 {
                        23.0
                    } else {
                        32.0
                    }
                }
                "constant" => 25.0,
                _ => unreachable!(),
            };
        }
        assert_eq!(
            analyze(&plan(), &blocks).unwrap().outcome,
            Outcome::Inconclusive,
            "{mode}"
        );
    }
}

#[test]
fn baselineIsInterpolatedAtCandidateTimeWithoutLosingLargeTimestampPrecision() {
    let mut blocks = blocks(1);
    blocks[0].originalAfter.values[0] = 34.0;
    blocks[0].candidate.startedAtUnixMs = 1100;
    blocks[0].candidate.finishedAtUnixMs = 1200;
    let block = &mut blocks[0];
    for session in [
        &mut block.originalBefore,
        &mut block.candidate,
        &mut block.originalAfter,
    ] {
        session.startedAtUnixMs += 1u64 << 60;
        session.finishedAtUnixMs += 1u64 << 60;
    }
    let report = analyze(&plan(), &blocks).unwrap();
    assert_eq!(report.metrics[0].meanBaseline, 31.0);
}

#[test]
fn mismatchedReusedUnfinishedOrOverlappingSessionsAreRefused() {
    for change in [
        "cohort",
        "environment",
        "configuration",
        "reused",
        "unfinished",
        "overlap",
        "missing",
        "nan",
        "window",
    ] {
        let mut blocks = blocks(2);
        match change {
            "cohort" => blocks[1].candidate.cohortSha256 = "e".repeat(64),
            "environment" => blocks[1].candidate.environmentSha256 = "e".repeat(64),
            "configuration" => blocks[1].originalAfter.configurationSha256 = "e".repeat(64),
            "reused" => blocks[1].candidate.id = blocks[0].candidate.id.clone(),
            "unfinished" => blocks[1].candidate.completed = false,
            "overlap" => {
                blocks[1].candidate.startedAtUnixMs = blocks[1].originalBefore.startedAtUnixMs
            }
            "missing" => {
                blocks[1].candidate.values.pop();
            }
            "nan" => blocks[1].candidate.values[0] = f64::NAN,
            "window" => blocks[1].originalAfter.finishedAtUnixMs += 20_000,
            _ => unreachable!(),
        }
        assert!(analyze(&plan(), &blocks).is_err(), "{change}");
    }
}

#[test]
fn invalidPolicyAndPercentagesCannotEnterTheAnalysis() {
    for change in [
        "hash",
        "metric",
        "resolution",
        "threshold",
        "role",
        "percent",
        "capacity",
    ] {
        let mut plan = plan();
        match change {
            "hash" => plan.cohortSha256 = "not-a-hash".into(),
            "metric" => plan.metrics[1].id = plan.metrics[0].id.clone(),
            "resolution" => plan.metrics[0].resolution = 3.0,
            "threshold" => plan.metrics[0].maximumRegression.absolute = f64::INFINITY,
            "role" => plan.metrics[1].role = Role::Objective,
            "percent" => {
                plan.metrics[1].unit = Unit::Percent;
                plan.metrics[1].resolution = 101.0;
            }
            "capacity" => {
                let metric = plan.metrics[0].clone();
                plan.metrics.resize(17, metric);
            }
            _ => unreachable!(),
        }
        assert!(plan.validate().is_err(), "{change}");
    }
    let mut plan = plan();
    plan.metrics[1].unit = Unit::Percent;
    let mut evidence = blocks(1);
    evidence[0].candidate.values[1] = 101.0;
    assert!(analyze(&plan, &evidence).is_err());
    assert!(analyze(&plan, &[]).is_err());
    assert!(analyze(&plan, &blocks(129)).is_err());
}
