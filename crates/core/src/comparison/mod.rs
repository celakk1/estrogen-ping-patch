pub mod baseline;
mod bootstrap;
pub mod load;

use crate::AppResult;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[cfg(test)]
mod tests;

const MIN_BLOCKS: usize = 12;
const MAX_BLOCKS: usize = 128;
const MAX_METRICS: usize = 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Direction {
    LowerIsBetter,
    HigherIsBetter,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Role {
    Objective,
    Guard,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Unit {
    Milliseconds,
    MegabitsPerSecond,
    Percent,
    Count,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Threshold {
    pub absolute: f64,
    pub relativeFraction: f64,
}

impl Threshold {
    fn validate(self) -> AppResult<()> {
        if !self.absolute.is_finite()
            || !(0.0..=1e12).contains(&self.absolute)
            || !self.relativeFraction.is_finite()
            || !(0.0..=1.0).contains(&self.relativeFraction)
        {
            return Err("Comparison thresholds require finite nonnegative bounds".into());
        }
        Ok(())
    }

    fn at(self, baseline: f64) -> f64 {
        self.absolute.max(baseline * self.relativeFraction)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetricRule {
    pub id: String,
    pub unit: Unit,
    pub direction: Direction,
    pub role: Role,
    pub resolution: f64,
    pub minimumImprovement: Threshold,
    pub maximumRegression: Threshold,
    pub maximumBaselineDrift: Threshold,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Plan {
    pub maximumBlockDurationMs: u64,
    pub cohortSha256: String,
    pub environmentSha256: String,
    pub originalConfigurationSha256: String,
    pub candidateConfigurationSha256: String,
    pub metrics: Vec<MetricRule>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Session {
    pub id: String,
    pub startedAtUnixMs: u64,
    pub finishedAtUnixMs: u64,
    pub completed: bool,
    pub cohortSha256: String,
    pub environmentSha256: String,
    pub configurationSha256: String,
    pub values: Vec<f64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MatchedBlock {
    pub originalBefore: Session,
    pub candidate: Session,
    pub originalAfter: Session,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Outcome {
    Invalid,
    Reject,
    Inconclusive,
    Promising,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricResult {
    pub id: String,
    pub unit: Unit,
    pub direction: Direction,
    pub role: Role,
    pub meanBaseline: f64,
    pub meanCandidate: f64,
    pub meanBenefit: f64,
    pub benefitInterval: Option<bootstrap::Interval>,
    pub practicalMarginInterval: Option<bootstrap::Interval>,
    pub nonRegressionMarginInterval: Option<bootstrap::Interval>,
    pub practicalThreshold: f64,
    pub regressionLimit: f64,
    pub hardRegressionBlocks: Vec<usize>,
    pub driftedBlocks: Vec<usize>,
    pub outcome: Outcome,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub schemaVersion: u32,
    pub method: String,
    pub evidenceSha256: String,
    pub plan: Plan,
    pub blocks: Vec<MatchedBlock>,
    pub blockCount: usize,
    pub minimumBlocks: usize,
    pub resamples: usize,
    pub nominalFamilyConfidence: f64,
    pub exploratory: bool,
    pub outcome: Outcome,
    pub metrics: Vec<MetricResult>,
}

fn identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 100 && !value.chars().any(char::is_control)
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl Plan {
    pub fn validate(&self) -> AppResult<()> {
        if ![
            &self.cohortSha256,
            &self.environmentSha256,
            &self.originalConfigurationSha256,
            &self.candidateConfigurationSha256,
        ]
        .iter()
        .all(|value| digest(value))
            || !(1..=86_400_000).contains(&self.maximumBlockDurationMs)
            || !(1..=MAX_METRICS).contains(&self.metrics.len())
            || !self.metrics.iter().any(|rule| rule.role == Role::Objective)
            || !self.metrics.iter().any(|rule| rule.role == Role::Guard)
        {
            return Err(format!("Comparison requires canonical evidence hashes, objective and safety metrics, and at most {MAX_METRICS} metrics").into());
        }
        let mut identifiers = BTreeSet::new();
        for rule in &self.metrics {
            if !identifier(&rule.id)
                || !identifiers.insert(&rule.id)
                || !rule.resolution.is_finite()
                || !(f64::MIN_POSITIVE..=1e12).contains(&rule.resolution)
            {
                return Err("Comparison metric identity, unit, or resolution is invalid".into());
            }
            rule.minimumImprovement.validate()?;
            rule.maximumRegression.validate()?;
            rule.maximumBaselineDrift.validate()?;
            if rule.unit == Unit::Percent
                && [
                    rule.resolution,
                    rule.minimumImprovement.absolute,
                    rule.maximumRegression.absolute,
                    rule.maximumBaselineDrift.absolute,
                ]
                .iter()
                .any(|value| *value > 100.0)
            {
                return Err(
                    "Percentage metric bounds must not exceed 100 percentage points".into(),
                );
            }
            if rule.minimumImprovement.absolute < rule.resolution {
                return Err(
                    "Practical improvement must be at least the measurement resolution".into(),
                );
            }
        }
        Ok(())
    }
}

pub(crate) fn validateSession(
    plan: &Plan,
    session: &Session,
    configuration: &str,
    identifiers: &mut BTreeSet<String>,
    previousEnd: u64,
) -> AppResult<()> {
    if !identifier(&session.id)
        || !identifiers.insert(session.id.clone())
        || !session.completed
        || session.startedAtUnixMs == 0
        || session.startedAtUnixMs < previousEnd
        || session.finishedAtUnixMs <= session.startedAtUnixMs
        || session.finishedAtUnixMs > i64::MAX as u64
        || session.cohortSha256 != plan.cohortSha256
        || session.environmentSha256 != plan.environmentSha256
        || session.configurationSha256 != configuration
        || session.values.len() != plan.metrics.len()
        || session
            .values
            .iter()
            .zip(&plan.metrics)
            .any(|(value, rule)| {
                !value.is_finite()
                    || !(0.0..=1e12).contains(value)
                    || (rule.unit == Unit::Percent && *value > 100.0)
            })
    {
        return Err("Comparison sessions must be completed, unique, ordered, nonoverlapping, and bound to the same cohort, environment, configuration, and metric order".into());
    }
    Ok(())
}

pub(crate) fn validateSessions(plan: &Plan, blocks: &[MatchedBlock]) -> AppResult<()> {
    if !(1..=MAX_BLOCKS).contains(&blocks.len()) {
        return Err("Comparison requires one to 128 complete matched blocks".into());
    }
    let mut identifiers = BTreeSet::new();
    let mut previousEnd = 0;
    for block in blocks {
        for (session, configuration) in [
            (&block.originalBefore, &plan.originalConfigurationSha256),
            (&block.candidate, &plan.candidateConfigurationSha256),
            (&block.originalAfter, &plan.originalConfigurationSha256),
        ] {
            validateSession(plan, session, configuration, &mut identifiers, previousEnd)?;
            previousEnd = session.finishedAtUnixMs;
        }
        if block.originalAfter.finishedAtUnixMs - block.originalBefore.startedAtUnixMs
            > plan.maximumBlockDurationMs
        {
            return Err("Matched block exceeds the plan's measurement time window".into());
        }
    }
    Ok(())
}

fn mean(values: &[f64]) -> f64 {
    values.iter().sum::<f64>() / values.len() as f64
}

fn midpoint(session: &Session, origin: u64) -> f64 {
    (session.startedAtUnixMs - origin) as f64
        + (session.finishedAtUnixMs - session.startedAtUnixMs) as f64 / 2.0
}

pub fn analyze(plan: &Plan, blocks: &[MatchedBlock]) -> AppResult<Report> {
    analyzeWithCheck(plan, blocks, || Ok(()))
}

pub fn analyzeWithCheck(
    plan: &Plan,
    blocks: &[MatchedBlock],
    mut check: impl FnMut() -> AppResult<()>,
) -> AppResult<Report> {
    check()?;
    plan.validate()?;
    validateSessions(plan, blocks)?;
    check()?;
    let seed: [u8; 32] = Sha256::digest(serde_json::to_vec(&(plan, blocks))?).into();
    let mut differences = Vec::new();
    let mut metrics = Vec::new();
    for (metricIndex, rule) in plan.metrics.iter().enumerate() {
        check()?;
        let mut baseline = Vec::new();
        let mut candidate = Vec::new();
        let mut benefits = Vec::new();
        let mut practical = Vec::new();
        let mut regression = Vec::new();
        let mut hardRegressionBlocks = Vec::new();
        let mut driftedBlocks = Vec::new();
        for (blockIndex, block) in blocks.iter().enumerate() {
            let before = block.originalBefore.values[metricIndex];
            let after = block.originalAfter.values[metricIndex];
            let value = block.candidate.values[metricIndex];
            let origin = block.originalBefore.startedAtUnixMs;
            let position = (midpoint(&block.candidate, origin)
                - midpoint(&block.originalBefore, origin))
                / (midpoint(&block.originalAfter, origin)
                    - midpoint(&block.originalBefore, origin));
            let original = before + (after - before) * position;
            let benefit = match rule.direction {
                Direction::LowerIsBetter => original - value,
                Direction::HigherIsBetter => value - original,
            };
            if (after - before).abs() > rule.maximumBaselineDrift.at(before).max(rule.resolution) {
                driftedBlocks.push(blockIndex);
            }
            if benefit < -rule.maximumRegression.at(original) {
                hardRegressionBlocks.push(blockIndex);
            }
            baseline.push(original);
            candidate.push(value);
            benefits.push(benefit);
            practical.push(rule.minimumImprovement.at(original));
            regression.push(rule.maximumRegression.at(original));
        }
        metrics.push(MetricResult {
            id: rule.id.clone(),
            unit: rule.unit,
            direction: rule.direction,
            role: rule.role,
            meanBaseline: mean(&baseline),
            meanCandidate: mean(&candidate),
            meanBenefit: mean(&benefits),
            benefitInterval: None,
            practicalMarginInterval: None,
            nonRegressionMarginInterval: None,
            practicalThreshold: mean(&practical),
            regressionLimit: mean(&regression),
            hardRegressionBlocks,
            driftedBlocks,
            outcome: Outcome::Inconclusive,
        });
        let practicalMargins = benefits
            .iter()
            .zip(&practical)
            .map(|(benefit, threshold)| benefit - threshold)
            .collect();
        let nonRegressionMargins = benefits
            .iter()
            .zip(&regression)
            .map(|(benefit, limit)| benefit + limit)
            .collect();
        differences.extend([benefits, practicalMargins, nonRegressionMargins]);
    }
    let invalid = metrics
        .iter()
        .any(|metric| !metric.driftedBlocks.is_empty());
    if !invalid && blocks.len() >= MIN_BLOCKS {
        let mut intervals = bootstrap::intervals(&differences, seed, &mut check)?.into_iter();
        for metric in &mut metrics {
            let interval = intervals.next().unwrap();
            let practicalMargin = intervals.next().unwrap();
            let nonRegressionMargin = intervals.next().unwrap();
            metric.outcome = if !metric.hardRegressionBlocks.is_empty() {
                Outcome::Reject
            } else if practicalMargin.lower > 0.0
                && !practicalMargin.degenerate
                && !interval.degenerate
            {
                Outcome::Promising
            } else {
                Outcome::Inconclusive
            };
            metric.benefitInterval = Some(interval);
            metric.practicalMarginInterval = Some(practicalMargin);
            metric.nonRegressionMarginInterval = Some(nonRegressionMargin);
        }
    }
    let outcome = if invalid {
        Outcome::Invalid
    } else if metrics
        .iter()
        .any(|metric| !metric.hardRegressionBlocks.is_empty())
    {
        Outcome::Reject
    } else if metrics.iter().all(|metric| {
        metric
            .benefitInterval
            .as_ref()
            .is_some_and(|interval| !interval.degenerate)
            && metric
                .nonRegressionMarginInterval
                .as_ref()
                .is_some_and(|interval| !interval.degenerate && interval.lower >= 0.0)
    }) && metrics
        .iter()
        .any(|metric| metric.role == Role::Objective && metric.outcome == Outcome::Promising)
    {
        Outcome::Promising
    } else {
        Outcome::Inconclusive
    };
    for metric in &mut metrics {
        if !metric.driftedBlocks.is_empty() {
            metric.outcome = Outcome::Invalid;
        } else if !metric.hardRegressionBlocks.is_empty() {
            metric.outcome = Outcome::Reject;
        }
    }
    let report = Report {
        schemaVersion: 1,
        method: "paired-session-percentile-bootstrap-bonferroni-v1".into(),
        evidenceSha256: seed.iter().map(|byte| format!("{byte:02x}")).collect(),
        plan: plan.clone(),
        blocks: blocks.to_vec(),
        blockCount: blocks.len(),
        minimumBlocks: MIN_BLOCKS,
        resamples: if invalid || blocks.len() < MIN_BLOCKS {
            0
        } else {
            bootstrap::RESAMPLES
        },
        nominalFamilyConfidence: 0.95,
        exploratory: true,
        outcome,
        metrics,
    };
    check()?;
    Ok(report)
}
