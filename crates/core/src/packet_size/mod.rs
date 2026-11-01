#[cfg(windows)]
mod windows;

use crate::{
    AppResult,
    icmp::{EchoOutcome, EchoStatus, EchoTarget},
};
use serde::{Deserialize, Serialize};
use std::{
    net::Ipv4Addr,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(test)]
mod tests;

pub const MAX_PACKET_BYTES: u32 = 9000;
const MAX_PROBES: usize = 144;
const CONTROL_BYTES: u32 = 84;
const MIN_SEARCH_BYTES: u32 = 576;
const PACKET_TOO_BIG: u32 = 11009;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Plan {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub interfaceMtu: u32,
    pub timeoutMs: u32,
    pub intervalMs: u32,
    pub budgetMs: u32,
}

impl Plan {
    pub fn validate(&self) -> AppResult<()> {
        for address in [self.source, self.destination] {
            EchoTarget {
                address: address.into(),
                scopeId: 0,
            }
            .validate()?;
        }
        if self.interfaceMtu < MIN_SEARCH_BYTES
            || !(50..=1000).contains(&self.timeoutMs)
            || !(25..=250).contains(&self.intervalMs)
            || !(1000..=120_000).contains(&self.budgetMs)
        {
            return Err("Packet-size diagnosis requires a valid IPv4 interface MTU, 50-1000 ms probe timeout, 25-250 ms pacing, and a 1-120 second budget".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Outcome {
    TestedLimitReached,
    SizeBoundaryObserved,
    SmallPacketsUnavailable,
    Inconclusive,
    Cancelled,
    BudgetExpired,
    ClockChanged,
    Unsupported,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Sample {
    pub sequence: usize,
    pub timestampUnixMs: u64,
    pub packetBytes: u32,
    pub control: bool,
    pub dontFragment: bool,
    pub echo: EchoOutcome,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Report {
    pub schemaVersion: u32,
    pub plan: Plan,
    pub outcome: Outcome,
    pub startedAtUnixMs: u64,
    pub finishedAtUnixMs: u64,
    pub maximumTestedBytes: u32,
    pub largestSuccessfulBytes: Option<u32>,
    pub smallestTooBigBytes: Option<u32>,
    pub confirmedBoundaryBytes: Option<u32>,
    pub requestedIpv4Bytes: u64,
    pub samples: Vec<Sample>,
    pub error: Option<String>,
}

impl Report {
    pub fn validate(&self) -> AppResult<()> {
        self.plan.validate()?;
        if self.schemaVersion != 1
            || self.maximumTestedBytes != self.plan.interfaceMtu.min(MAX_PACKET_BYTES)
            || self.samples.len() > MAX_PROBES
            || self.startedAtUnixMs == 0
            || self.error.as_ref().is_some_and(|error| error.len() > 2048)
            || self.requestedIpv4Bytes
                != self
                    .samples
                    .iter()
                    .map(|sample| u64::from(sample.packetBytes))
                    .sum::<u64>()
        {
            return Err("Packet check metadata does not match its bounded raw samples".into());
        }
        let mut previous = self.startedAtUnixMs;
        for (sequence, sample) in self.samples.iter().enumerate() {
            if sample.sequence != sequence
                || !sample.dontFragment
                || !(CONTROL_BYTES..=self.maximumTestedBytes).contains(&sample.packetBytes)
                || (sample.control && sample.packetBytes != CONTROL_BYTES)
                || !sample.echo.callDurationMs.is_finite()
                || sample.echo.callDurationMs < 0.0
                || (self.outcome != Outcome::ClockChanged && sample.timestampUnixMs < previous)
            {
                return Err("Packet check contains invalid sample evidence".into());
            }
            previous = sample.timestampUnixMs;
        }
        if self.outcome != Outcome::ClockChanged && self.finishedAtUnixMs < previous {
            return Err("Packet check timestamps moved backward".into());
        }
        if self.outcome != Outcome::SizeBoundaryObserved && self.confirmedBoundaryBytes.is_some() {
            return Err("An unfinished packet check cannot confirm a size boundary".into());
        }
        if matches!(
            self.outcome,
            Outcome::TestedLimitReached | Outcome::SizeBoundaryObserved
        ) {
            self.validateCompletedEvidence()?;
        }
        Ok(())
    }

    fn validateCompletedEvidence(&self) -> AppResult<()> {
        let invalid = || "Packet check conclusion does not match the controlled probe sequence";
        let controlsReply = |sample: &Sample| {
            sample.control
                && sample.packetBytes == CONTROL_BYTES
                && classify(&self.plan, &sample.echo) == Classification::Reply
        };
        if self.error.is_some()
            || self.samples.len() < 10
            || !self.samples[..3].iter().all(controlsReply)
        {
            return Err(invalid().into());
        }
        let (groups, remainder) = self.samples[3..].as_chunks::<7>();
        if !remainder.is_empty() {
            return Err(invalid().into());
        }
        let mut groups = groups.iter();
        let mut largest = None;
        let mut smallest = None;
        let mut nextGroup = |bytes, expected| -> AppResult<()> {
            let group = groups.next().ok_or_else(invalid)?;
            if group.iter().enumerate().any(|(index, sample)| {
                if index % 2 == 0 {
                    !controlsReply(sample)
                } else {
                    sample.control
                        || sample.packetBytes != bytes
                        || classify(&self.plan, &sample.echo) != expected
                }
            }) {
                return Err(invalid().into());
            }
            match expected {
                Classification::Reply => largest = Some(largest.unwrap_or(0).max(bytes)),
                Classification::TooBig => smallest = Some(smallest.unwrap_or(u32::MAX).min(bytes)),
                _ => return Err(invalid().into()),
            }
            Ok(())
        };
        if self.outcome == Outcome::TestedLimitReached {
            nextGroup(self.maximumTestedBytes, Classification::Reply)?;
        } else {
            let boundary = self.confirmedBoundaryBytes.ok_or_else(invalid)?;
            if !(MIN_SEARCH_BYTES..self.maximumTestedBytes).contains(&boundary) {
                return Err(invalid().into());
            }
            let mut high = self.maximumTestedBytes;
            let mut low = MIN_SEARCH_BYTES;
            nextGroup(high, Classification::TooBig)?;
            nextGroup(low, Classification::Reply)?;
            while high - low > 1 {
                let middle = low + (high - low) / 2;
                if middle <= boundary {
                    nextGroup(middle, Classification::Reply)?;
                    low = middle;
                } else {
                    nextGroup(middle, Classification::TooBig)?;
                    high = middle;
                }
            }
            nextGroup(low, Classification::Reply)?;
            nextGroup(high, Classification::TooBig)?;
        }
        if groups.next().is_some()
            || self.largestSuccessfulBytes != largest
            || self.smallestTooBigBytes != smallest
        {
            return Err(invalid().into());
        }
        Ok(())
    }
}

pub trait Probe {
    fn measure(
        &mut self,
        plan: &Plan,
        packetBytes: u32,
        timeout: Duration,
    ) -> AppResult<EchoOutcome>;
}

#[derive(Default)]
pub struct NativeProbe {
    #[cfg(windows)]
    native: windows::WindowsProbe,
}

impl Probe for NativeProbe {
    fn measure(
        &mut self,
        plan: &Plan,
        packetBytes: u32,
        timeout: Duration,
    ) -> AppResult<EchoOutcome> {
        plan.validate()?;
        if !(CONTROL_BYTES..=plan.interfaceMtu.min(MAX_PACKET_BYTES)).contains(&packetBytes)
            || !(1..=u128::from(plan.timeoutMs)).contains(&timeout.as_millis())
        {
            return Err("Packet-size probe exceeds its validated size or timeout limit".into());
        }
        #[cfg(windows)]
        return Ok(self
            .native
            .measure(plan, packetBytes, timeout.as_millis() as u32));
        #[cfg(not(windows))]
        Ok(EchoOutcome::unavailable(EchoStatus::Unsupported))
    }
}

fn nowUnixMs() -> AppResult<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Classification {
    Reply,
    TooBig,
    Unknown,
}

fn classify(plan: &Plan, echo: &EchoOutcome) -> Classification {
    if !echo.callDurationMs.is_finite() || echo.callDurationMs < 0.0 || echo.rttUnitMs != 1 {
        return Classification::Unknown;
    }
    match (echo.status, echo.nativeCode) {
        (EchoStatus::Reply, Some(0))
            if echo.responder == Some(plan.destination.into()) && echo.rttMs.is_some() =>
        {
            Classification::Reply
        }
        (EchoStatus::IpError, Some(PACKET_TOO_BIG)) if echo.rttMs.is_none() => {
            Classification::TooBig
        }
        _ => Classification::Unknown,
    }
}

struct Run<'a, P> {
    report: Report,
    probe: &'a mut P,
    cancelled: &'a AtomicBool,
    start: Instant,
    progress: &'a mut dyn FnMut(&Sample),
    stop: Option<Outcome>,
}

impl<P: Probe> Run<'_, P> {
    fn check(&mut self) -> AppResult<()> {
        let reason = if self.cancelled.load(Ordering::SeqCst) {
            Some(Outcome::Cancelled)
        } else if self.start.elapsed()
            >= Duration::from_millis(u64::from(self.report.plan.budgetMs))
            || self.report.samples.len() >= MAX_PROBES
        {
            Some(Outcome::BudgetExpired)
        } else {
            None
        };
        if let Some(reason) = reason {
            self.stop = Some(reason);
            return Err("Packet-size diagnosis stopped before all checks finished".into());
        }
        Ok(())
    }

    fn sample(&mut self, bytes: u32, control: bool) -> AppResult<Classification> {
        self.check()?;
        if !self.report.samples.is_empty() {
            let delayStart = Instant::now();
            let delay = Duration::from_millis(u64::from(self.report.plan.intervalMs));
            while delayStart.elapsed() < delay {
                self.check()?;
                std::thread::sleep(
                    Duration::from_millis(10).min(delay.saturating_sub(delayStart.elapsed())),
                );
            }
        }
        self.check()?;
        let remaining = Duration::from_millis(u64::from(self.report.plan.budgetMs))
            .saturating_sub(self.start.elapsed());
        let timeout = Duration::from_millis(u64::from(self.report.plan.timeoutMs)).min(remaining);
        if timeout.as_millis() == 0 {
            self.stop = Some(Outcome::BudgetExpired);
            return Err("Packet-size diagnosis reached its time budget".into());
        }
        let timestamp = nowUnixMs()?;
        if timestamp
            < self
                .report
                .samples
                .last()
                .map_or(self.report.startedAtUnixMs, |sample| sample.timestampUnixMs)
        {
            self.stop = Some(Outcome::ClockChanged);
            return Err("The system clock moved backward during the packet check".into());
        }
        let measured = self.probe.measure(&self.report.plan, bytes, timeout);
        let (echo, error) = match measured {
            Ok(echo) => (echo, None),
            Err(error) => (EchoOutcome::unavailable(EchoStatus::OsError), Some(error)),
        };
        let classification = classify(&self.report.plan, &echo);
        if echo.status == EchoStatus::Unsupported {
            self.stop = Some(Outcome::Unsupported);
        }
        self.report.requestedIpv4Bytes += u64::from(bytes);
        self.report.samples.push(Sample {
            sequence: self.report.samples.len(),
            timestampUnixMs: timestamp,
            packetBytes: bytes,
            control,
            dontFragment: true,
            echo,
        });
        (self.progress)(
            self.report
                .samples
                .last()
                .ok_or("Missing packet-size sample")?,
        );
        if let Some(error) = error {
            return Err(error);
        }
        if self.stop.is_some() {
            return Err("Native packet-size probes are unsupported on this system".into());
        }
        self.check()?;
        Ok(classification)
    }

    fn group(&mut self, bytes: u32) -> AppResult<Classification> {
        let mut common = None;
        for _ in 0..3 {
            if self.sample(CONTROL_BYTES, true)? != Classification::Reply {
                return Ok(Classification::Unknown);
            }
            let classification = self.sample(bytes, false)?;
            if classification == Classification::Unknown
                || common.is_some_and(|previous| previous != classification)
            {
                return Ok(Classification::Unknown);
            }
            common = Some(classification);
        }
        if self.sample(CONTROL_BYTES, true)? != Classification::Reply {
            return Ok(Classification::Unknown);
        }
        let result = common.unwrap_or(Classification::Unknown);
        match result {
            Classification::Reply => {
                self.report.largestSuccessfulBytes =
                    Some(self.report.largestSuccessfulBytes.unwrap_or(0).max(bytes))
            }
            Classification::TooBig => {
                self.report.smallestTooBigBytes = Some(
                    self.report
                        .smallestTooBigBytes
                        .unwrap_or(u32::MAX)
                        .min(bytes),
                )
            }
            _ => {}
        }
        Ok(result)
    }

    fn diagnose(&mut self) -> AppResult<Outcome> {
        for _ in 0..3 {
            if self.sample(CONTROL_BYTES, true)? != Classification::Reply {
                return Ok(Outcome::SmallPacketsUnavailable);
            }
        }
        let mut high = self.report.maximumTestedBytes;
        match self.group(high)? {
            Classification::Reply => return Ok(Outcome::TestedLimitReached),
            Classification::Unknown => return Ok(Outcome::Inconclusive),
            Classification::TooBig => {}
        }
        let mut low = MIN_SEARCH_BYTES;
        if high <= low {
            return Ok(Outcome::Inconclusive);
        }
        if self.group(low)? != Classification::Reply {
            return Ok(Outcome::Inconclusive);
        }
        while high - low > 1 {
            let middle = low + (high - low) / 2;
            match self.group(middle)? {
                Classification::Reply => low = middle,
                Classification::TooBig => high = middle,
                Classification::Unknown => return Ok(Outcome::Inconclusive),
            }
        }
        if self.group(low)? != Classification::Reply || self.group(high)? != Classification::TooBig
        {
            return Ok(Outcome::Inconclusive);
        }
        self.report.confirmedBoundaryBytes = Some(low);
        Ok(Outcome::SizeBoundaryObserved)
    }
}

pub fn diagnose<P: Probe>(
    plan: Plan,
    probe: &mut P,
    cancelled: &AtomicBool,
    mut progress: impl FnMut(&Sample),
) -> AppResult<Report> {
    plan.validate()?;
    let now = nowUnixMs()?;
    let mut run = Run {
        report: Report {
            schemaVersion: 1,
            maximumTestedBytes: plan.interfaceMtu.min(MAX_PACKET_BYTES),
            plan,
            outcome: Outcome::Inconclusive,
            startedAtUnixMs: now,
            finishedAtUnixMs: now,
            largestSuccessfulBytes: None,
            smallestTooBigBytes: None,
            confirmedBoundaryBytes: None,
            requestedIpv4Bytes: 0,
            samples: Vec::new(),
            error: None,
        },
        probe,
        cancelled,
        start: Instant::now(),
        progress: &mut progress,
        stop: None,
    };
    match run.diagnose() {
        Ok(outcome) => match run.check() {
            Ok(()) => run.report.outcome = outcome,
            Err(error) => {
                run.report.outcome = run.stop.unwrap_or(Outcome::Inconclusive);
                run.report.error = Some(error.to_string());
            }
        },
        Err(error) => {
            run.report.outcome = run.stop.unwrap_or(Outcome::Inconclusive);
            run.report.error = Some(error.to_string().chars().take(512).collect());
        }
    }
    run.report.finishedAtUnixMs = nowUnixMs()?;
    if run.report.finishedAtUnixMs
        < run
            .report
            .samples
            .last()
            .map_or(run.report.startedAtUnixMs, |sample| sample.timestampUnixMs)
    {
        run.report.outcome = Outcome::ClockChanged;
        run.report.error = Some("The system clock moved backward during the packet check".into());
    }
    if run.report.outcome != Outcome::SizeBoundaryObserved {
        run.report.confirmedBoundaryBytes = None;
    }
    Ok(run.report)
}
