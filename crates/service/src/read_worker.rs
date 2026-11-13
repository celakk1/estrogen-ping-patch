use crate::{
    ServiceResult,
    owned_process::{
        CommandJob,
        request::{self, Input},
    },
    routing,
};
use epp_core::packet_size::{self, Limits, Outcome, Report, Sample};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    io::Write,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

const FRAME_BYTES: usize = 131_072;
const STREAM_BYTES: usize = 524_288;

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
enum Request {
    Routes {
        targets: Vec<routing::Address>,
    },
    Packet {
        plan: packet_size::Plan,
        limits: Limits,
    },
}

impl Request {
    fn validate(&self) -> ServiceResult<()> {
        match self {
            Self::Routes { targets } => {
                if !(1..=8).contains(&targets.len()) {
                    return Err("Route worker requires one to eight destinations".into());
                }
                for (index, target) in targets.iter().enumerate() {
                    target.validateDestination()?;
                    if targets[..index].contains(target) {
                        return Err("Route worker destinations must be distinct".into());
                    }
                }
                Ok(())
            }
            Self::Packet { plan, limits } => {
                plan.validate()?;
                limits.validate()
            }
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Frame<T> {
    schemaVersion: u32,
    sequence: u32,
    body: T,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
enum Body {
    Sample(Sample),
    Packet(Box<Report>),
    Routes(Vec<routing::Capture>),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
enum Output<'a> {
    Sample(&'a Sample),
    Packet(&'a Report),
    Routes(&'a [routing::Capture]),
}

fn decode<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> ServiceResult<T> {
    let result: T = serde_json::from_slice(bytes)?;
    if serde_json::to_value(&result)? != serde_json::from_slice::<serde_json::Value>(bytes)? {
        return Err("Network reader contains missing or unknown fields".into());
    }
    Ok(result)
}

struct Encoder<W> {
    writer: W,
    sequence: u32,
    bytes: usize,
}
impl<W: Write> Encoder<W> {
    fn send(&mut self, body: Output<'_>) -> ServiceResult<()> {
        let bytes = serde_json::to_vec(&Frame {
            schemaVersion: 1,
            sequence: self.sequence,
            body,
        })?;
        if self.sequence >= 145
            || bytes.len() + 1 > FRAME_BYTES
            || self.bytes + bytes.len() + 1 > STREAM_BYTES
        {
            return Err("Network reader exceeded its fixed frame allowance".into());
        }
        self.writer.write_all(&bytes)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        self.sequence += 1;
        self.bytes += bytes.len() + 1;
        Ok(())
    }
}

pub fn run(length: &str, parentId: &str) -> ServiceResult<()> {
    runVerified(request::read(length, parentId)?, false)
}

pub fn runPacket(length: &str, parentId: &str) -> ServiceResult<()> {
    runVerified(request::readPacket(length, parentId)?, true)
}

fn runVerified(bytes: Vec<u8>, packet: bool) -> ServiceResult<()> {
    let envelope: Frame<Request> = decode(&bytes)?;
    if envelope.schemaVersion != 1 || envelope.sequence != 0 {
        return Err("Unsupported network reader request schema".into());
    }
    let input = envelope.body;
    input.validate()?;
    if matches!(input, Request::Packet { .. }) != packet {
        return Err("Network reader operation does not match its token policy".into());
    }
    let stdout = std::io::stdout();
    let mut encoder = Encoder {
        writer: stdout.lock(),
        sequence: 0,
        bytes: 0,
    };
    let cancelled = AtomicBool::new(false);
    match input {
        Request::Routes { targets } => {
            encoder.send(Output::Routes(&routing::capture(&targets, &cancelled)?))
        }
        Request::Packet { plan, limits } => {
            let mut failure = None;
            let report = packet_size::diagnoseWithLimits(
                plan,
                limits,
                &mut packet_size::NativeProbe::default(),
                &cancelled,
                |sample| {
                    if failure.is_none()
                        && let Err(error) = encoder.send(Output::Sample(sample))
                    {
                        failure = Some(error);
                        cancelled.store(true, Ordering::SeqCst);
                    }
                },
            )?;
            if let Some(error) = failure {
                return Err(error);
            }
            encoder.send(Output::Packet(&report))
        }
    }
}

struct Decoder<'a> {
    input: &'a Request,
    startedAtUnixMs: u64,
    bytes: usize,
    sequence: u32,
    partial: Vec<u8>,
    samples: Vec<Sample>,
    result: Option<Body>,
}

impl<'a> Decoder<'a> {
    fn new(input: &'a Request, startedAtUnixMs: u64) -> Self {
        Self {
            input,
            startedAtUnixMs,
            bytes: 0,
            sequence: 0,
            partial: Vec::new(),
            samples: Vec::new(),
            result: None,
        }
    }
    fn consume(
        &mut self,
        bytes: &[u8],
        progress: &mut impl FnMut(&Sample) -> ServiceResult<()>,
    ) -> ServiceResult<()> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .ok_or("Network reader size overflow")?;
        if self.bytes > STREAM_BYTES {
            return Err("Network reader stream allowance exceeded".into());
        }
        for piece in bytes.split_inclusive(|byte| *byte == b'\n') {
            if self.result.is_some() || self.partial.len() + piece.len() > FRAME_BYTES {
                return Err("Network reader trailing data or frame allowance exceeded".into());
            }
            self.partial.extend_from_slice(piece);
            if self.partial.last() == Some(&b'\n') {
                let mut line = std::mem::take(&mut self.partial);
                line.pop();
                self.frame(&line, progress)?;
                line.clear();
                self.partial = line;
            }
        }
        Ok(())
    }
    fn frame(
        &mut self,
        line: &[u8],
        progress: &mut impl FnMut(&Sample) -> ServiceResult<()>,
    ) -> ServiceResult<()> {
        let frame: Frame<Body> = decode(line)?;
        if frame.schemaVersion != 1 || frame.sequence != self.sequence || self.sequence >= 145 {
            return Err("Network reader version or sequence changed".into());
        }
        match (&self.input, frame.body) {
            (Request::Packet { plan, limits }, Body::Sample(sample)) => {
                let previous = self
                    .samples
                    .last()
                    .map_or(self.startedAtUnixMs, |sample| sample.timestampUnixMs);
                let requested: u64 = self
                    .samples
                    .iter()
                    .map(|sample| u64::from(sample.packetBytes))
                    .sum();
                if sample.sequence != self.samples.len()
                    || self.samples.len() >= limits.maximumProbes
                    || sample.timestampUnixMs < previous
                    || sample.timestampUnixMs > crate::watchdog::nowUnixMs()?.saturating_add(250)
                    || !sample.dontFragment
                    || !(84..=plan.interfaceMtu.min(packet_size::MAX_PACKET_BYTES))
                        .contains(&sample.packetBytes)
                    || (sample.control && sample.packetBytes != 84)
                    || requested + u64::from(sample.packetBytes) > limits.maximumRequestedIpv4Bytes
                    || !sample.echo.callDurationMs.is_finite()
                    || sample.echo.callDurationMs < 0.0
                    || sample.echo.rttUnitMs != 1
                {
                    return Err(
                        "Network reader probe contradicts its frozen request or allowance".into(),
                    );
                }
                self.samples.push(sample);
                progress(self.samples.last().unwrap())?;
            }
            (Request::Packet { plan, limits }, Body::Packet(report)) => {
                report.validate()?;
                if serde_json::to_value(&report.plan)? != serde_json::to_value(plan)?
                    || serde_json::to_value(&report.samples)?
                        != serde_json::to_value(&self.samples)?
                    || report.samples.len() > limits.maximumProbes
                    || report.requestedIpv4Bytes > limits.maximumRequestedIpv4Bytes
                    || report.startedAtUnixMs < self.startedAtUnixMs
                    || report.finishedAtUnixMs > crate::watchdog::nowUnixMs()?.saturating_add(250)
                {
                    return Err(
                        "Network reader terminal report differs from its validated probe stream"
                            .into(),
                    );
                }
                self.result = Some(Body::Packet(report));
            }
            (Request::Routes { targets }, Body::Routes(captures)) => {
                if captures.len() != targets.len() {
                    return Err("Network reader route count changed".into());
                }
                for (target, capture) in targets.iter().zip(&captures) {
                    match capture {
                        routing::Capture::Captured { snapshot } => {
                            snapshot.validate()?;
                            if &snapshot.destination != target
                                || snapshot.capturedAtUnixMs < self.startedAtUnixMs
                                || snapshot.capturedAtUnixMs
                                    > crate::watchdog::nowUnixMs()?.saturating_add(250)
                            {
                                return Err(
                                    "Network reader route identity or capture time changed".into(),
                                );
                            }
                        }
                        routing::Capture::Unavailable { destination, error } => {
                            if destination != target || error.len() > 2048 {
                                return Err("Network reader unavailable route changed".into());
                            }
                        }
                    }
                }
                self.result = Some(Body::Routes(captures));
            }
            _ => return Err("Network reader frame does not match its fixed operation".into()),
        }
        self.sequence += 1;
        Ok(())
    }
    fn finish(&mut self) -> ServiceResult<Body> {
        if !self.partial.is_empty() {
            return Err("Network reader ended with an incomplete frame".into());
        }
        self.result
            .take()
            .ok_or_else(|| "Network reader ended without a terminal frame".into())
    }
}

fn image() -> ServiceResult<std::path::PathBuf> {
    let image = std::env::current_exe()?.canonicalize()?;
    if !image
        .file_name()
        .is_some_and(|name| name.eq_ignore_ascii_case("epp-network-service.exe"))
    {
        return Err("Network readers require the known service image".into());
    }
    Ok(image)
}

fn spawn(image: &Path, input: &Request) -> ServiceResult<(CommandJob, Input)> {
    input.validate()?;
    let mapping = Input::new(&serde_json::to_vec(&Frame {
        schemaVersion: 1,
        sequence: 0,
        body: input,
    })?)?;
    let arguments = vec![
        if matches!(input, Request::Packet { .. }) {
            "--packet-read-worker"
        } else {
            "--network-read-worker"
        }
        .into(),
        mapping.length.to_string(),
        std::process::id().to_string(),
    ];
    let child = match input {
        Request::Packet { .. } => {
            CommandJob::spawnPacketReader(image, &arguments, &mapping.handle)?
        }
        Request::Routes { .. } => {
            CommandJob::spawnRestrictedReader(image, &arguments, Some(&mapping.handle), None)?
        }
    };
    Ok((child, mapping))
}

fn execute(
    image: &Path,
    input: &Request,
    cancelled: &AtomicBool,
    budget: Duration,
    progress: &mut impl FnMut(&Sample) -> ServiceResult<()>,
    decoder: &mut Decoder<'_>,
) -> ServiceResult<Body> {
    let started = Instant::now();
    let check = || {
        if cancelled.load(Ordering::SeqCst) {
            Err("Network reader cancelled".into())
        } else if started.elapsed() >= budget {
            Err("Network reader process deadline expired".into())
        } else {
            Ok(())
        }
    };
    input.validate()?;
    check()?;
    let (child, _mapping) = spawn(image, input)?;
    child.stream(STREAM_BYTES, check, |chunk| {
        decoder.consume(chunk, progress)
    })?;
    decoder.finish()
}

pub fn routes(
    targets: &[routing::Address],
    cancelled: &AtomicBool,
) -> ServiceResult<Vec<routing::Capture>> {
    routesUsing(&image()?, targets, cancelled)
}

fn routesUsing(
    image: &Path,
    targets: &[routing::Address],
    cancelled: &AtomicBool,
) -> ServiceResult<Vec<routing::Capture>> {
    let input = Request::Routes {
        targets: targets.to_vec(),
    };
    let mut decoder = Decoder::new(&input, crate::watchdog::nowUnixMs()?);
    match execute(
        image,
        &input,
        cancelled,
        Duration::from_secs(3),
        &mut |_| Ok(()),
        &mut decoder,
    )? {
        Body::Routes(captures) => Ok(captures),
        _ => Err("Network reader did not return routes".into()),
    }
}

pub fn diagnose(
    plan: packet_size::Plan,
    limits: Limits,
    cancelled: &AtomicBool,
    progress: impl FnMut(&Sample) -> ServiceResult<()>,
) -> ServiceResult<Report> {
    diagnoseUsing(&image()?, plan, limits, cancelled, progress)
}

fn diagnoseUsing(
    image: &Path,
    plan: packet_size::Plan,
    limits: Limits,
    cancelled: &AtomicBool,
    mut progress: impl FnMut(&Sample) -> ServiceResult<()>,
) -> ServiceResult<Report> {
    let input = Request::Packet {
        plan: plan.clone(),
        limits,
    };
    input.validate()?;
    let startedAtUnixMs = crate::watchdog::nowUnixMs()?;
    let mut decoder = Decoder::new(&input, startedAtUnixMs);
    match execute(
        image,
        &input,
        cancelled,
        Duration::from_millis(u64::from(plan.budgetMs)),
        &mut progress,
        &mut decoder,
    ) {
        Ok(Body::Packet(report)) => Ok(*report),
        outcome => {
            let detail = match outcome {
                Err(error) => error.to_string(),
                _ => "Network reader did not return a packet report".into(),
            };
            let finishedAtUnixMs = crate::watchdog::nowUnixMs()?;
            let clockChanged = finishedAtUnixMs
                < decoder
                    .samples
                    .last()
                    .map_or(startedAtUnixMs, |sample| sample.timestampUnixMs);
            let report = Report {
                schemaVersion: 1,
                maximumTestedBytes: plan.interfaceMtu.min(packet_size::MAX_PACKET_BYTES),
                plan,
                outcome: if clockChanged {
                    Outcome::ClockChanged
                } else if cancelled.load(Ordering::SeqCst) {
                    Outcome::Cancelled
                } else {
                    Outcome::Inconclusive
                },
                startedAtUnixMs,
                finishedAtUnixMs,
                largestSuccessfulBytes: None,
                smallestTooBigBytes: None,
                confirmedBoundaryBytes: None,
                requestedIpv4Bytes: decoder
                    .samples
                    .iter()
                    .map(|sample| u64::from(sample.packetBytes))
                    .sum(),
                samples: decoder.samples,
                error: Some(
                    detail
                        .chars()
                        .take(512)
                        .map(|value| if value.is_control() { ' ' } else { value })
                        .collect(),
                ),
            };
            report.validate()?;
            Ok(report)
        }
    }
}

#[cfg(test)]
mod tests;
