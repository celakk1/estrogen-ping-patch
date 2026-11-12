use crate::{
    ServiceResult,
    owned_process::{CommandJob, request, request::Input},
};
use epp_core::transfer::{
    Direction, SourceBinding, TransferPlan, TransferProgress, TransferResult, TransferStatus,
};
use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

mod protocol;
mod shared;
pub use protocol::{Counters, Observation, ProgressUpdate};

#[derive(Default)]
pub struct IsolatedTransferRunner {
    #[cfg(test)]
    image: Option<std::path::PathBuf>,
}

impl epp_core::transfer::session::BoundTransferRunner for IsolatedTransferRunner {
    fn createProgress(&self) -> ServiceResult<TransferProgress> {
        Ok(TransferProgress::fromStorage(shared::SharedProgress::new()?))
    }

    fn execution(&self) -> Option<epp_core::transfer::session::TransferExecution> {
        Some(epp_core::transfer::session::TransferExecution::RestrictedWorkerV2)
    }

    fn snapshot(
        &self,
        progress: &TransferProgress,
    ) -> ServiceResult<epp_core::transfer::session::ProgressSnapshot> {
        let counters = progress
            .storage::<shared::SharedProgress>()
            .ok_or("Isolated transfers require their own shared progress capability")?
            .read()?;
        Ok(epp_core::transfer::session::ProgressSnapshot {
            downloadBytesRead: counters.downloadBytesRead,
            uploadBodyBytesProvided: counters.uploadBodyBytesProvided,
            activeRequests: counters.activeRequests,
        })
    }

    fn measureFrom(
        &self,
        plan: TransferPlan,
        binding: SourceBinding,
        cancelled: &AtomicBool,
        progress: &TransferProgress,
    ) -> ServiceResult<TransferResult> {
        let started = Instant::now();
        let shared = progress
            .storage::<shared::SharedProgress>()
            .ok_or("Isolated transfers require their own shared progress capability")?;
        #[cfg(test)]
        let image = if let Some(image) = &self.image {
            image.clone()
        } else {
            workerImage()?
        };
        #[cfg(not(test))]
        let image = workerImage()?;
        measureUsingStorage(
            &image,
            Request {
                schemaVersion: SCHEMA_VERSION,
                plan,
                binding,
            },
            cancelled,
            shared,
            started,
            |_| Ok(()),
        )
    }
}

const SCHEMA_VERSION: u32 = 1;
#[cfg(test)]
const RESULT_BYTES: usize = 65536;

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    schemaVersion: u32,
    plan: TransferPlan,
    binding: SourceBinding,
}

impl Request {
    fn validate(&self) -> ServiceResult<()> {
        if self.schemaVersion != SCHEMA_VERSION {
            return Err("Unsupported benchmark worker request schema".into());
        }
        self.plan.validate()?;
        self.binding.validate(&self.plan.provider)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Response {
    schemaVersion: u32,
    result: TransferResult,
}

pub fn run(length: &str, parentId: &str, progressHandle: &str) -> ServiceResult<()> {
    let bytes = request::read(length, parentId)?;
    let input: Request = serde_json::from_slice(&bytes)?;
    input.validate()?;
    let cancelled = AtomicBool::new(false);
    let progress = TransferProgress::fromStorage(shared::SharedProgress::open(progressHandle)?);
    let started = Instant::now();
    let stdout = std::io::stdout();
    let mut encoder = protocol::Encoder::new(stdout.lock());
    std::thread::scope(|scope| {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let progressRef = &progress;
        let cancelledRef = &cancelled;
        scope.spawn(move || {
            let result = epp_core::transfer::measureIsolatedFrom(
                input.plan,
                input.binding,
                cancelledRef,
                progressRef,
            );
            let _ = sender.send(result);
        });
        let outcome = loop {
            match receiver.recv_timeout(Duration::from_millis(25)) {
                Ok(result) => {
                    break encoder
                        .progress(&progress, started)
                        .and_then(|()| encoder.finish(result?));
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if let Err(error) = encoder.progress(&progress, started) {
                        break Err(error);
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    break Err("Benchmark transfer task ended without a result".into());
                }
            }
        };
        cancelled.store(true, Ordering::SeqCst);
        outcome
    })
}

pub fn measureFrom(
    plan: TransferPlan,
    binding: SourceBinding,
    cancelled: &AtomicBool,
) -> ServiceResult<TransferResult> {
    measureWithProgress(plan, binding, cancelled, |_| Ok(()))
}

pub fn measureWithProgress(
    plan: TransferPlan,
    binding: SourceBinding,
    cancelled: &AtomicBool,
    onProgress: impl FnMut(ProgressUpdate) -> ServiceResult<()>,
) -> ServiceResult<TransferResult> {
    let image = workerImage()?;
    measureUsingProgress(&image, plan, binding, cancelled, onProgress)
}

fn workerImage() -> ServiceResult<std::path::PathBuf> {
    let image = std::env::current_exe()?.canonicalize()?;
    if !image
        .file_name()
        .is_some_and(|name| name.eq_ignore_ascii_case("epp-network-service.exe"))
    {
        return Err("Isolated transfers must be launched by the known service image".into());
    }
    Ok(image)
}

#[cfg(test)]
fn measureUsing(
    image: &Path,
    plan: TransferPlan,
    binding: SourceBinding,
    cancelled: &AtomicBool,
) -> ServiceResult<TransferResult> {
    measureUsingProgress(image, plan, binding, cancelled, |_| Ok(()))
}

fn measureUsingProgress(
    image: &Path,
    plan: TransferPlan,
    binding: SourceBinding,
    cancelled: &AtomicBool,
    onProgress: impl FnMut(ProgressUpdate) -> ServiceResult<()>,
) -> ServiceResult<TransferResult> {
    let started = Instant::now();
    let input = Request {
        schemaVersion: SCHEMA_VERSION,
        plan,
        binding,
    };
    input.validate()?;
    let shared = shared::SharedProgress::new()?;
    measureUsingStorage(image, input, cancelled, &shared, started, onProgress)
}

fn measureUsingStorage(
    image: &Path,
    input: Request,
    cancelled: &AtomicBool,
    shared: &shared::SharedProgress,
    started: Instant,
    mut onProgress: impl FnMut(ProgressUpdate) -> ServiceResult<()>,
) -> ServiceResult<TransferResult> {
    input.validate()?;
    if shared.read()? != Counters::default() {
        return Err("Isolated transfer progress cannot be reused".into());
    }
    let mut previous = Counters::default();
    let deadline = started
        .checked_add(Duration::from_millis(input.plan.timeoutMs))
        .ok_or("Benchmark worker deadline overflowed")?;
    let mut check = || {
        let counters = shared.read()?;
        counters.validate(&input, previous)?;
        previous = counters;
        if cancelled.load(Ordering::SeqCst) {
            Err("Isolated transfer cancelled".into())
        } else if Instant::now() >= deadline {
            Err("Isolated transfer phase deadline expired".into())
        } else {
            Ok(())
        }
    };
    check()?;
    let mapping = Input::new(&serde_json::to_vec(&input)?)?;
    let progressHandle = shared.inherit()?;
    check()?;
    let child = CommandJob::spawnRestrictedReader(
        image,
        &[
            "--transfer-worker".into(),
            mapping.length.to_string(),
            std::process::id().to_string(),
            {
                use std::os::windows::io::AsRawHandle;
                (progressHandle.as_raw_handle() as usize).to_string()
            },
        ],
        Some(&mapping.handle),
        Some(&progressHandle),
    )?;
    let mut decoder = protocol::Decoder::new(&input);
    child.stream(protocol::STREAM_BYTES, check, |chunk| {
        decoder.consume(chunk, &mut onProgress)
    })?;
    let result = decoder.finish()?;
    if shared.read()? != Counters::fromResult(&result) {
        return Err("Benchmark worker result disagrees with its shared counters".into());
    }
    Ok(result)
}

#[cfg(test)]
fn parseResult(input: &Request, output: &[u8]) -> ServiceResult<TransferResult> {
    if output.is_empty() || output.len() > RESULT_BYTES {
        return Err("Benchmark worker result is outside its fixed allowance".into());
    }
    let value: serde_json::Value = serde_json::from_slice(output)?;
    let response: Response = serde_json::from_value(value.clone())?;
    if serde_json::to_value(&response)? != value {
        return Err("Benchmark worker result contains missing or unknown fields".into());
    }
    validateResult(input, &response)?;
    Ok(response.result)
}

fn validateResult(input: &Request, response: &Response) -> ServiceResult<()> {
    let result = &response.result;
    if response.schemaVersion != SCHEMA_VERSION
        || serde_json::to_value(&result.plan)? != serde_json::to_value(&input.plan)?
        || serde_json::to_value(&result.provider)?
            != serde_json::to_value(input.plan.provider.info()?)?
        || result.sourceBinding != Some(input.binding)
        || result.streams.len() != usize::from(input.plan.streams)
        || !result.elapsedMs.is_finite()
        || result.elapsedMs <= 0.0
        || result.elapsedMs > input.plan.timeoutMs as f64 + 1000.0
        || result.startedAt.len() > 64
        || result.finishedAt.len() > 64
        || result.status == TransferStatus::Cancelled
    {
        return Err("Benchmark worker result does not match its frozen request".into());
    }
    let started = chrono::DateTime::parse_from_rfc3339(&result.startedAt)?;
    let finished = chrono::DateTime::parse_from_rfc3339(&result.finishedAt)?;
    let wallMs = finished
        .signed_duration_since(started)
        .num_microseconds()
        .ok_or("Benchmark worker timestamp interval overflowed")? as f64
        / 1000.0;
    if wallMs < 0.0 || (wallMs - result.elapsedMs).abs() > 50.0 {
        return Err("Benchmark worker timestamps disagree with its measured duration".into());
    }
    let mut accepted = 0;
    for (ordinal, stream) in result.streams.iter().enumerate() {
        let requested = input.plan.bytes / u64::from(input.plan.streams)
            + u64::from((ordinal as u64) < input.plan.bytes % u64::from(input.plan.streams));
        let completed = stream.status == TransferStatus::Completed;
        if stream.ordinal as usize != ordinal
            || stream.requestedBytes != requested
            || stream.downloadBytesRead > requested
            || stream.uploadBodyBytesProvided > requested
            || (input.plan.direction == Direction::Download && stream.uploadBodyBytesProvided != 0)
            || (input.plan.direction == Direction::Upload && stream.downloadBytesRead != 0)
            || !stream.elapsedMs.is_finite()
            || stream.elapsedMs < 0.0
            || stream.elapsedMs > result.elapsedMs
            || stream.acceptedPayloadBytes != if completed { requested } else { 0 }
            || stream
                .httpStatus
                .is_some_and(|status| !(100..=599).contains(&status))
            || stream.remoteAddress.as_ref().is_some_and(|address| {
                address.parse::<std::net::SocketAddr>().ok() != Some(input.binding.peer)
            })
            || stream
                .error
                .as_ref()
                .is_some_and(|error| error.len() > 2048)
            || stream
                .retryAfter
                .as_ref()
                .is_some_and(|retry| retry.len() > 4096)
            || stream.status == TransferStatus::Cancelled
            || (completed
                && (stream.error.is_some()
                    || stream.remoteAddress.is_none()
                    || !stream
                        .httpStatus
                        .is_some_and(|status| (200..=299).contains(&status))
                    || (input.plan.direction == Direction::Download
                        && (stream.httpStatus != Some(200)
                            || stream.downloadBytesRead != requested))
                    || (input.plan.direction == Direction::Upload
                        && stream.uploadBodyBytesProvided != requested)))
        {
            return Err("Benchmark worker stream exceeds or contradicts its frozen request".into());
        }
        accepted += stream.acceptedPayloadBytes;
    }
    let status = result
        .streams
        .iter()
        .find(|stream| stream.status != TransferStatus::Completed)
        .map_or(TransferStatus::Completed, |stream| stream.status);
    let goodput = if status == TransferStatus::Completed {
        Some(accepted as f64 * 8.0 / (result.elapsedMs * 1000.0))
    } else {
        None
    };
    if result.status != status
        || result.acceptedPayloadBytes != accepted
        || match (result.applicationGoodputMbps, goodput) {
            (None, None) => false,
            (Some(actual), Some(expected)) => {
                !actual.is_finite() || (actual - expected).abs() > expected.abs().max(1.0) * 1e-9
            }
            _ => true,
        }
    {
        return Err("Benchmark worker summary does not match its raw streams".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
