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

const SCHEMA_VERSION: u32 = 1;
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

pub fn run(length: &str, parentId: &str) -> ServiceResult<()> {
    let bytes = request::read(length, parentId)?;
    let input: Request = serde_json::from_slice(&bytes)?;
    input.validate()?;
    let cancelled = AtomicBool::new(false);
    let result = epp_core::transfer::measureFrom(
        input.plan,
        input.binding,
        &cancelled,
        &TransferProgress::default(),
    )?;
    let output = serde_json::to_vec(&Response {
        schemaVersion: SCHEMA_VERSION,
        result,
    })?;
    if output.len() > RESULT_BYTES {
        return Err("Benchmark worker result exceeded its fixed allowance".into());
    }
    std::io::stdout().lock().write_all(&output)?;
    Ok(())
}

pub fn measureFrom(
    plan: TransferPlan,
    binding: SourceBinding,
    cancelled: &AtomicBool,
) -> ServiceResult<TransferResult> {
    let image = std::env::current_exe()?.canonicalize()?;
    if !image
        .file_name()
        .is_some_and(|name| name.eq_ignore_ascii_case("epp-network-service.exe"))
    {
        return Err("Isolated transfers must be launched by the known service image".into());
    }
    measureUsing(&image, plan, binding, cancelled)
}

fn measureUsing(
    image: &Path,
    plan: TransferPlan,
    binding: SourceBinding,
    cancelled: &AtomicBool,
) -> ServiceResult<TransferResult> {
    let started = Instant::now();
    let input = Request {
        schemaVersion: SCHEMA_VERSION,
        plan,
        binding,
    };
    input.validate()?;
    let deadline = started
        .checked_add(Duration::from_millis(input.plan.timeoutMs))
        .ok_or("Benchmark worker deadline overflowed")?;
    let check = || {
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
    check()?;
    let child = CommandJob::spawnRestrictedReader(
        image,
        &[
            "--transfer-worker".into(),
            mapping.length.to_string(),
            std::process::id().to_string(),
        ],
        Some(&mapping.handle),
    )?;
    let output = child.collect(RESULT_BYTES, check)?;
    parseResult(&input, &output)
}

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
