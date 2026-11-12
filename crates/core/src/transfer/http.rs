use super::{
    Direction, Provider, SourceBinding, StreamResult, TransferPlan, TransferProgress,
    TransferResult, TransferStatus, deadline,
};
use crate::AppResult;
use bytes::Bytes;
use futures_util::{future::join_all, stream};
use reqwest::{Client, Response, header};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

const CHUNK_SIZE: usize = 32 * 1024;
const ACK_LIMIT: usize = 4096;

struct RequestContext<'a> {
    client: &'a Client,
    plan: &'a TransferPlan,
    binding: Option<&'a SourceBinding>,
}

struct ActiveRequest<'a>(&'a AtomicU64);
impl Drop for ActiveRequest<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

struct Failure(TransferStatus, String);
impl From<reqwest::Error> for Failure {
    fn from(error: reqwest::Error) -> Self {
        Self(
            if error.is_timeout() {
                TransferStatus::TimedOut
            } else {
                TransferStatus::NetworkError
            },
            error.without_url().to_string().chars().take(512).collect(),
        )
    }
}

fn protocolFailure(message: &str) -> Failure {
    Failure(TransferStatus::ProtocolError, message.into())
}

fn validateHeaders(
    response: &Response,
    context: &RequestContext<'_>,
    result: &mut StreamResult,
) -> Result<(), Failure> {
    let plan = context.plan;
    result.httpStatus = Some(response.status().as_u16());
    result.remoteAddress = response.remote_addr().map(|address| address.to_string());
    if context
        .binding
        .is_some_and(|binding| response.remote_addr() != Some(binding.peer))
    {
        return Err(protocolFailure(
            "Transfer peer differs from the pinned benchmark destination",
        ));
    }
    result.retryAfter = response
        .headers()
        .get(header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.chars().take(160).collect());
    if !response.status().is_success() {
        return Err(Failure(
            TransferStatus::HttpError,
            format!("HTTP {}; no automatic retry", response.status().as_u16()),
        ));
    }
    if response
        .headers()
        .get(header::CONTENT_ENCODING)
        .is_some_and(|value| value.as_bytes() != b"identity")
    {
        return Err(protocolFailure(
            "Encoded responses cannot be counted as uncompressed payload goodput",
        ));
    }
    if matches!(plan.provider, Provider::UserOwnedHttp { .. })
        && response
            .headers()
            .get("x-epp-benchmark-protocol")
            .is_none_or(|value| value.as_bytes() != b"1")
    {
        return Err(protocolFailure(
            "The selected server did not identify the EPP benchmark protocol version",
        ));
    }
    Ok(())
}

async fn exchange(
    context: &RequestContext<'_>,
    result: &mut StreamResult,
    download: &AtomicU64,
    upload: &Arc<AtomicU64>,
    progress: &TransferProgress,
    payload: Bytes,
) -> Result<(), Failure> {
    let client = context.client;
    let plan = context.plan;
    let url = plan
        .provider
        .requestUrl(plan.direction, result.requestedBytes)
        .map_err(|error| protocolFailure(&error.to_string()))?;
    let mut response = match plan.direction {
        Direction::Download => client.get(url).send().await?,
        Direction::Upload => {
            let remaining = result.requestedBytes;
            let uploaded = upload.clone();
            let totalProgress = progress.clone();
            let body = stream::unfold((remaining, payload), move |(remaining, payload)| {
                let uploaded = uploaded.clone();
                let totalProgress = totalProgress.clone();
                async move {
                    if remaining == 0 {
                        return None;
                    }
                    tokio::task::yield_now().await;
                    let size = remaining.min(payload.len() as u64) as usize;
                    uploaded.fetch_add(size as u64, Ordering::SeqCst);
                    totalProgress
                        .uploadBodyBytesProvided
                        .fetch_add(size as u64, Ordering::SeqCst);
                    Some((
                        Ok::<_, io::Error>(payload.slice(..size)),
                        (remaining - size as u64, payload),
                    ))
                }
            });
            client
                .post(url)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .header(header::CONTENT_LENGTH, remaining)
                .body(reqwest::Body::wrap_stream(body))
                .send()
                .await?
        }
    };
    validateHeaders(&response, context, result)?;
    match plan.direction {
        Direction::Download => {
            if response.status().as_u16() != 200
                || response.content_length() != Some(result.requestedBytes)
            {
                return Err(protocolFailure(
                    "Download requires HTTP 200 and the exact requested Content-Length",
                ));
            }
            while let Some(chunk) = response.chunk().await? {
                tokio::task::yield_now().await;
                let count = chunk.len() as u64;
                download.fetch_add(count, Ordering::SeqCst);
                progress
                    .downloadBytesRead
                    .fetch_add(count, Ordering::SeqCst);
                if download.load(Ordering::SeqCst) > result.requestedBytes {
                    return Err(protocolFailure(
                        "Download exceeded its declared payload length",
                    ));
                }
            }
            if download.load(Ordering::SeqCst) != result.requestedBytes {
                return Err(protocolFailure(
                    "Download ended before its declared payload length",
                ));
            }
        }
        Direction::Upload => {
            if upload.load(Ordering::SeqCst) != result.requestedBytes {
                return Err(protocolFailure(
                    "Server answered before the full upload body was provided",
                ));
            }
            if matches!(plan.provider, Provider::UserOwnedHttp { .. }) {
                let received = response
                    .headers()
                    .get("x-epp-received-bytes")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u64>().ok());
                if received != Some(result.requestedBytes) {
                    return Err(protocolFailure(
                        "Upload acknowledgement does not match the requested payload length",
                    ));
                }
            }
            let mut acknowledged = 0;
            while let Some(chunk) = response.chunk().await? {
                acknowledged += chunk.len();
                if acknowledged > ACK_LIMIT {
                    return Err(protocolFailure("Upload acknowledgement exceeds 4096 bytes"));
                }
            }
        }
    }
    result.acceptedPayloadBytes = result.requestedBytes;
    Ok(())
}

async fn waitForCancellation(cancelled: &AtomicBool) {
    loop {
        if cancelled.load(Ordering::SeqCst) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn measureStream(
    context: &RequestContext<'_>,
    ordinal: u8,
    started: Instant,
    cancelled: &AtomicBool,
    progress: &TransferProgress,
    payload: Bytes,
) -> StreamResult {
    let plan = context.plan;
    let base = plan.bytes / u64::from(plan.streams);
    let requestedBytes =
        base + u64::from(u64::from(ordinal) < plan.bytes % u64::from(plan.streams));
    let mut result = StreamResult {
        ordinal,
        requestedBytes,
        downloadBytesRead: 0,
        uploadBodyBytesProvided: 0,
        acceptedPayloadBytes: 0,
        elapsedMs: 0.0,
        status: TransferStatus::Cancelled,
        httpStatus: None,
        remoteAddress: None,
        retryAfter: None,
        error: None,
    };
    if cancelled.load(Ordering::SeqCst) {
        return result;
    }
    let upload = Arc::new(AtomicU64::new(0));
    let download = AtomicU64::new(0);
    progress.activeRequests.fetch_add(1, Ordering::SeqCst);
    let _activeRequest = ActiveRequest(&progress.activeRequests);
    let streamStart = Instant::now();
    let failure = tokio::select! {
        biased;
        _ = waitForCancellation(cancelled) => Some(Failure(TransferStatus::Cancelled, "Transfer cancelled".into())),
        _ = tokio::time::sleep_until(tokio::time::Instant::from_std(started + deadline(plan))) => Some(Failure(TransferStatus::TimedOut, "Transfer deadline expired".into())),
        response = exchange(context, &mut result, &download, &upload, progress, payload) => response.err(),
    };
    result.elapsedMs = streamStart.elapsed().as_secs_f64() * 1000.0;
    result.downloadBytesRead = download.load(Ordering::SeqCst);
    result.uploadBodyBytesProvided = upload.load(Ordering::SeqCst);
    if let Some(Failure(status, error)) = failure {
        result.status = status;
        result.error = Some(error);
        result.acceptedPayloadBytes = 0;
    } else {
        result.status = TransferStatus::Completed;
    }
    result
}

pub(super) async fn measure(
    plan: TransferPlan,
    binding: Option<SourceBinding>,
    cancelled: &AtomicBool,
    progress: &TransferProgress,
) -> AppResult<TransferResult> {
    let provider = plan.provider.info()?;
    let client = Client::builder()
        .http1_only()
        .http1_max_headers(64)
        .no_proxy()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(deadline(&plan))
        .pool_max_idle_per_host(0)
        .user_agent(concat!("estrogen-ping-patch/", env!("CARGO_PKG_VERSION")))
        .default_headers(
            [
                (
                    header::ACCEPT_ENCODING,
                    header::HeaderValue::from_static("identity"),
                ),
                (
                    header::CACHE_CONTROL,
                    header::HeaderValue::from_static("no-store"),
                ),
            ]
            .into_iter()
            .collect(),
        );
    let client = if let Some(binding) = binding {
        let origin = reqwest::Url::parse(&provider.origin)?;
        client.local_address(binding.source).resolve(
            origin.host_str().ok_or("Missing provider hostname")?,
            binding.peer,
        )
    } else {
        client
    }
    .build()?;
    let mut random = vec![0; CHUNK_SIZE];
    getrandom::fill(&mut random)
        .map_err(|error| format!("Transfer payload generation failed: {error}"))?;
    let payload = Bytes::from(random);
    let startedAt = chrono::Utc::now().to_rfc3339();
    let started = Instant::now();
    let context = RequestContext {
        client: &client,
        plan: &plan,
        binding: binding.as_ref(),
    };
    let streams = join_all((0..plan.streams).map(|ordinal| {
        measureStream(
            &context,
            ordinal,
            started,
            cancelled,
            progress,
            payload.clone(),
        )
    }))
    .await;
    let elapsedMs = started.elapsed().as_secs_f64() * 1000.0;
    let status = if cancelled.load(Ordering::SeqCst) {
        TransferStatus::Cancelled
    } else {
        streams
            .iter()
            .find(|stream| stream.status != TransferStatus::Completed)
            .map_or(TransferStatus::Completed, |stream| stream.status)
    };
    let acceptedPayloadBytes = streams
        .iter()
        .map(|stream| stream.acceptedPayloadBytes)
        .sum();
    let applicationGoodputMbps = if status == TransferStatus::Completed && elapsedMs > 0.0 {
        Some(acceptedPayloadBytes as f64 * 8.0 / (elapsedMs * 1000.0))
    } else {
        None
    };
    Ok(TransferResult {
        plan,
        provider,
        startedAt,
        finishedAt: chrono::Utc::now().to_rfc3339(),
        elapsedMs,
        status,
        acceptedPayloadBytes,
        applicationGoodputMbps,
        streams,
        sourceBinding: binding,
    })
}
