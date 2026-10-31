use super::{DnsOutcome, DnsStatus, QueryPlan, Transport, wire};
use crate::AppResult;
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream, UdpSocket},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

const IO_POLL: Duration = Duration::from_millis(50);
const MAX_REJECTED_RESPONSES: u32 = 32;

enum ExchangeError {
    Cancelled,
    Timeout,
    Io(io::Error),
    Invalid(String),
}
impl From<io::Error> for ExchangeError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

fn remaining(deadline: Instant, cancelled: &AtomicBool) -> Result<Duration, ExchangeError> {
    if cancelled.load(Ordering::SeqCst) {
        return Err(ExchangeError::Cancelled);
    }
    let duration = deadline.saturating_duration_since(Instant::now());
    if duration.is_zero() {
        Err(ExchangeError::Timeout)
    } else {
        Ok(duration)
    }
}

fn transient(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

fn tcpExchange(
    resolver: SocketAddr,
    payload: &[u8],
    deadline: Instant,
    cancelled: &AtomicBool,
    result: &mut DnsOutcome,
) -> Result<Vec<u8>, ExchangeError> {
    let mut stream = TcpStream::connect_timeout(&resolver, remaining(deadline, cancelled)?)
        .map_err(|error| {
            if transient(&error) {
                ExchangeError::Timeout
            } else {
                ExchangeError::Io(error)
            }
        })?;
    let mut request = Vec::with_capacity(payload.len() + 2);
    request.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    request.extend_from_slice(payload);
    let mut position = 0;
    while position < request.len() {
        stream.set_write_timeout(Some(remaining(deadline, cancelled)?.min(IO_POLL)))?;
        match stream.write(&request[position..]) {
            Ok(0) => {
                return Err(ExchangeError::Invalid(
                    "DNS TCP connection closed while writing".into(),
                ));
            }
            Ok(count) => {
                position += count;
                result.requestBytes += count as u32;
            }
            Err(error) if transient(&error) => {}
            Err(error) => return Err(error.into()),
        }
    }
    let mut length = [0u8; 2];
    readExact(&mut stream, &mut length, deadline, cancelled, result)?;
    let length = usize::from(u16::from_be_bytes(length));
    if length < 12 {
        return Err(ExchangeError::Invalid(
            "DNS TCP response length is invalid".into(),
        ));
    }
    let mut buffer = vec![0u8; length];
    readExact(&mut stream, &mut buffer, deadline, cancelled, result)?;
    remaining(deadline, cancelled)?;
    Ok(buffer)
}

fn readExact(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    deadline: Instant,
    cancelled: &AtomicBool,
    result: &mut DnsOutcome,
) -> Result<(), ExchangeError> {
    let mut position = 0;
    while position < buffer.len() {
        stream.set_read_timeout(Some(remaining(deadline, cancelled)?.min(IO_POLL)))?;
        match stream.read(&mut buffer[position..]) {
            Ok(0) => {
                return Err(ExchangeError::Invalid(
                    "DNS TCP response ended before its declared length".into(),
                ));
            }
            Ok(count) => {
                position += count;
                result.responseBytes += count as u32;
            }
            Err(error) if transient(&error) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn exchange(
    resolver: SocketAddr,
    request: &[u8],
    id: u16,
    deadline: Instant,
    cancelled: &AtomicBool,
    result: &mut DnsOutcome,
) -> Result<Vec<u8>, ExchangeError> {
    let local: SocketAddr = if resolver.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()
    .unwrap();
    let socket = UdpSocket::bind(local)?;
    socket.connect(resolver)?;
    socket.set_write_timeout(Some(remaining(deadline, cancelled)?))?;
    let sent = socket.send(request)?;
    result.requestBytes += sent as u32;
    if sent != request.len() {
        return Err(ExchangeError::Invalid(
            "DNS UDP query was not sent completely".into(),
        ));
    }
    let mut buffer = [0u8; 513];
    loop {
        socket.set_read_timeout(Some(remaining(deadline, cancelled)?.min(IO_POLL)))?;
        let count = match socket.recv(&mut buffer) {
            Ok(count) => count,
            Err(error) if transient(&error) => continue,
            Err(error) => return Err(error.into()),
        };
        result.responseBytes += count as u32;
        remaining(deadline, cancelled)?;
        let parsed = if count > 512 {
            Err("DNS UDP response exceeds the non-EDNS limit".into())
        } else {
            wire::isTruncated(&buffer[..count], &result.query, id)
        };
        match parsed {
            Ok(true) => {
                result.transport = Transport::TcpFallback;
                return tcpExchange(resolver, request, deadline, cancelled, result);
            }
            Ok(false) => return Ok(buffer[..count].to_vec()),
            Err(error) => {
                result.rejectedResponses += 1;
                if result.rejectedResponses >= MAX_REJECTED_RESPONSES {
                    return Err(ExchangeError::Invalid(error.to_string()));
                }
            }
        }
    }
}

pub(super) fn measure(
    resolver: SocketAddr,
    query: QueryPlan,
    timeout: Duration,
    cancelled: &AtomicBool,
) -> AppResult<DnsOutcome> {
    let mut result = DnsOutcome::empty(query);
    if cancelled.load(Ordering::SeqCst) {
        return Ok(result);
    }
    let mut random = [0u8; 2];
    getrandom::fill(&mut random)
        .map_err(|error| format!("DNS transaction ID generation failed: {error}"))?;
    let id = u16::from_ne_bytes(random);
    let request = wire::request(&result.query, id)?;
    let start = Instant::now();
    let response = exchange(
        resolver,
        &request,
        id,
        start + timeout,
        cancelled,
        &mut result,
    );
    match response {
        Ok(response) => {
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;
            let mut parsed = DnsOutcome::empty(result.query.clone());
            match wire::apply(&response, &result.query, id, &mut parsed) {
                Ok(()) => {
                    parsed.transport = result.transport;
                    parsed.requestBytes = result.requestBytes;
                    parsed.responseBytes = result.responseBytes;
                    parsed.rejectedResponses = result.rejectedResponses;
                    parsed.responseMs = Some(elapsed);
                    if parsed.status == DnsStatus::Resolved {
                        parsed.lookupMs = Some(start.elapsed().as_secs_f64() * 1000.0);
                    }
                    result = parsed;
                }
                Err(error) => {
                    result.status = DnsStatus::InvalidResponse;
                    result.error = Some(error.to_string());
                }
            }
        }
        Err(error) => {
            let (status, reason) = match error {
                ExchangeError::Cancelled => (DnsStatus::Cancelled, None),
                ExchangeError::Timeout => (
                    DnsStatus::TimedOut,
                    Some("DNS query deadline expired".into()),
                ),
                ExchangeError::Io(error) => (DnsStatus::OsError, Some(error.to_string())),
                ExchangeError::Invalid(reason) => (DnsStatus::InvalidResponse, Some(reason)),
            };
            result.status = status;
            result.error = reason;
        }
    }
    Ok(result)
}
