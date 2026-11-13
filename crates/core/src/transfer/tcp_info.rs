use crate::AppResult;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TcpInfo {
    pub schemaVersion: u32,
    pub source: SocketAddr,
    pub peer: SocketAddr,
    pub capturedAt: String,
    pub queryElapsedNs: String,
    pub state: i32,
    pub maximumSegmentSize: u32,
    pub connectionTimeMs: String,
    pub timestampsEnabled: bool,
    pub rttUs: u32,
    pub minimumRttUs: u32,
    pub bytesInFlight: u32,
    pub congestionWindowBytes: u32,
    pub sendWindowBytes: u32,
    pub receiveWindowBytes: u32,
    pub receiveBufferBytes: u32,
    pub bytesOut: String,
    pub bytesIn: String,
    pub bytesReordered: u32,
    pub bytesRetransmitted: u32,
    pub fastRetransmissions: u32,
    pub duplicateAcksIn: u32,
    pub timeoutEpisodes: u32,
    pub synRetransmissions: u8,
}

impl TcpInfo {
    pub fn validate(&self) -> AppResult<()> {
        if self.schemaVersion != 1
            || !(0..=10).contains(&self.state)
            || self.capturedAt.len() > 64
            || self.source.port() == 0
            || self.peer.port() == 0
            || self.source.ip().is_ipv4() != self.peer.ip().is_ipv4()
        {
            return Err(
                "Socket TCP evidence has invalid schema, state, addresses, or timestamp".into(),
            );
        }
        for address in [self.source, self.peer] {
            crate::icmp::EchoTarget {
                address: address.ip(),
                scopeId: match address {
                    SocketAddr::V6(value) => value.scope_id(),
                    _ => 0,
                },
            }
            .validate()?;
        }
        chrono::DateTime::parse_from_rfc3339(&self.capturedAt)?;
        for value in [
            &self.queryElapsedNs,
            &self.connectionTimeMs,
            &self.bytesOut,
            &self.bytesIn,
        ] {
            let parsed: u64 = value.parse()?;
            if parsed.to_string() != *value {
                return Err("Socket TCP counters require canonical unsigned decimal values".into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
pub enum TcpInfoEvidence {
    Measured { snapshot: Box<TcpInfo> },
    Unavailable { reason: String },
}

impl TcpInfoEvidence {
    pub fn validate(&self) -> AppResult<()> {
        match self {
            Self::Measured { snapshot } => snapshot.validate(),
            Self::Unavailable { reason } => super::resources::validateUnavailableReason(reason),
        }
    }

    pub fn validateFor(
        &self,
        binding: super::SourceBinding,
        startedAt: &str,
        finishedAt: &str,
    ) -> AppResult<()> {
        self.validate()?;
        if let Self::Measured { snapshot } = self {
            let captured = chrono::DateTime::parse_from_rfc3339(&snapshot.capturedAt)?;
            if snapshot.source.ip() != binding.source
                || snapshot.peer != binding.peer
                || (1..=3).contains(&snapshot.state)
                || captured < chrono::DateTime::parse_from_rfc3339(startedAt)?
                || captured > chrono::DateTime::parse_from_rfc3339(finishedAt)?
            {
                return Err(
                    "Socket TCP evidence differs from its connected source/peer or transfer window"
                        .into(),
                );
            }
        }
        Ok(())
    }
}

#[cfg(feature = "isolated-tls")]
#[derive(Default)]
pub(super) struct Slot(std::sync::Mutex<Option<Result<std::net::TcpStream, String>>>);

#[cfg(feature = "isolated-tls")]
pub(super) fn unavailable(error: impl std::fmt::Display) -> TcpInfoEvidence {
    TcpInfoEvidence::Unavailable {
        reason: error
            .to_string()
            .chars()
            .take(512)
            .map(|value| if value.is_control() { ' ' } else { value })
            .collect(),
    }
}

#[cfg(feature = "isolated-tls")]
impl Slot {
    pub(super) fn attach(&self, socket: &std::net::TcpStream) {
        *self.0.lock().unwrap_or_else(|error| error.into_inner()) =
            Some(socket.try_clone().map_err(|error| error.to_string()));
    }

    pub(super) fn finish(self) -> TcpInfoEvidence {
        match self
            .0
            .into_inner()
            .unwrap_or_else(|error| error.into_inner())
        {
            Some(Ok(socket)) => {
                capture(&socket).map_or_else(unavailable, |snapshot| TcpInfoEvidence::Measured {
                    snapshot: Box::new(snapshot),
                })
            }
            Some(Err(error)) => unavailable(error),
            None => unavailable("A connected socket was unavailable for TCP information"),
        }
    }
}

#[cfg(all(feature = "isolated-tls", not(windows)))]
fn capture(_: &std::net::TcpStream) -> AppResult<TcpInfo> {
    Err("Socket TCP information requires Windows SIO_TCP_INFO support".into())
}

#[cfg(all(feature = "isolated-tls", windows))]
fn capture(socket: &std::net::TcpStream) -> AppResult<TcpInfo> {
    use std::{mem::size_of, os::windows::io::AsRawSocket, ptr::null_mut, time::Instant};
    use windows_sys::Win32::Networking::WinSock::{
        SIO_TCP_INFO, TCP_INFO_v0, WSAGetLastError, WSAIoctl,
    };
    let started = Instant::now();
    let version = 0u32;
    let mut info = TCP_INFO_v0::default();
    let mut length = 0;
    if unsafe {
        WSAIoctl(
            socket.as_raw_socket() as usize,
            SIO_TCP_INFO,
            (&version as *const u32).cast(),
            size_of::<u32>() as u32,
            (&mut info as *mut TCP_INFO_v0).cast(),
            size_of::<TCP_INFO_v0>() as u32,
            &mut length,
            null_mut(),
            None,
        )
    } != 0
    {
        return Err(
            format!("Socket TCP information unavailable: Windows {}", unsafe {
                WSAGetLastError()
            })
            .into(),
        );
    }
    if length as usize != size_of::<TCP_INFO_v0>() {
        return Err("Socket TCP information returned an unexpected ABI size".into());
    }
    let result = TcpInfo {
        schemaVersion: 1,
        source: socket.local_addr()?,
        peer: socket.peer_addr()?,
        capturedAt: chrono::Utc::now().to_rfc3339(),
        queryElapsedNs: u64::try_from(started.elapsed().as_nanos())?.to_string(),
        state: info.State,
        maximumSegmentSize: info.Mss,
        connectionTimeMs: info.ConnectionTimeMs.to_string(),
        timestampsEnabled: info.TimestampsEnabled,
        rttUs: info.RttUs,
        minimumRttUs: info.MinRttUs,
        bytesInFlight: info.BytesInFlight,
        congestionWindowBytes: info.Cwnd,
        sendWindowBytes: info.SndWnd,
        receiveWindowBytes: info.RcvWnd,
        receiveBufferBytes: info.RcvBuf,
        bytesOut: info.BytesOut.to_string(),
        bytesIn: info.BytesIn.to_string(),
        bytesReordered: info.BytesReordered,
        bytesRetransmitted: info.BytesRetrans,
        fastRetransmissions: info.FastRetrans,
        duplicateAcksIn: info.DupAcksIn,
        timeoutEpisodes: info.TimeoutEpisodes,
        synRetransmissions: info.SynRetrans,
    };
    result.validate()?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> TcpInfo {
        TcpInfo {
            schemaVersion: 1,
            source: "192.0.2.2:5000".parse().unwrap(),
            peer: "192.0.2.10:443".parse().unwrap(),
            capturedAt: "2026-11-13T12:00:01Z".into(),
            queryElapsedNs: "1000".into(),
            state: 4,
            maximumSegmentSize: 1460,
            connectionTimeMs: "1000".into(),
            timestampsEnabled: true,
            rttUs: 0,
            minimumRttUs: 0,
            bytesInFlight: 0,
            congestionWindowBytes: 65536,
            sendWindowBytes: 65536,
            receiveWindowBytes: 65536,
            receiveBufferBytes: 65536,
            bytesOut: u64::MAX.to_string(),
            bytesIn: "9007199254740993".into(),
            bytesReordered: u32::MAX,
            bytesRetransmitted: u32::MAX,
            fastRetransmissions: u32::MAX,
            duplicateAcksIn: u32::MAX,
            timeoutEpisodes: u32::MAX,
            synRetransmissions: u8::MAX,
        }
    }

    #[test]
    fn exactSocketCountersKeepTheirNativeWidthsAndOwnedFlowWindow() {
        let snapshot = fixture();
        let binding = crate::transfer::SourceBinding {
            source: snapshot.source.ip(),
            peer: snapshot.peer,
        };
        let evidence = TcpInfoEvidence::Measured {
            snapshot: Box::new(snapshot),
        };
        evidence
            .validateFor(binding, "2026-11-13T12:00:00Z", "2026-11-13T12:00:02Z")
            .unwrap();
        let restored: TcpInfoEvidence =
            serde_json::from_str(&serde_json::to_string(&evidence).unwrap()).unwrap();
        assert_eq!(evidence, restored);
        TcpInfoEvidence::Unavailable {
            reason: "unsupported socket query".into(),
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn malformedOrMismatchedSocketEvidenceCannotDescribeACompletedFlow() {
        for failure in 0..11 {
            let mut snapshot = fixture();
            let binding = crate::transfer::SourceBinding {
                source: snapshot.source.ip(),
                peer: snapshot.peer,
            };
            match failure {
                0 => snapshot.schemaVersion = 2,
                1 => snapshot.state = 11,
                2 => snapshot.source.set_port(0),
                3 => snapshot.peer.set_port(444),
                4 => snapshot.source.set_ip("192.0.2.3".parse().unwrap()),
                5 => snapshot.queryElapsedNs = "01".into(),
                6 => snapshot.bytesIn = "18446744073709551616".into(),
                7 => snapshot.capturedAt = "invalid".into(),
                8 => snapshot.capturedAt = "2026-11-13T12:00:03Z".into(),
                9 => snapshot.state = 2,
                _ => snapshot.connectionTimeMs = "-1".into(),
            }
            assert!(
                TcpInfoEvidence::Measured {
                    snapshot: Box::new(snapshot)
                }
                .validateFor(binding, "2026-11-13T12:00:00Z", "2026-11-13T12:00:02Z")
                .is_err(),
                "accepted {failure}"
            );
        }
    }
}
