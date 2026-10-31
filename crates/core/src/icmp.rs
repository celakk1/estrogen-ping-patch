use crate::AppResult;
use serde::{Deserialize, Serialize};
use std::{
    net::IpAddr,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

#[cfg(windows)]
mod windows;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EchoTarget {
    pub address: IpAddr,
    #[serde(default)]
    pub scopeId: u32,
}

impl EchoTarget {
    pub fn parse(value: &str) -> AppResult<Self> {
        let (address, scopeId) = if let Some((address, scope)) = value.split_once('%') {
            let address: IpAddr = address.parse()?;
            if !address.is_ipv6() {
                return Err("Only IPv6 destinations accept an interface scope suffix".into());
            }
            (address, scope.parse()?)
        } else {
            (value.parse()?, 0)
        };
        let target = Self { address, scopeId };
        target.validate()?;
        Ok(target)
    }

    pub fn validate(&self) -> AppResult<()> {
        if self.address.is_unspecified() || self.address.is_multicast() {
            return Err("ICMP requires a specific unicast destination".into());
        }
        match self.address {
            IpAddr::V4(address) if address.is_broadcast() || self.scopeId != 0 => {
                return Err(
                    "IPv4 echo does not accept broadcast addresses or IPv6 scope IDs".into(),
                );
            }
            IpAddr::V6(address) if address.to_ipv4_mapped().is_some() => {
                return Err("Use a plain IPv4 address for an IPv4-mapped destination".into());
            }
            IpAddr::V6(address) if address.is_unicast_link_local() && self.scopeId == 0 => {
                return Err("Link-local IPv6 echo requires the target interface scope ID".into());
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum EchoStatus {
    Reply,
    TimedOut,
    IpError,
    OsError,
    InvalidReply,
    Cancelled,
    Unsupported,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EchoOutcome {
    pub status: EchoStatus,
    pub rttMs: Option<u32>,
    pub rttUnitMs: u32,
    pub callDurationMs: f64,
    pub responder: Option<IpAddr>,
    pub responderScopeId: Option<u32>,
    pub nativeCode: Option<u32>,
}

impl EchoOutcome {
    fn unavailable(status: EchoStatus) -> Self {
        Self {
            status,
            rttMs: None,
            rttUnitMs: 1,
            callDurationMs: 0.0,
            responder: None,
            responderScopeId: None,
            nativeCode: None,
        }
    }
}

#[derive(Default)]
pub struct EchoProbe {
    #[cfg(windows)]
    native: windows::WindowsProbe,
}

impl EchoProbe {
    pub fn measure(
        &mut self,
        target: &EchoTarget,
        timeout: Duration,
        cancelled: &AtomicBool,
    ) -> AppResult<EchoOutcome> {
        target.validate()?;
        if !(1..=5000).contains(&timeout.as_millis()) {
            return Err("ICMP timeout must be between 1 and 5000 milliseconds".into());
        }
        if cancelled.load(Ordering::SeqCst) {
            return Ok(EchoOutcome::unavailable(EchoStatus::Cancelled));
        }
        #[cfg(windows)]
        {
            Ok(self.native.measure(target, timeout.as_millis() as u32))
        }
        #[cfg(not(windows))]
        Ok(EchoOutcome::unavailable(EchoStatus::Unsupported))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(address: &str, scopeId: u32) -> EchoTarget {
        EchoTarget {
            address: address.parse().unwrap(),
            scopeId,
        }
    }

    #[test]
    fn onlyUnicastTargetsWithUnambiguousAddressFamiliesAreAccepted() {
        for address in [
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "::",
            "ff02::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(target(address, 0).validate().is_err(), "Accepted {address}");
        }
        assert!(target("fe80::1", 0).validate().is_err());
        assert!(target("fe80::1", 12).validate().is_ok());
        assert!(target("127.0.0.1", 12).validate().is_err());
        assert!(target("127.0.0.1", 0).validate().is_ok());
        assert!(target("::1", 0).validate().is_ok());
    }

    #[test]
    fn cancellationAndInvalidTimeoutsNeverInitializeNativeProbes() {
        let mut probe = EchoProbe::default();
        let target = target("127.0.0.1", 0);
        let cancelled = AtomicBool::new(true);
        let result = probe
            .measure(&target, Duration::from_millis(100), &cancelled)
            .unwrap();
        assert_eq!(result.status, EchoStatus::Cancelled);
        assert!(result.rttMs.is_none());
        assert!(result.nativeCode.is_none());
        assert!(probe.measure(&target, Duration::ZERO, &cancelled).is_err());
        assert!(
            probe
                .measure(&target, Duration::from_millis(5001), &cancelled)
                .is_err()
        );
        #[cfg(windows)]
        assert!(probe.native.isUninitialized());
    }

    #[cfg(windows)]
    #[test]
    fn realLoopbackEchoUsesWindowsRttAndPreservesItsReportedUnit() {
        let mut probe = EchoProbe::default();
        for address in ["127.0.0.1", "::1", "127.0.0.1", "::1"] {
            let target = target(address, 0);
            let result = probe
                .measure(&target, Duration::from_millis(500), &AtomicBool::new(false))
                .unwrap();
            assert_eq!(result.status, EchoStatus::Reply, "{address}: {result:?}");
            assert_eq!(result.responder, Some(target.address));
            assert!(result.rttMs.is_some());
            assert_eq!(result.rttUnitMs, 1);
            assert_eq!(result.nativeCode, Some(0));
            assert!(result.callDurationMs.is_finite() && result.callDurationMs >= 0.0);
            println!(
                "ICMP loopback {address}: reply with {} ms Windows RTT (whole-millisecond reporting)",
                result.rttMs.unwrap()
            );
        }
    }
}
