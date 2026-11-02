use super::{EchoOutcome, EchoStatus, EchoTarget};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Instant,
};
use windows_sys::Win32::{
    Foundation::{GetLastError, HANDLE, INVALID_HANDLE_VALUE},
    NetworkManagement::IpHelper::{
        ICMPV6_ECHO_REPLY_LH, IP_REQ_TIMED_OUT, IP_SUCCESS, Icmp6CreateFile, Icmp6SendEcho2,
        IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, IcmpSendEcho2Ex,
    },
    Networking::WinSock::{AF_INET6, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN6, SOCKADDR_IN6_0},
};

const PAYLOAD: &[u8] = b"estrogen-ping-patch-echo-v1";
const REPLY_WORDS: usize = 32;

struct EchoHandle(HANDLE);

impl Drop for EchoHandle {
    fn drop(&mut self) {
        unsafe { IcmpCloseHandle(self.0) };
    }
}

#[derive(Default)]
pub(super) struct WindowsProbe {
    ipv4: Option<EchoHandle>,
    ipv6: Option<EchoHandle>,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Ipv4ReplyPrefix {
    Address: u32,
    Status: u32,
    RoundTripTime: u32,
}

fn socketAddress(address: Ipv6Addr, scopeId: u32) -> SOCKADDR_IN6 {
    SOCKADDR_IN6 {
        sin6_family: AF_INET6,
        sin6_addr: IN6_ADDR {
            u: IN6_ADDR_0 {
                Byte: address.octets(),
            },
        },
        Anonymous: SOCKADDR_IN6_0 {
            sin6_scope_id: scopeId,
        },
        ..SOCKADDR_IN6::default()
    }
}

fn failure(code: u32, durationMs: f64) -> EchoOutcome {
    let status = if code == IP_REQ_TIMED_OUT {
        EchoStatus::TimedOut
    } else if (11000..=11099).contains(&code) {
        EchoStatus::IpError
    } else {
        EchoStatus::OsError
    };
    EchoOutcome {
        callDurationMs: durationMs,
        nativeCode: Some(code),
        ..EchoOutcome::unavailable(status)
    }
}

fn reply(
    target: &EchoTarget,
    responder: IpAddr,
    scopeId: Option<u32>,
    code: u32,
    rttMs: u32,
    durationMs: f64,
) -> EchoOutcome {
    if code != IP_SUCCESS {
        return EchoOutcome {
            responder: Some(responder),
            responderScopeId: scopeId,
            ..failure(code, durationMs)
        };
    }
    let status = if responder != target.address
        || (target.scopeId != 0 && scopeId != Some(target.scopeId))
    {
        EchoStatus::InvalidReply
    } else {
        EchoStatus::Reply
    };
    EchoOutcome {
        rttMs: if status == EchoStatus::Reply {
            Some(rttMs)
        } else {
            None
        },
        callDurationMs: durationMs,
        responder: Some(responder),
        responderScopeId: scopeId,
        nativeCode: Some(code),
        ..EchoOutcome::unavailable(status)
    }
}

impl WindowsProbe {
    #[cfg(test)]
    pub(super) fn isUninitialized(&self) -> bool {
        self.ipv4.is_none() && self.ipv6.is_none()
    }

    pub(super) fn measure(
        &mut self,
        source: Option<&EchoTarget>,
        target: &EchoTarget,
        timeoutMs: u32,
    ) -> EchoOutcome {
        let start = Instant::now();
        let slot = match target.address {
            IpAddr::V4(_) => &mut self.ipv4,
            IpAddr::V6(_) => &mut self.ipv6,
        };
        if slot.is_none() {
            let handle = unsafe {
                match target.address {
                    IpAddr::V4(_) => IcmpCreateFile(),
                    IpAddr::V6(_) => Icmp6CreateFile(),
                }
            };
            if handle == INVALID_HANDLE_VALUE || handle.is_null() {
                let code = unsafe { GetLastError() };
                return failure(code, start.elapsed().as_secs_f64() * 1000.0);
            }
            *slot = Some(EchoHandle(handle));
        }
        let handle = slot.as_ref().expect("initialized echo handle").0;
        let mut buffer = [0u64; REPLY_WORDS];
        let (count, lastError) = unsafe {
            let count = match target.address {
                IpAddr::V4(address) if source.is_some() => IcmpSendEcho2Ex(
                    handle,
                    std::ptr::null_mut(),
                    None,
                    std::ptr::null(),
                    match source.expect("validated source").address {
                        IpAddr::V4(address) => u32::from_ne_bytes(address.octets()),
                        _ => unreachable!("validated source family"),
                    },
                    u32::from_ne_bytes(address.octets()),
                    PAYLOAD.as_ptr().cast(),
                    PAYLOAD.len() as u16,
                    std::ptr::null(),
                    buffer.as_mut_ptr().cast(),
                    size_of_val(&buffer) as u32,
                    timeoutMs,
                ),
                IpAddr::V4(address) => IcmpSendEcho(
                    handle,
                    u32::from_ne_bytes(address.octets()),
                    PAYLOAD.as_ptr().cast(),
                    PAYLOAD.len() as u16,
                    std::ptr::null(),
                    buffer.as_mut_ptr().cast(),
                    size_of_val(&buffer) as u32,
                    timeoutMs,
                ),
                IpAddr::V6(address) => Icmp6SendEcho2(
                    handle,
                    std::ptr::null_mut(),
                    None,
                    std::ptr::null(),
                    &socketAddress(
                        source.map_or(Ipv6Addr::UNSPECIFIED, |source| match source.address {
                            IpAddr::V6(address) => address,
                            _ => unreachable!("validated source family"),
                        }),
                        source.map_or(target.scopeId, |source| source.scopeId),
                    ),
                    &socketAddress(address, target.scopeId),
                    PAYLOAD.as_ptr().cast(),
                    PAYLOAD.len() as u16,
                    std::ptr::null(),
                    buffer.as_mut_ptr().cast(),
                    size_of_val(&buffer) as u32,
                    timeoutMs,
                ),
            };
            (count, if count == 0 { GetLastError() } else { 0 })
        };
        let durationMs = start.elapsed().as_secs_f64() * 1000.0;
        if count == 0 {
            return failure(lastError, durationMs);
        }
        match target.address {
            IpAddr::V4(_) => {
                // the scalar prefix is common to native and x64 parsed replies; no returned data pointer is dereferenced.
                let result = unsafe { std::ptr::read(buffer.as_ptr().cast::<Ipv4ReplyPrefix>()) };
                reply(
                    target,
                    Ipv4Addr::from(result.Address.to_ne_bytes()).into(),
                    None,
                    result.Status,
                    result.RoundTripTime,
                    durationMs,
                )
            }
            IpAddr::V6(_) => {
                let result =
                    unsafe { std::ptr::read(buffer.as_ptr().cast::<ICMPV6_ECHO_REPLY_LH>()) };
                let words = result.Address.sin6_addr;
                let address = Ipv6Addr::from(std::array::from_fn::<_, 16, _>(|index| {
                    words[index / 2].to_ne_bytes()[index % 2]
                }));
                reply(
                    target,
                    address.into(),
                    Some(result.Address.sin6_scope_id),
                    result.Status,
                    result.RoundTripTime,
                    durationMs,
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::{
        NetworkManagement::IpHelper::ICMP_ECHO_REPLY, System::IO::IO_STATUS_BLOCK,
    };

    #[test]
    fn buffersIncludeErrorPayloadAndIpv6IoStatusSpace() {
        let size = REPLY_WORDS * size_of::<u64>();
        assert!(
            size >= size_of::<ICMP_ECHO_REPLY>() + PAYLOAD.len() + 8 + size_of::<IO_STATUS_BLOCK>()
        );
        assert!(
            size >= size_of::<ICMPV6_ECHO_REPLY_LH>()
                + PAYLOAD.len()
                + 8
                + size_of::<IO_STATUS_BLOCK>()
        );
    }

    #[test]
    fn missingRepliesAndLocalErrorsNeverBecomeZeroRttOrSuccess() {
        for (code, expected) in [
            (11010, EchoStatus::TimedOut),
            (11003, EchoStatus::IpError),
            (11008, EchoStatus::IpError),
            (5, EchoStatus::OsError),
            (50, EchoStatus::OsError),
            (0, EchoStatus::OsError),
        ] {
            let outcome = failure(code, 25.0);
            assert_eq!(outcome.status, expected);
            assert!(outcome.rttMs.is_none());
            assert_eq!(outcome.nativeCode, Some(code));
            assert_eq!(outcome.callDurationMs, 25.0);
        }
    }

    #[test]
    fn onlyMatchingSuccessfulRepliesSupplyRtt() {
        let target = EchoTarget {
            address: "127.0.0.1".parse().unwrap(),
            scopeId: 0,
        };
        let valid = reply(&target, target.address, None, 0, 0, 1.5);
        assert_eq!(valid.rttMs, Some(0));
        assert_eq!(valid.rttUnitMs, 1);
        let wrong = reply(&target, "127.0.0.2".parse().unwrap(), None, 0, 1, 2.0);
        assert_eq!(wrong.status, EchoStatus::InvalidReply);
        assert!(wrong.rttMs.is_none());
        let ttl = reply(&target, target.address, None, 11013, 1, 2.0);
        assert_eq!(ttl.status, EchoStatus::IpError);
        assert!(ttl.rttMs.is_none());
        let scoped = EchoTarget {
            address: "fe80::1".parse().unwrap(),
            scopeId: 12,
        };
        assert_eq!(
            reply(&scoped, scoped.address, Some(13), 0, 1, 2.0).status,
            EchoStatus::InvalidReply
        );
    }
}
