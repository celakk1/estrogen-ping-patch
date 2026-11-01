use super::*;
use windows_sys::Win32::{
    Foundation::{GetLastError, HANDLE, INVALID_HANDLE_VALUE},
    NetworkManagement::IpHelper::{
        ICMP_ECHO_REPLY, IP_FLAG_DF, IP_OPTION_INFORMATION, IcmpCloseHandle, IcmpCreateFile,
        IcmpSendEcho2Ex,
    },
    System::IO::IO_STATUS_BLOCK,
};

const HEADER_BYTES: u32 = 28;
const BUFFER_WORDS: usize = (MAX_PACKET_BYTES as usize + 512).div_ceil(8);

#[derive(Default)]
pub(super) struct WindowsProbe {
    handle: Option<Handle>,
}
struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { IcmpCloseHandle(self.0) };
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ReplyPrefix {
    address: u32,
    status: u32,
    rttMs: u32,
    dataSize: u16,
    reserved: u16,
}

fn decode(
    plan: &Plan,
    payloadBytes: u16,
    count: u32,
    error: u32,
    prefix: ReplyPrefix,
    duration: f64,
) -> EchoOutcome {
    let code = if count == 0 { error } else { prefix.status };
    let responder = if count == 0 {
        None
    } else {
        Some(Ipv4Addr::from(prefix.address.to_ne_bytes()).into())
    };
    let status = if count > 1 {
        EchoStatus::InvalidReply
    } else if count == 1 && code == 0 {
        if responder == Some(plan.destination.into()) && prefix.dataSize == payloadBytes {
            EchoStatus::Reply
        } else {
            EchoStatus::InvalidReply
        }
    } else if code == 11010 {
        EchoStatus::TimedOut
    } else if (11000..=11099).contains(&code) {
        EchoStatus::IpError
    } else {
        EchoStatus::OsError
    };
    EchoOutcome {
        rttMs: (status == EchoStatus::Reply).then_some(prefix.rttMs),
        nativeCode: Some(code),
        responder,
        callDurationMs: duration,
        ..EchoOutcome::unavailable(status)
    }
}

impl WindowsProbe {
    pub(super) fn measure(&mut self, plan: &Plan, packetBytes: u32, timeoutMs: u32) -> EchoOutcome {
        let start = Instant::now();
        if self.handle.is_none() {
            let handle = unsafe { IcmpCreateFile() };
            if handle == INVALID_HANDLE_VALUE || handle.is_null() {
                return EchoOutcome {
                    nativeCode: Some(unsafe { GetLastError() }),
                    ..EchoOutcome::unavailable(EchoStatus::OsError)
                };
            }
            self.handle = Some(Handle(handle));
        }
        let payload = [0x65u8; MAX_PACKET_BYTES as usize - HEADER_BYTES as usize];
        let payloadBytes = (packetBytes - HEADER_BYTES) as u16;
        let mut replies = [0u64; BUFFER_WORDS];
        let replyBytes = (size_of::<ICMP_ECHO_REPLY>()
            + usize::from(payloadBytes)
            + 8
            + size_of::<IO_STATUS_BLOCK>())
        .div_ceil(8)
            * 8;
        let options = IP_OPTION_INFORMATION {
            Ttl: 64,
            Flags: IP_FLAG_DF as u8,
            ..Default::default()
        };
        let count = unsafe {
            IcmpSendEcho2Ex(
                self.handle
                    .as_ref()
                    .expect("initialized packet-size handle")
                    .0,
                std::ptr::null_mut(),
                None,
                std::ptr::null(),
                u32::from_ne_bytes(plan.source.octets()),
                u32::from_ne_bytes(plan.destination.octets()),
                payload.as_ptr().cast(),
                payloadBytes,
                &options,
                replies.as_mut_ptr().cast(),
                replyBytes as u32,
                timeoutMs,
            )
        };
        let error = if count == 0 {
            unsafe { GetLastError() }
        } else {
            0
        };
        // only scalar fields shared by native and parsed x64 layouts are read.
        let prefix = unsafe { std::ptr::read(replies.as_ptr().cast::<ReplyPrefix>()) };
        decode(
            plan,
            payloadBytes,
            count,
            error,
            prefix,
            start.elapsed().as_secs_f64() * 1000.0,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nativeReplyRequiresTheRequestedPayloadAndMatchingPeer() {
        let plan = super::super::tests::plan();
        for (address, bytes, expected) in [
            (plan.destination, 56, EchoStatus::Reply),
            (plan.destination, 55, EchoStatus::InvalidReply),
            (Ipv4Addr::new(127, 0, 0, 2), 56, EchoStatus::InvalidReply),
        ] {
            let result = decode(
                &plan,
                56,
                1,
                0,
                ReplyPrefix {
                    address: u32::from_ne_bytes(address.octets()),
                    status: 0,
                    rttMs: 0,
                    dataSize: bytes,
                    reserved: 0,
                },
                1.0,
            );
            assert_eq!(result.status, expected);
            assert_eq!(result.rttMs.is_some(), expected == EchoStatus::Reply);
        }
    }
}
