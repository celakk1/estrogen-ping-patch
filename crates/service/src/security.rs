use crate::ServiceResult;
use std::{
    ffi::c_void,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
};
use windows_sys::Win32::{
    Foundation::{HANDLE, LocalFree},
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            ConvertStringSidToSidW,
        },
        GetTokenInformation, RevertToSelf, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
    },
    System::{
        Pipes::ImpersonateNamedPipeClient,
        Threading::{GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken},
    },
};

struct LocalAllocation(*mut c_void);

pub(crate) const CLIENT_ACCESS: u32 = 0x00100083;

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

pub(crate) struct Descriptor(LocalAllocation);

impl Descriptor {
    pub(crate) fn pipe(ownerSid: &str, serverSid: &str) -> ServiceResult<Self> {
        let ownerSid = canonicalSid(ownerSid)?;
        let serverSid = canonicalSid(serverSid)?;
        // client opens also require read-attributes; generic write would grant create-pipe-instance.
        let sddl =
            format!("D:P(A;;GA;;;SY)(A;;GA;;;{serverSid})(A;;0x{CLIENT_ACCESS:08x};;;{ownerSid})");
        let text: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut descriptor = std::ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self(LocalAllocation(descriptor)))
    }

    pub(crate) fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0.0,
            bInheritHandle: 0,
        }
    }
}

fn sidText(sid: *mut c_void) -> ServiceResult<String> {
    let mut text = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let allocation = LocalAllocation(text.cast());
    for length in 0..256 {
        if unsafe { *text.add(length) } == 0 {
            let value = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })?;
            drop(allocation);
            return Ok(value);
        }
    }
    Err("Windows SID text exceeded its safe bound".into())
}

pub(crate) fn canonicalSid(value: &str) -> ServiceResult<String> {
    if value.len() > 184
        || !value.starts_with("S-1-")
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && byte != b'-' && byte != b'S')
    {
        return Err("Invalid authorized Windows SID".into());
    }
    let text: Vec<u16> = value.encode_utf16().chain(Some(0)).collect();
    let mut sid = std::ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(text.as_ptr(), &mut sid) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let allocation = LocalAllocation(sid);
    let result = sidText(sid);
    drop(allocation);
    result
}

fn tokenSid(token: HANDLE) -> ServiceResult<String> {
    let mut byteCount = 0;
    unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut byteCount) };
    if byteCount == 0 || byteCount > 65_536 {
        return Err("Windows returned an invalid token information length".into());
    }
    let mut buffer = vec![0u64; (byteCount as usize).div_ceil(8)];
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            byteCount,
            &mut byteCount,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    sidText(user.User.Sid)
}

pub(crate) fn currentSid() -> ServiceResult<String> {
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    tokenSid(token.as_raw_handle())
}

struct Impersonation;

impl Drop for Impersonation {
    fn drop(&mut self) {
        // continuing under a client token after failed reversion is unsafe.
        if unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
    }
}

pub(crate) fn authenticateClient(pipe: HANDLE, ownerSid: &str) -> ServiceResult<()> {
    if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
        return Err("Windows could not authenticate the pipe client".into());
    }
    let _impersonation = Impersonation;
    let mut token = std::ptr::null_mut();
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    if tokenSid(token.as_raw_handle())? != ownerSid {
        return Err("Pipe client is not the authorized Windows user".into());
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn assertNoThreadImpersonation() {
    let mut token = std::ptr::null_mut();
    assert_eq!(
        unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) },
        0
    );
    assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(1008));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sidValidationPreventsSecurityDescriptorInjection() {
        assert_eq!(canonicalSid("S-1-5-19").unwrap(), "S-1-5-19");
        for value in [
            "WD",
            "S-1-5-19)(A;;GA;;;WD)",
            "S-1-5-19\0",
            "S-2-5-19",
            "S-1-5-not-a-sid",
        ] {
            assert!(
                canonicalSid(value).is_err(),
                "Unexpected accepted SID: {value}"
            );
        }
        assert!(currentSid().unwrap().starts_with("S-1-"));
    }

    #[test]
    fn explicitAclDoesNotGiveTheAuthorizedUserPipeCreationRights() {
        use windows_sys::Win32::Security::{ACCESS_ALLOWED_ACE, GetAce, GetSecurityDescriptorDacl};
        let owner = currentSid().unwrap();
        let descriptor = Descriptor::pipe(&owner, "S-1-5-19").unwrap();
        let mut present = 0;
        let mut defaulted = 1;
        let mut acl = std::ptr::null_mut();
        assert_ne!(
            unsafe {
                GetSecurityDescriptorDacl(descriptor.0.0, &mut present, &mut acl, &mut defaulted)
            },
            0
        );
        assert_eq!(present, 1);
        assert_eq!(defaulted, 0);
        assert!(!acl.is_null());
        assert_eq!(unsafe { (*acl).AceCount }, 3);
        let mut ace = std::ptr::null_mut();
        assert_ne!(unsafe { GetAce(acl, 2, &mut ace) }, 0);
        let ace = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        assert_eq!(ace.Header.AceType, 0);
        assert_eq!(ace.Mask, CLIENT_ACCESS);
        assert_eq!(ace.Mask & 4, 0);
        assert_eq!(
            sidText((&ace.SidStart as *const u32).cast_mut().cast()).unwrap(),
            owner
        );
    }
}
