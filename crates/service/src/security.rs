use crate::ServiceResult;
use std::{
    ffi::c_void,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
};
use windows_sys::Win32::{
    Foundation::{HANDLE, LocalFree},
    Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER,
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            ConvertStringSidToSidW, GetSecurityInfo, SE_FILE_OBJECT,
        },
        CheckTokenMembership, DACL_SECURITY_INFORMATION, GetAce, GetSecurityDescriptorControl,
        GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, GetTokenInformation,
        LookupAccountNameW, OWNER_SECURITY_INFORMATION, RevertToSelf, SE_DACL_PROTECTED,
        SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
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
        Self::fromSddl(&sddl)
    }

    fn fromSddl(sddl: &str) -> ServiceResult<Self> {
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

pub(crate) fn serviceSid() -> ServiceResult<String> {
    serviceSidForName(crate::SERVICE_NAME)
}

pub(crate) fn serviceSidForName(serviceName: &str) -> ServiceResult<String> {
    let name: Vec<u16> = format!(r"NT SERVICE\{serviceName}")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut sid = [0u64; 32];
    let mut sidSize = size_of_val(&sid) as u32;
    let mut domain = [0u16; 256];
    let mut domainSize = domain.len() as u32;
    let mut useType = 0;
    if unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            name.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sidSize,
            domain.as_mut_ptr(),
            &mut domainSize,
            &mut useType,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let value = sidText(sid.as_mut_ptr().cast())?;
    if !value.starts_with("S-1-5-80-") {
        return Err("Windows returned an unexpected service identity".into());
    }
    Ok(value)
}

pub(crate) fn requireServiceMembership(serviceSid: &str) -> ServiceResult<()> {
    let text: Vec<u16> = serviceSid.encode_utf16().chain(Some(0)).collect();
    let mut sid = std::ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(text.as_ptr(), &mut sid) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let _allocation = LocalAllocation(sid);
    let mut member = 0;
    if unsafe { CheckTokenMembership(std::ptr::null_mut(), sid, &mut member) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if member == 0 {
        return Err(
            "The service-specific SID is absent from the process token; reinstall the service"
                .into(),
        );
    }
    Ok(())
}

pub(crate) fn verifyStorageHandle(
    handle: HANDLE,
    serviceSid: &str,
    directory: bool,
) -> ServiceResult<()> {
    let mut descriptor = std::ptr::null_mut();
    let error = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if error != 0 {
        return Err(std::io::Error::from_raw_os_error(error as i32).into());
    }
    let _allocation = LocalAllocation(descriptor);
    verifyStorageDescriptor(descriptor, serviceSid, directory)
}

fn verifyStorageDescriptor(
    descriptor: *mut c_void,
    serviceSid: &str,
    directory: bool,
) -> ServiceResult<()> {
    let mut owner = std::ptr::null_mut();
    let mut defaulted = 0;
    if unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut defaulted) } == 0
        || owner.is_null()
    {
        return Err("Recovery storage has no verifiable owner".into());
    }
    let owner = sidText(owner)?;
    let validOwner = if directory {
        owner == "S-1-5-32-544"
    } else {
        [
            "S-1-5-32-544",
            "S-1-5-18",
            crate::SERVICE_ACCOUNT_SID,
            serviceSid,
        ]
        .contains(&owner.as_str())
    };
    if !validOwner {
        return Err("Recovery storage has an unexpected owner".into());
    }
    let mut control = 0;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
        || (directory && control & SE_DACL_PROTECTED == 0)
    {
        return Err("Recovery directory must have a protected access-control list".into());
    }
    let mut present = 0;
    let mut acl = std::ptr::null_mut();
    if unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted) } == 0
        || present == 0
        || acl.is_null()
        || unsafe { (*acl).AceCount } != 4
    {
        return Err("Recovery storage must have exactly the expected access rules".into());
    }
    let mut expected = vec![
        ("S-1-5-18".to_string(), 0x1f01ff),
        ("S-1-5-32-544".to_string(), 0x1f01ff),
        (serviceSid.to_string(), 0x1301bf),
        ("S-1-3-4".to_string(), 0x20000),
    ];
    for index in 0..4 {
        let mut ace = std::ptr::null_mut();
        if unsafe { GetAce(acl, index, &mut ace) } == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        let flags = if directory { 3 } else { 16 };
        if header.AceType != 0 || header.AceFlags != flags || header.AceSize < 16 {
            return Err("Recovery storage has an unsupported access rule or inheritance".into());
        }
        let ace = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = sidText((&ace.SidStart as *const u32).cast_mut().cast())?;
        let Some(index) = expected
            .iter()
            .position(|entry| entry.0 == sid && entry.1 == ace.Mask)
        else {
            return Err("Recovery storage grants unexpected permissions".into());
        };
        expected.swap_remove(index);
    }
    Ok(())
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

    #[test]
    fn recoveryAclRequiresTheServiceSidAndBoundsSharedOwnerRights() {
        let service = "S-1-5-80-1-2-3-4-5".to_string();
        assert!(requireServiceMembership(&service).is_err());
        let directory = format!(
            "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;{service})(A;OICI;RC;;;OW)"
        );
        let descriptor = Descriptor::fromSddl(&directory).unwrap();
        verifyStorageDescriptor(descriptor.0.0, &service, true).unwrap();
        for invalid in [
            directory.replace("O:BA", "O:LS"),
            directory.replace("D:P", "D:"),
            directory.replace("RC;;;OW", "WD;;;OW"),
            directory.replace("RC;;;OW", "RC;;;LS"),
            directory.replace("0x1301bf", "FA"),
            directory.replace("OICI", "CI"),
        ] {
            let descriptor = Descriptor::fromSddl(&invalid).unwrap();
            assert!(
                verifyStorageDescriptor(descriptor.0.0, &service, true).is_err(),
                "Accepted: {invalid}"
            );
        }
        let file =
            format!("O:LSD:(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1301bf;;;{service})(A;ID;RC;;;OW)");
        let descriptor = Descriptor::fromSddl(&file).unwrap();
        verifyStorageDescriptor(descriptor.0.0, &service, false).unwrap();
        let descriptor = Descriptor::fromSddl(&file.replace("RC;;;OW", "RC;;;WD")).unwrap();
        assert!(verifyStorageDescriptor(descriptor.0.0, &service, false).is_err());
    }
}
