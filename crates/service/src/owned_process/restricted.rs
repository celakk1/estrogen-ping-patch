use super::*;
use windows_sys::Win32::{
    Foundation::{HANDLE, LUID, LocalFree},
    Security::{
        Authorization::ConvertStringSidToSidW, CreateRestrictedToken, DISABLE_MAX_PRIVILEGE,
        GetLengthSid, GetTokenInformation, IsTokenRestricted, LUID_AND_ATTRIBUTES,
        LookupPrivilegeValueW, SID_AND_ATTRIBUTES, SetTokenInformation, TOKEN_ADJUST_DEFAULT,
        TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS,
        TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER, TokenGroups,
        TokenIntegrityLevel, TokenPrivileges, TokenRestrictedSids, TokenUser,
    },
    System::{
        SystemServices::{SE_GROUP_INTEGRITY, SE_GROUP_USE_FOR_DENY_ONLY},
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

struct Sid(*mut c_void);

impl Sid {
    fn new(text: &str) -> ServiceResult<Self> {
        let text: Vec<_> = text.encode_utf16().chain(Some(0)).collect();
        let mut sid = null_mut();
        succeeded("Convert benchmark identity SID", unsafe {
            ConvertStringSidToSidW(text.as_ptr(), &mut sid)
        })?;
        Ok(Self(sid))
    }
}

impl Drop for Sid {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

struct Information {
    words: Vec<u64>,
    bytes: usize,
}

impl Information {
    fn query(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> ServiceResult<Self> {
        let mut bytes = 0;
        unsafe { GetTokenInformation(token, class, null_mut(), 0, &mut bytes) };
        if bytes == 0 || bytes > 65_536 {
            return Err("Benchmark token information exceeded its fixed size".into());
        }
        let mut words = vec![0; (bytes as usize).div_ceil(8)];
        succeeded("Read benchmark token information", unsafe {
            GetTokenInformation(token, class, words.as_mut_ptr().cast(), bytes, &mut bytes)
        })?;
        if bytes as usize > std::mem::size_of_val(words.as_slice()) {
            return Err("Benchmark token information length changed".into());
        }
        Ok(Self {
            words,
            bytes: bytes as usize,
        })
    }

    fn header<T>(&self) -> ServiceResult<&T> {
        if self.bytes < size_of::<T>() {
            return Err("Benchmark token information is truncated".into());
        }
        Ok(unsafe { &*self.words.as_ptr().cast::<T>() })
    }

    fn groups(&self) -> ServiceResult<&[SID_AND_ATTRIBUTES]> {
        let count = self.header::<TOKEN_GROUPS>()?.GroupCount as usize;
        let offset = std::mem::offset_of!(TOKEN_GROUPS, Groups);
        if count > 256 || offset + count * size_of::<SID_AND_ATTRIBUTES>() > self.bytes {
            return Err("Benchmark token group list is invalid".into());
        }
        Ok(unsafe {
            std::slice::from_raw_parts(self.words.as_ptr().cast::<u8>().add(offset).cast(), count)
        })
    }
}

fn primaryToken(access: u32) -> ServiceResult<OwnedHandle> {
    let mut token = null_mut();
    succeeded("Open benchmark parent token", unsafe {
        OpenProcessToken(GetCurrentProcess(), access, &mut token)
    })?;
    Ok(unsafe { OwnedHandle::from_raw_handle(token) })
}

fn logonIdentity(token: HANDLE) -> ServiceResult<String> {
    let information = Information::query(token, TokenGroups)?;
    let identities = information
        .groups()?
        .iter()
        .filter(|group| group.Attributes & 0xc0000000 == 0xc0000000)
        .collect::<Vec<_>>();
    if identities.len() != 1 {
        return Err("Benchmark token requires exactly one logon identity".into());
    }
    crate::security::sidText(identities[0].Sid)
}

pub(super) fn create() -> ServiceResult<OwnedHandle> {
    let original =
        primaryToken(TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY)?;
    let administrator = Sid::new("S-1-5-32-544")?;
    let system = Sid::new("S-1-5-18")?;
    let authenticated = Sid::new("S-1-5-11")?;
    let users = Sid::new("S-1-5-32-545")?;
    let everyone = Sid::new("S-1-1-0")?;
    let logon = Sid::new(&logonIdentity(original.as_raw_handle())?)?;
    let disabled = [
        SID_AND_ATTRIBUTES {
            Sid: administrator.0,
            Attributes: 0,
        },
        SID_AND_ATTRIBUTES {
            Sid: system.0,
            Attributes: 0,
        },
    ];
    let restricted = [
        SID_AND_ATTRIBUTES {
            Sid: logon.0,
            Attributes: 0,
        },
        SID_AND_ATTRIBUTES {
            Sid: everyone.0,
            Attributes: 0,
        },
        SID_AND_ATTRIBUTES {
            Sid: authenticated.0,
            Attributes: 0,
        },
        SID_AND_ATTRIBUTES {
            Sid: users.0,
            Attributes: 0,
        },
    ];
    let mut token = null_mut();
    succeeded("Create restricted benchmark token", unsafe {
        CreateRestrictedToken(
            original.as_raw_handle(),
            DISABLE_MAX_PRIVILEGE,
            disabled.len() as u32,
            disabled.as_ptr(),
            0,
            null(),
            restricted.len() as u32,
            restricted.as_ptr(),
            &mut token,
        )
    })?;
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let low = Sid::new("S-1-16-4096")?;
    let sidBytes = unsafe { GetLengthSid(low.0) } as usize;
    let length = size_of::<TOKEN_MANDATORY_LABEL>() + sidBytes;
    let mut label = vec![0u64; length.div_ceil(8)];
    let labelAddress = label.as_mut_ptr().cast::<u8>();
    let sidAddress = unsafe { labelAddress.add(size_of::<TOKEN_MANDATORY_LABEL>()) };
    unsafe {
        std::ptr::copy_nonoverlapping(low.0.cast::<u8>(), sidAddress, sidBytes);
        *label.as_mut_ptr().cast::<TOKEN_MANDATORY_LABEL>() = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: sidAddress.cast(),
                Attributes: SE_GROUP_INTEGRITY as u32,
            },
        };
    }
    succeeded("Lower benchmark token integrity", unsafe {
        SetTokenInformation(
            token.as_raw_handle(),
            TokenIntegrityLevel,
            label.as_ptr().cast(),
            length as u32,
        )
    })?;
    validate(token.as_raw_handle())?;
    Ok(token)
}

fn validate(token: HANDLE) -> ServiceResult<()> {
    if unsafe { IsTokenRestricted(token) } == 0 {
        return Err("Benchmark worker requires a restricted token".into());
    }
    let restricted = Information::query(token, TokenRestrictedSids)?;
    let groups = restricted.groups()?;
    let mut identities = groups
        .iter()
        .map(|group| crate::security::sidText(group.Sid))
        .collect::<ServiceResult<Vec<_>>>()?;
    identities.sort();
    let mut expected = vec![
        "S-1-1-0".to_owned(),
        "S-1-5-11".to_owned(),
        "S-1-5-32-545".to_owned(),
        logonIdentity(token)?,
    ];
    expected.sort();
    if identities != expected {
        return Err("Benchmark token has an unexpected restricting identity".into());
    }
    let groupInformation = Information::query(token, TokenGroups)?;
    for group in groupInformation.groups()? {
        if crate::security::sidText(group.Sid)? == "S-1-5-32-544"
            && group.Attributes & SE_GROUP_USE_FOR_DENY_ONLY as u32 == 0
        {
            return Err("Benchmark token still permits administrative group access".into());
        }
    }
    let user = Information::query(token, TokenUser)?;
    let user = user.header::<TOKEN_USER>()?;
    if crate::security::sidText(user.User.Sid)? == "S-1-5-18"
        && user.User.Attributes & SE_GROUP_USE_FOR_DENY_ONLY as u32 == 0
    {
        return Err("Benchmark token still permits System identity access".into());
    }
    let integrity = Information::query(token, TokenIntegrityLevel)?;
    if crate::security::sidText(integrity.header::<TOKEN_MANDATORY_LABEL>()?.Label.Sid)?
        != "S-1-16-4096"
    {
        return Err("Benchmark worker requires low integrity".into());
    }
    let mut changeNotify = LUID::default();
    succeeded("Resolve permitted benchmark privilege", unsafe {
        LookupPrivilegeValueW(
            null(),
            windows_sys::core::w!("SeChangeNotifyPrivilege"),
            &mut changeNotify,
        )
    })?;
    let privileges = Information::query(token, TokenPrivileges)?;
    let count = *privileges.header::<u32>()? as usize;
    let offset = std::mem::offset_of!(TOKEN_PRIVILEGES, Privileges);
    if count > 1 || offset + count * size_of::<LUID_AND_ATTRIBUTES>() > privileges.bytes {
        return Err("Benchmark token retains unexpected privileges".into());
    }
    for privilege in unsafe {
        std::slice::from_raw_parts(
            privileges
                .words
                .as_ptr()
                .cast::<u8>()
                .add(offset)
                .cast::<LUID_AND_ATTRIBUTES>(),
            count,
        )
    } {
        if privilege.Luid.LowPart != changeNotify.LowPart
            || privilege.Luid.HighPart != changeNotify.HighPart
        {
            return Err("Benchmark token retains an unexpected privilege".into());
        }
    }
    Ok(())
}

pub(super) fn validateCurrent() -> ServiceResult<()> {
    let token = primaryToken(TOKEN_QUERY)?;
    validate(token.as_raw_handle())
}

#[cfg(test)]
mod tests;
