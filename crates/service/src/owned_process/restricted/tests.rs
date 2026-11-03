use super::*;

use std::{os::windows::process::CommandExt, path::PathBuf, process::Command};
use windows_sys::Win32::{
    Foundation::{ERROR_ACCESS_DENIED, ERROR_NOT_ENOUGH_QUOTA},
    Security::{DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, SetFileSecurityW},
    Storage::FileSystem::WRITE_DAC,
    System::Threading::{
        CreateEventW, EVENT_MODIFY_STATE, OpenEventW, OpenProcess, PROCESS_DUP_HANDLE,
        PROCESS_SYNCHRONIZE, PROCESS_VM_READ, PROCESS_VM_WRITE,
    },
};

const CHILD: &str = "owned_process::restricted::tests::childFixture";
const WRAPPER: &str = "owned_process::restricted::tests::wrapperFixture";

struct Fixture(PathBuf);

impl Fixture {
    fn new(owner: &str) -> Self {
        let directory =
            std::env::temp_dir().join(format!("epp-restricted-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let image = directory.join("epp-restricted-fixture.exe");
        std::fs::copy(std::env::current_exe().unwrap(), &image).unwrap();
        let descriptor = crate::security::Descriptor::testObject(&format!(
            "D:P(A;;FA;;;{owner})(A;;FRFX;;;AU)(A;;RC;;;OW)"
        ))
        .unwrap();
        let path: Vec<_> = directory.as_os_str().encode_wide().chain(Some(0)).collect();
        succeeded("Protect restricted fixture directory", unsafe {
            SetFileSecurityW(
                path.as_ptr(),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor.attributes().lpSecurityDescriptor,
            )
        })
        .unwrap();
        let path: Vec<_> = image.as_os_str().encode_wide().chain(Some(0)).collect();
        succeeded("Protect restricted fixture image", unsafe {
            SetFileSecurityW(
                path.as_ptr(),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor.attributes().lpSecurityDescriptor,
            )
        })
        .unwrap();
        Self(image)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.0.parent().unwrap().join("worker-private.txt"));
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_dir(self.0.parent().unwrap());
    }
}

fn arguments(filter: &str) -> Vec<String> {
    [
        "--ignored",
        "--exact",
        filter,
        "--nocapture",
        "--test-threads=1",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn eventName(context: &str) -> Vec<u16> {
    format!("Local\\epp-worker-private-{context}")
        .encode_utf16()
        .chain(Some(0))
        .collect()
}

#[test]
fn restrictedIdentityRequiresRemovedPrivilegesAndLowIntegrity() {
    assert!(validateCurrent().is_err());
    let token = create().unwrap();
    validate(token.as_raw_handle()).unwrap();
}

#[test]
fn restrictedChildDeniesProtectedAccessAndInheritedEnvironment() {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(arguments(WRAPPER))
        .env("EPP_RESTRICTED_SENTINEL", "parent-only")
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("restricted-child-verified"));
}

#[test]
#[ignore]
fn wrapperFixture() {
    assert_eq!(
        std::env::var("EPP_RESTRICTED_SENTINEL").unwrap(),
        "parent-only"
    );
    let owner = crate::security::currentSid().unwrap();
    let fixture = Fixture::new(&owner);
    let privateFile = fixture.0.parent().unwrap().join("worker-private.txt");
    std::fs::write(&privateFile, b"private fixture data").unwrap();
    let descriptor =
        crate::security::Descriptor::testObject(&format!("D:P(A;;FA;;;{owner})(A;;RC;;;OW)"))
            .unwrap();
    let path: Vec<_> = privateFile
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    succeeded("Protect private worker fixture", unsafe {
        SetFileSecurityW(
            path.as_ptr(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor.attributes().lpSecurityDescriptor,
        )
    })
    .unwrap();
    let payload = serde_json::to_vec(
        &serde_json::json!({"marker":"immutable-request", "privateFile":privateFile}),
    )
    .unwrap();
    let input = request::Input::new(&payload).unwrap();
    let context = format!("{}-{}", std::process::id(), uuid::Uuid::new_v4());
    let name = eventName(&context);
    let descriptor =
        crate::security::Descriptor::testObject(&format!("D:P(A;;GA;;;{owner})(A;;RC;;;OW)"))
            .unwrap();
    let event = unsafe { CreateEventW(&descriptor.attributes(), 1, 0, name.as_ptr()) };
    assert!(!event.is_null(), "{}", std::io::Error::last_os_error());
    let _event = unsafe { OwnedHandle::from_raw_handle(event) };
    let opened = unsafe { OpenEventW(PROCESS_SYNCHRONIZE, 0, name.as_ptr()) };
    assert!(
        !opened.is_null(),
        "parent must be allowed to open its fixture"
    );
    drop(unsafe { OwnedHandle::from_raw_handle(opened) });
    let mut args = arguments(CHILD);
    args.push(format!("identity-fixture={context}"));
    args.push(format!("input-length={}", input.length));
    let job = CommandJob::spawnRestrictedReader(&fixture.0, &args, Some(&input.handle)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let output = job
        .collect(65536, || {
            if Instant::now() >= deadline {
                Err("Restricted fixture deadline expired".into())
            } else {
                Ok(())
            }
        })
        .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("restricted-child-verified"), "{output}");
    println!("restricted-child-verified");
}

#[test]
#[ignore]
fn childFixture() {
    validateCurrent().unwrap();
    assert!(std::env::var_os("EPP_RESTRICTED_SENTINEL").is_none());
    for (key, _) in std::env::vars_os() {
        assert!(
            key.eq_ignore_ascii_case("SystemRoot") || key.eq_ignore_ascii_case("WINDIR"),
            "unexpected inherited environment key: {key:?}"
        );
    }
    let (_, directory) = workerParameters().unwrap();
    assert_eq!(
        std::env::current_dir().unwrap(),
        PathBuf::from(String::from_utf16(&directory[..directory.len() - 1]).unwrap())
    );
    let context = std::env::args()
        .find_map(|arg| arg.strip_prefix("identity-fixture=").map(str::to_owned))
        .unwrap();
    let length = std::env::args()
        .find_map(|arg| arg.strip_prefix("input-length=").map(str::to_owned))
        .unwrap();
    let bytes = request::read(&length).unwrap();
    let input: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(input["marker"], "immutable-request");
    let privateFile = input["privateFile"].as_str().unwrap();
    assert_eq!(
        std::fs::read(privateFile).unwrap_err().raw_os_error(),
        Some(ERROR_ACCESS_DENIED as i32)
    );
    assert_eq!(
        std::fs::OpenOptions::new()
            .write(true)
            .open(privateFile)
            .unwrap_err()
            .raw_os_error(),
        Some(ERROR_ACCESS_DENIED as i32)
    );
    let name = eventName(&context);
    for rights in [PROCESS_SYNCHRONIZE, EVENT_MODIFY_STATE, WRITE_DAC] {
        let opened = unsafe { OpenEventW(rights, 0, name.as_ptr()) };
        let error = std::io::Error::last_os_error();
        assert!(
            opened.is_null(),
            "restricted worker reopened a protected event with {rights}"
        );
        assert_eq!(error.raw_os_error(), Some(ERROR_ACCESS_DENIED as i32));
    }
    let parent: u32 = context.split('-').next().unwrap().parse().unwrap();
    for rights in [PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_DUP_HANDLE] {
        let opened = unsafe { OpenProcess(rights, 0, parent) };
        let error = std::io::Error::last_os_error();
        assert!(
            opened.is_null(),
            "restricted worker opened its parent with {rights}"
        );
        assert_eq!(error.raw_os_error(), Some(ERROR_ACCESS_DENIED as i32));
    }
    let child = Command::new(std::env::current_exe().unwrap())
        .arg("--list")
        .creation_flags(CREATE_NO_WINDOW)
        .spawn();
    assert_eq!(
        child.unwrap_err().raw_os_error(),
        Some(ERROR_NOT_ENOUGH_QUOTA as i32)
    );
    let mut memory = Vec::<u8>::new();
    assert!(
        memory.try_reserve_exact(300 * 1024 * 1024).is_err(),
        "restricted worker exceeded its memory ceiling"
    );
    println!("restricted-child-verified");
}
