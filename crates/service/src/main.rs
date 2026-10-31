#![allow(non_snake_case)]

fn main() {
    if let Err(error) = execute() {
        eprintln!(
            "Dedicated service error: {error}. Use install-service.bat or Windows Services to manage this component; the desktop launcher does not require elevation."
        );
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn execute() -> epp_service::ServiceResult<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.as_slice() {
        [mode, ownerFlag, ownerSid] if mode == "--service" && ownerFlag == "--owner-sid" => {
            epp_service::windows::run(ownerSid.clone())
        }
        [mode] if mode == "--identity" => {
            println!("{}", epp_service::windows::identity()?);
            Ok(())
        }
        [mode] if mode == "--status" => {
            println!(
                "{}",
                serde_json::to_string_pretty(&epp_service::windows::inspectBlocking()?)?
            );
            Ok(())
        }
        _ => Err("Expected --status, --identity, or SCM-owned --service --owner-sid SID".into()),
    }
}

#[cfg(not(windows))]
fn execute() -> epp_service::ServiceResult<()> {
    Err("The dedicated service requires Windows".into())
}
