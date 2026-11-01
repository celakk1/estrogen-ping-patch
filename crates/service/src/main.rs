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
        #[cfg(feature = "native-mtu-lab")]
        [mode, rest @ ..] if mode == "--native-mtu-lab-service" => {
            epp_service::mtu_lab::run(rest)
        }
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
        [mode] if mode=="--mtu-inventory" => {
            println!("{}",serde_json::to_string_pretty(&epp_service::mtu::inventory(&std::sync::atomic::AtomicBool::new(false))?)?);
            Ok(())
        }
        [mode,guid,family] if mode=="--inspect-mtu" => {
            let family=match family.as_str(){"ipv4"=>epp_service::journal::AddressFamily::Ipv4,"ipv6"=>epp_service::journal::AddressFamily::Ipv6,_=>return Err("MTU family must be ipv4 or ipv6".into())};
            println!("{}",serde_json::to_string_pretty(&epp_service::mtu::capture(guid.parse()?,family,&std::sync::atomic::AtomicBool::new(false))?)?);
            Ok(())
        }
        [mode,guid,family] if mode=="--inspect-ip-policy" => {
            let family=match family.as_str(){"ipv4"=>epp_service::journal::AddressFamily::Ipv4,"ipv6"=>epp_service::journal::AddressFamily::Ipv6,_=>return Err("IP policy family must be ipv4 or ipv6".into())};
            println!("{}",serde_json::to_string_pretty(&epp_service::mtu::policy::inspectWorker(guid.parse()?,family,&std::sync::atomic::AtomicBool::new(false))?)?);
            Ok(())
        }
        _ => Err("Expected --status, --identity, --mtu-inventory, --inspect-mtu GUID ipv4|ipv6, --inspect-ip-policy GUID ipv4|ipv6, or SCM-owned --service --owner-sid SID".into()),
    }
}

#[cfg(not(windows))]
fn execute() -> epp_service::ServiceResult<()> {
    Err("The dedicated service requires Windows".into())
}
