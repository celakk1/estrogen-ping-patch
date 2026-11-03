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
        #[cfg(feature = "automatic-trials")]
        [mode, length] if mode == "--transfer-worker" => epp_service::transfer_worker::run(length),
        #[cfg(feature = "native-mtu-lab")]
        [mode, rest @ ..] if mode == "--native-mtu-lab-service" => {
            epp_service::mtu_lab::run(rest)
        }
        [mode, ownerFlag, ownerSid] if mode == "--service" && ownerFlag == "--owner-sid" => {
            epp_service::windows::run(ownerSid.clone())
        }
        #[cfg(feature = "native-recovery")]
        [mode, ownerFlag, ownerSid] if mode == "--recovery-service" && ownerFlag == "--owner-sid" => {
            epp_service::windows::runRecovery(ownerSid.clone())
        }
        [mode] if mode == "--identity" => {
            println!("{}", epp_service::windows::identity()?);
            Ok(())
        }
        [mode] if mode == "--capabilities" => {
            println!("{}", serde_json::json!({"nativeRecoveryAvailable": cfg!(feature = "native-recovery")}));
            Ok(())
        }
        [mode] if mode == "--status" => {
            println!(
                "{}",
                serde_json::to_string_pretty(&epp_service::windows::inspectBlocking()?)?
            );
            Ok(())
        }
        [mode, guid, family, mtu, duration] if mode == "--preview-mtu" => {
            let addressFamily = match family.as_str() { "ipv4" => epp_service::journal::AddressFamily::Ipv4, "ipv6" => epp_service::journal::AddressFamily::Ipv6, _ => return Err("MTU family must be ipv4 or ipv6".into()) };
            let proposal = epp_service::preview::Proposal { adapterGuid: guid.parse()?, addressFamily, proposedMtu: mtu.parse()?, trialDurationMs: duration.parse()? };
            println!("{}", serde_json::to_string_pretty(&epp_service::previewBlocking(epp_service::protocol::Operation::StartMtuPreview(proposal))?)?);
            Ok(())
        }
        [mode, jobId] if mode == "--preview-status" || mode == "--cancel-mtu-preview" => {
            let jobId = jobId.parse()?;
            let operation = if mode == "--preview-status" { epp_service::protocol::Operation::GetMtuPreview { jobId } } else { epp_service::protocol::Operation::CancelMtuPreview { jobId } };
            println!("{}", serde_json::to_string_pretty(&epp_service::previewBlocking(operation)?)?);
            Ok(())
        }
        [mode, jobId, previewId, checkpointSha256] if mode == "--approve-mtu-preview" => {
            let operation = epp_service::protocol::Operation::ApproveMtuPreview { jobId: jobId.parse()?, previewId: previewId.parse()?, checkpointSha256: checkpointSha256.clone() };
            println!("{}", serde_json::to_string_pretty(&epp_service::previewBlocking(operation)?)?);
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
        [mode,guid,family] if mode=="--inspect-ip-policy" || mode=="--ip-policy-worker" => {
            let family=match family.as_str(){"ipv4"=>epp_service::journal::AddressFamily::Ipv4,"ipv6"=>epp_service::journal::AddressFamily::Ipv6,_=>return Err("IP policy family must be ipv4 or ipv6".into())};
            let cancelled=std::sync::atomic::AtomicBool::new(false);
            let capture=if mode=="--ip-policy-worker" { epp_service::mtu::policy::inspectWorker(guid.parse()?,family,&cancelled)? } else { epp_service::mtu::policy::inspect(guid.parse()?,family,&cancelled)? };
            println!("{}",serde_json::to_string_pretty(&capture)?);
            Ok(())
        }
        _ => Err("Expected --status, --identity, --mtu-inventory, --inspect-mtu GUID ipv4|ipv6, --inspect-ip-policy GUID ipv4|ipv6, or SCM-owned --service --owner-sid SID".into()),
    }
}

#[cfg(not(windows))]
fn execute() -> epp_service::ServiceResult<()> {
    Err("The dedicated service requires Windows".into())
}
