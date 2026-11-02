use crate::{
    ServiceResult,
    protocol::{self, CheckpointStoreStatus, Request, ServiceStatus},
    security,
};
use std::{
    os::windows::io::AsRawHandle,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, ServerOptions},
    sync::watch,
};
use windows_sys::Win32::{
    Foundation::INVALID_HANDLE_VALUE,
    Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, SECURITY_IDENTIFICATION,
        SECURITY_SQOS_PRESENT,
    },
    System::Pipes::{GetNamedPipeServerProcessId, GetNamedPipeServerSessionId},
};

pub(crate) fn nowUnixMs() -> ServiceResult<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}

async fn readFrame(reader: &mut (impl AsyncRead + Unpin)) -> ServiceResult<Vec<u8>> {
    let length = reader.read_u32().await? as usize;
    if length == 0 || length > protocol::MAX_FRAME_BYTES {
        return Err("Service frame length is outside the 1..4096-byte bound".into());
    }
    let mut frame = vec![0; length];
    reader.read_exact(&mut frame).await?;
    Ok(frame)
}

async fn writeFrame(writer: &mut (impl AsyncWrite + Unpin), frame: &[u8]) -> ServiceResult<()> {
    if frame.is_empty() || frame.len() > protocol::MAX_FRAME_BYTES {
        return Err("Service response exceeded its frame bound".into());
    }
    writer.write_u32(frame.len() as u32).await?;
    writer.write_all(frame).await?;
    Ok(())
}

pub(crate) fn createServer(
    pipeName: &str,
    ownerSid: &str,
    serverSid: &str,
    firstInstance: bool,
) -> ServiceResult<NamedPipeServer> {
    let descriptor = security::Descriptor::pipe(ownerSid, serverSid)?;
    let mut attributes = descriptor.attributes();
    let pipe = unsafe {
        ServerOptions::new()
            .first_pipe_instance(firstInstance)
            .reject_remote_clients(true)
            .max_instances(2)
            .in_buffer_size(4096)
            .out_buffer_size(4096)
            .create_with_security_attributes_raw(
                pipeName,
                (&mut attributes as *mut windows_sys::Win32::Security::SECURITY_ATTRIBUTES).cast(),
            )
    }?;
    Ok(pipe)
}

async fn serveClient(
    pipe: &mut NamedPipeServer,
    ownerSid: &str,
    checkpointStore: &CheckpointStoreStatus,
    preview: Option<&crate::preview::Control>,
) -> ServiceResult<()> {
    let frame = readFrame(pipe).await?;
    let actorSid = security::authenticateClient(pipe.as_raw_handle(), ownerSid)?;
    let request = protocol::decodeRequest(&frame, nowUnixMs()?)?;
    let result = match &request.operation {
        protocol::Operation::GetStatus => {
            protocol::ReplyBody::Status(protocol::response(&request, checkpointStore))
        }
        operation => {
            let result = (|| {
                let preview = preview.ok_or("MTU preview worker is unavailable")?;
                match operation {
                    protocol::Operation::StartMtuPreview(proposal) => {
                        preview.start(proposal.clone(), &actorSid)
                    }
                    protocol::Operation::GetMtuPreview { jobId } => preview.get(*jobId, &actorSid),
                    protocol::Operation::ApproveMtuPreview {
                        jobId,
                        previewId,
                        checkpointSha256,
                    } => preview.approve(*jobId, *previewId, checkpointSha256, &actorSid),
                    protocol::Operation::CancelMtuPreview { jobId } => {
                        preview.cancel(*jobId, &actorSid)
                    }
                    protocol::Operation::GetStatus => unreachable!(),
                }
            })();
            match result {
                Ok(report) => {
                    report.validate()?;
                    protocol::ReplyBody::MtuPreview(report)
                }
                Err(error) => protocol::ReplyBody::Rejected {
                    detail: error.to_string().chars().take(256).collect(),
                },
            }
        }
    };
    writeFrame(
        pipe,
        &serde_json::to_vec(&protocol::Reply::new(&request, result))?,
    )
    .await
}

pub(crate) async fn serve(
    mut pipe: NamedPipeServer,
    pipeName: String,
    ownerSid: String,
    serverSid: String,
    mut stop: watch::Receiver<bool>,
    checkpointStore: CheckpointStoreStatus,
    preview: Option<crate::preview::Control>,
) -> ServiceResult<()> {
    loop {
        if *stop.borrow() {
            return Ok(());
        }
        tokio::select! {
            result = pipe.connect() => result?,
            _ = stop.changed() => return Ok(()),
        }
        // fresh handles avoid stale mio reads; the waiting instance preserves the pipe namespace.
        let next = createServer(&pipeName, &ownerSid, &serverSid, false)?;
        let mut connected = std::mem::replace(&mut pipe, next);
        tokio::select! {
            _ = tokio::time::timeout(Duration::from_millis(protocol::MAX_REQUEST_LIFETIME_MS), serveClient(&mut connected, &ownerSid, &checkpointStore, preview.as_ref())) => {},
            _ = stop.changed() => return Ok(()),
        }
    }
}

fn openClient(pipeName: &str) -> ServiceResult<NamedPipeClient> {
    let name: Vec<u16> = pipeName.encode_utf16().chain(Some(0)).collect();
    // identification exposes the caller's identity without granting impersonation privileges.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            security::CLIENT_ACCESS,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let error = std::io::Error::last_os_error();
        return Err(error.into());
    }
    Ok(unsafe { NamedPipeClient::from_raw_handle(handle) }?)
}

pub(crate) fn serverIdentity(client: &NamedPipeClient) -> ServiceResult<(u32, u32)> {
    let mut pid = 0;
    let mut session = u32::MAX;
    if unsafe { GetNamedPipeServerProcessId(client.as_raw_handle(), &mut pid) } == 0
        || unsafe { GetNamedPipeServerSessionId(client.as_raw_handle(), &mut session) } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok((pid, session))
}

pub(crate) async fn exchange(
    pipeName: &str,
    expectedPid: u32,
    expectedSession: u32,
    operation: protocol::Operation,
) -> ServiceResult<protocol::Reply> {
    tokio::time::timeout(
        Duration::from_millis(protocol::MAX_REQUEST_LIFETIME_MS),
        async {
            let mut client = loop {
                match openClient(pipeName) {
                    Ok(client) => break client,
                    Err(error)
                        if error
                            .downcast_ref::<std::io::Error>()
                            .is_some_and(|error| matches!(error.raw_os_error(), Some(2 | 231))) =>
                    {
                        tokio::time::sleep(Duration::from_millis(25)).await
                    }
                    Err(error) => return Err(error),
                }
            };
            if serverIdentity(&client)? != (expectedPid, expectedSession) {
                return Err("Pipe server does not match the registered Windows service".into());
            }
            let now = nowUnixMs()?;
            let request = Request {
                schemaVersion: protocol::SCHEMA_VERSION,
                requestId: format!("{}-{now}", std::process::id()),
                issuedAtUnixMs: now,
                expiresAtUnixMs: now.saturating_add(protocol::MAX_REQUEST_LIFETIME_MS),
                operation,
            };
            request.validate(now)?;
            writeFrame(&mut client, &serde_json::to_vec(&request)?).await?;
            let response: protocol::Reply = serde_json::from_slice(&readFrame(&mut client).await?)?;
            if response.schemaVersion != protocol::SCHEMA_VERSION
                || response.requestId != request.requestId
                || response.servicePid != expectedPid
            {
                return Err("Service response failed protocol or safety validation".into());
            }
            Ok(response)
        },
    )
    .await
    .map_err(|_| "Dedicated service exceeded its five-second communication deadline")?
}

pub(crate) async fn query(
    pipeName: &str,
    expectedPid: u32,
    expectedSession: u32,
) -> ServiceResult<ServiceStatus> {
    let reply = exchange(
        pipeName,
        expectedPid,
        expectedSession,
        protocol::Operation::GetStatus,
    )
    .await?;
    let protocol::ReplyBody::Status(response) = reply.result else {
        return Err("Service returned an unexpected status response".into());
    };
    if response.schemaVersion != protocol::SCHEMA_VERSION
        || response.requestId != reply.requestId
        || response.servicePid != expectedPid
        || response.mode != "readOnly"
        || response.modificationsPermitted
        || response.rollbackAvailable
        || response.checkpointStore.schemaVersion != crate::journal::SCHEMA_VERSION
        || response.checkpointStore.verifiedAtUnixMs == 0
        || response.checkpointStore.verifiedAtUnixMs > i64::MAX as u64
        || response.checkpointStore.pendingRecoveryCount > 2000
    {
        return Err("Service response failed protocol or safety validation".into());
    }
    Ok(response)
}

#[cfg(test)]
pub(crate) async fn localTestExchange(
    pipeName: &str,
    operation: protocol::Operation,
) -> ServiceResult<(protocol::Reply, u32)> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut client = openClient(pipeName)?;
        let (pid, session) = serverIdentity(&client)?;
        if pid != std::process::id() {
            return Err("Test pipe belongs to another process".into());
        }
        let now = nowUnixMs()?;
        let request = Request {
            schemaVersion: protocol::SCHEMA_VERSION,
            requestId: format!("{}-{now}", std::process::id()),
            issuedAtUnixMs: now,
            expiresAtUnixMs: now + protocol::MAX_REQUEST_LIFETIME_MS,
            operation,
        };
        writeFrame(&mut client, &serde_json::to_vec(&request)?).await?;
        let reply: protocol::Reply = serde_json::from_slice(&readFrame(&mut client).await?)?;
        if reply.schemaVersion != protocol::SCHEMA_VERSION
            || reply.requestId != request.requestId
            || reply.servicePid != pid
        {
            return Err("Test pipe response identity mismatch".into());
        }
        Ok((reply, session))
    })
    .await
    .map_err(|_| "Test pipe exchange expired")?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT_PIPE: AtomicUsize = AtomicUsize::new(1);

    fn testPipe() -> String {
        format!(
            r"\\.\pipe\epp-test-{}-{}-{}",
            std::process::id(),
            nowUnixMs().unwrap(),
            NEXT_PIPE.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn checkpointStore() -> CheckpointStoreStatus {
        CheckpointStoreStatus {
            schemaVersion: crate::journal::SCHEMA_VERSION,
            verifiedAtUnixMs: nowUnixMs().unwrap() + 86_400_000,
            pendingRecoveryCount: 0,
        }
    }

    #[test]
    fn realPipeAuthenticatesCallerBoundsFramesAndRejectsServerImpersonation() {
        runtime().block_on(async {
            let name = testPipe();
            let owner = security::currentSid().unwrap();
            let pipe = createServer(&name, &owner, &owner, true).unwrap();
            assert!(createServer(&name, &owner, &owner, true).is_err());
            let (stop, receiver) = watch::channel(false);
            let server = serve(
                pipe,
                name.clone(),
                owner.clone(),
                owner,
                receiver,
                checkpointStore(),
                None,
            );
            let client = async {
                let probe = openClient(&name).unwrap();
                let (pid, session) = serverIdentity(&probe).unwrap();
                drop(probe);
                assert!(query(&name, pid + 1, session).await.is_err());
                let status = query(&name, pid, session).await.unwrap();
                assert_eq!(status.mode, "readOnly");
                assert!(!status.modificationsPermitted);
                stop.send(true).unwrap();
            };
            let (result, ()) = tokio::join!(server, client);
            result.unwrap();
        });
    }

    #[test]
    fn malformedClientCannotDispatchAndServerRemainsUsable() {
        runtime().block_on(async {
            let name = testPipe();
            let owner = security::currentSid().unwrap();
            let pipe = createServer(&name, &owner, &owner, true).unwrap();
            let (stop, receiver) = watch::channel(false);
            let server = serve(
                pipe,
                name.clone(),
                owner.clone(),
                owner.clone(),
                receiver,
                checkpointStore(),
                None,
            );
            let client = async {
                let mut client = openClient(&name).unwrap();
                client
                    .write_u32((protocol::MAX_FRAME_BYTES + 1) as u32)
                    .await
                    .unwrap();
                let mut buffer = [0];
                assert!(matches!(client.read(&mut buffer).await, Ok(0) | Err(_)));
                drop(client);
                let probe = openClient(&name).unwrap();
                let (pid, session) = serverIdentity(&probe).unwrap();
                drop(probe);
                assert_eq!(query(&name, pid, session).await.unwrap().mode, "readOnly");
                stop.send(true).unwrap();
            };
            let (result, ()) = tokio::join!(server, client);
            result.unwrap();
        });
    }

    #[test]
    fn unexpectedCallerTokenCannotDispatchEvenIfAclAllowsTheConnection() {
        runtime().block_on(async {
            let name = testPipe();
            let owner = security::currentSid().unwrap();
            let pipe = createServer(&name, &owner, &owner, true).unwrap();
            let (stop, receiver) = watch::channel(false);
            let server = serve(
                pipe,
                name.clone(),
                "S-1-5-19".into(),
                owner,
                receiver,
                checkpointStore(),
                None,
            );
            let client = async {
                let probe = openClient(&name).unwrap();
                let (pid, session) = serverIdentity(&probe).unwrap();
                drop(probe);
                assert!(query(&name, pid, session).await.is_err());
                security::assertNoThreadImpersonation();
                stop.send(true).unwrap();
            };
            let (result, ()) = tokio::join!(server, client);
            result.unwrap();
        });
    }

    #[test]
    fn explicitAclDeniesAnUnlistedUser() {
        runtime().block_on(async {
            let name = testPipe();
            let _pipe = createServer(&name, "S-1-5-21-1-2-3-4", "S-1-5-19", true).unwrap();
            let error = openClient(&name).unwrap_err();
            assert_eq!(
                error
                    .downcast_ref::<std::io::Error>()
                    .unwrap()
                    .raw_os_error(),
                Some(5)
            );
            let authorizedName = testPipe();
            let owner = security::currentSid().unwrap();
            let _authorized = createServer(&authorizedName, &owner, "S-1-5-19", true).unwrap();
            assert!(openClient(&authorizedName).is_ok());
            assert!(createServer(&authorizedName, &owner, "S-1-5-19", false).is_err());
        });
    }

    #[test]
    fn incompleteFrameExpiresAndTheNextClientCanQuery() {
        runtime().block_on(async {
            let name = testPipe();
            let owner = security::currentSid().unwrap();
            let pipe = createServer(&name, &owner, &owner, true).unwrap();
            let (stop, receiver) = watch::channel(false);
            let server = serve(
                pipe,
                name.clone(),
                owner.clone(),
                owner,
                receiver,
                checkpointStore(),
                None,
            );
            let client = async {
                let mut client = openClient(&name).unwrap();
                let (pid, session) = serverIdentity(&client).unwrap();
                client.write_u32(4096).await.unwrap();
                assert!(
                    tokio::time::timeout(Duration::from_secs(8), readFrame(&mut client))
                        .await
                        .unwrap()
                        .is_err()
                );
                drop(client);
                assert_eq!(query(&name, pid, session).await.unwrap().mode, "readOnly");
                stop.send(true).unwrap();
            };
            let (result, ()) = tokio::join!(server, client);
            result.unwrap();
        });
    }

    #[test]
    fn serviceStopCancelsAnIncompleteClientFrame() {
        runtime().block_on(async {
            let name = testPipe();
            let owner = security::currentSid().unwrap();
            let pipe = createServer(&name, &owner, &owner, true).unwrap();
            let (stop, receiver) = watch::channel(false);
            let server = serve(
                pipe,
                name.clone(),
                owner.clone(),
                owner,
                receiver,
                checkpointStore(),
                None,
            );
            let client = async {
                let mut client = openClient(&name).unwrap();
                client.write_u32(4096).await.unwrap();
                stop.send(true).unwrap();
                tokio::time::sleep(Duration::from_millis(100)).await;
            };
            let (result, ()) = tokio::join!(server, client);
            result.unwrap();
        });
    }
}
