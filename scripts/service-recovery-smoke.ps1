param([switch]$allowNetworkChanges)

$ErrorActionPreference = 'Stop'
$env:PSModulePath = "$PSHOME\Modules;$env:ProgramFiles\WindowsPowerShell\Modules"
if (-not $allowNetworkChanges -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'Recovery tests require -allowNetworkChanges on a fresh GitHub-hosted Windows runner. Development-machine execution is refused.'
}
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'An already elevated disposable account is required; this test never requests elevation.' }
$serviceName = 'EstrogenPingPatch'
$installRoot = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'estrogen ping patch service'
$dataRoot = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'estrogen-ping-patch-service'
if ((Get-Service -Name $serviceName -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath $installRoot) -or (Test-Path -LiteralPath $dataRoot)) { throw 'Existing service or recovery storage found; use a fresh disposable runner.' }
foreach ($device in @(Get-PnpDevice -Class Net -PresentOnly)) {
    $ids = (Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName DEVPKEY_Device_HardwareIds -ErrorAction SilentlyContinue).Data
    if (@($ids | Where-Object { $_ -ieq '*msloop' }).Count -gt 0) { throw 'An existing Microsoft loopback adapter was found; refusing global driver matching.' }
}
Add-Type -Path (Join-Path $PSScriptRoot 'native-mtu-lab-device.cs')
$manager = Join-Path $PSScriptRoot 'manage-service.ps1'
$installedExe = Join-Path $installRoot 'epp-network-service.exe'
$systemPowerShell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
$instanceId = $null
$installationAttempted = $false
$startedAt = Get-Date

function manage([string]$action) {
    $arguments = @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $manager, '-action', $action)
    if ($action -eq 'install') { $arguments += '-recoveryOnly' }
    & $systemPowerShell @arguments
    if ($LASTEXITCODE -ne 0) { throw "Recovery service $action failed with exit code $LASTEXITCODE." }
}

function client([string[]]$arguments) {
    $json = & $installedExe @arguments
    if ($LASTEXITCODE -ne 0) { throw "Recovery client failed for $($arguments[0])." }
    ($json -join "`n") | ConvertFrom-Json
}

function waitRecovery {
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    do {
        $status = client -arguments @('--status')
        if ($status.response.mode -cne 'recoveryOnly' -or $status.response.modificationsPermitted -ne $false -or $status.response.rollbackAvailable -ne $true) { throw 'Recovery mode exposed unexpected capabilities.' }
        if ($status.response.recovery.phase -ne 'running') { return $status }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Recovery exceeded its outer test allowance.'
}

function capturePolicy([string]$family) {
    $capture = client -arguments @('--inspect-ip-policy', $guid.ToString('D'), $family)
    if ($capture.native.adapterGuid -cne $guid.ToString('D') -or $capture.native.addressFamily -cne $family -or $capture.native.registryOrigins.status -cne 'captured') { throw 'Capture lacks exact owned-target or registry-origin evidence.' }
    $capture.native.PSObject.Properties.Remove('capturedAtUnixMs')
    $capture | ConvertTo-Json -Depth 24 -Compress
}

function journalFixture([string]$phase, [string]$family) {
    $env:EPP_RECOVERY_LAB_ACK = 'owned-loopback-recovery-only'
    $env:EPP_RECOVERY_LAB_GUID = $guid.ToString('D')
    $env:EPP_RECOVERY_LAB_PATH = Join-Path $dataRoot 'recovery.sqlite3'
    $env:EPP_RECOVERY_LAB_OWNER = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $env:EPP_RECOVERY_LAB_PHASE = $phase
    $env:EPP_RECOVERY_LAB_FAMILY = $family
    if ($phase -eq 'seed') {
        $capture = client -arguments @('--inspect-ip-policy', $guid.ToString('D'), $family)
        $env:EPP_RECOVERY_LAB_CAPTURE = $capture | ConvertTo-Json -Depth 24 -Compress
    }
    & cargo.exe test --locked -p epp-service --features native-recovery recovery::native::tests::installedRecoveryJournalFixture -- --ignored --exact --nocapture
    if ($LASTEXITCODE -ne 0) { throw "Protected recovery journal fixture failed during $phase." }
}

function matchesOwnedAdapter($adapter) {
    $adapter.PnPDeviceID -ieq $instanceId -and [Guid]$adapter.InterfaceGuid -eq $guid -and $adapter.Name -ceq "epp-recovery-lab-$guid"
}

function stageOwnedCandidate([string]$family) {
    $adapters = @(Get-NetAdapter -IncludeHidden | Where-Object { matchesOwnedAdapter $_ })
    if ($adapters.Count -ne 1) { throw 'The owned adapter identity changed before fixture setup.' }
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = Join-Path ([Environment]::SystemDirectory) 'netsh.exe'
    $start.Arguments = "interface $family set subinterface interface=epp-recovery-lab-$guid mtu=1372 store=active"
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $process = [Diagnostics.Process]::Start($start)
    try {
        if (-not $process.WaitForExit(5000)) {
            $process.Kill()
            if (-not $process.WaitForExit(5000)) { throw 'Owned fixture command termination could not be verified.' }
            throw 'Owned fixture command timed out.'
        }
        if ($process.ExitCode -ne 0) { throw 'Owned fixture MTU setup failed.' }
    } finally { $process.Dispose() }
    $row = Get-NetIPInterface -InterfaceIndex $adapters[0].ifIndex -AddressFamily $family -PolicyStore ActiveStore
    if ($row.NlMtu -ne 1372) { throw 'The owned fixture candidate did not read back.' }
}

try {
    $instanceId = [NativeMtuLabDevice]::create()
    $deadline = [DateTime]::UtcNow.AddSeconds(45)
    do {
        $adapters = @(Get-NetAdapter -IncludeHidden | Where-Object { $_.PnPDeviceID -ieq $instanceId })
        $ready = $adapters.Count -eq 1 -and @(Get-NetIPInterface -InterfaceIndex $adapters[0].ifIndex -ErrorAction SilentlyContinue).Count -eq 2
        if ($ready) { break }
        Start-Sleep -Milliseconds 300
    } while ([DateTime]::UtcNow -lt $deadline)
    if (-not $ready) { throw 'The newly owned loopback adapter was not uniquely ready for both families.' }
    $guid = [Guid]$adapters[0].InterfaceGuid
    Rename-NetAdapter -InputObject $adapters[0] -NewName "epp-recovery-lab-$guid"
    $installationAttempted = $true
    manage 'install'
    $empty = waitRecovery
    if ($empty.state -ne 'ready' -or $empty.response.recovery.phase -ne 'completed' -or $empty.response.checkpointStore.pendingRecoveryCount -ne 0) { throw 'An empty recovery-only startup did not finish safely.' }
    $configuration = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if ($configuration.StartName -notin @('LocalSystem', 'NT AUTHORITY\SYSTEM') -or $configuration.PathName -notlike '* --recovery-service --owner-sid *') { throw 'The installed recovery account or command was unexpected.' }
    $previousPid = $configuration.ProcessId
    $process = [Diagnostics.Process]::GetProcessById($previousPid)
    try {
        $null = $process.Handle
        $confirmed = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
        if ($confirmed.ProcessId -ne $previousPid -or $confirmed.State -ne 'Running') { throw 'Service PID changed before the crash fixture.' }
        $process.Kill()
        if (-not $process.WaitForExit(5000)) { throw 'The exact crashed service process did not exit.' }
    } finally { $process.Dispose() }
    $restartDeadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        $restarted = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
        if ($restarted.State -eq 'Running' -and $restarted.ProcessId -ne 0 -and $restarted.ProcessId -ne $previousPid) { break }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $restartDeadline)
    if ($restarted.State -ne 'Running' -or $restarted.ProcessId -eq $previousPid) { throw 'The recovery-only service did not restart automatically after its process crashed.' }
    $empty = waitRecovery
    if ($empty.state -ne 'ready' -or $empty.response.checkpointStore.pendingRecoveryCount -ne 0) { throw 'The automatically restarted recovery service did not finish its empty check.' }
    $before = @{}
    foreach ($family in @('ipv4', 'ipv6')) { $before[$family] = capturePolicy $family }
    foreach ($family in @('ipv4', 'ipv6')) {
        manage 'stop'
        journalFixture 'seed' $family
        stageOwnedCandidate $family
        Start-Sleep -Milliseconds 1200
        if (Test-Path -LiteralPath (Join-Path $dataRoot 'authorization.sqlite3')) { throw 'Recovery fixture unexpectedly has apply authorization storage.' }
        manage 'start'
        $restored = waitRecovery
        if ($restored.state -ne 'ready' -or $restored.response.recovery.phase -ne 'completed' -or $restored.response.recovery.verifiedCount -ne 1 -or $restored.response.checkpointStore.pendingRecoveryCount -ne 0) { throw "Recovery did not verify the $family original: $($restored | ConvertTo-Json -Depth 8 -Compress)" }
        foreach ($checkedFamily in @('ipv4', 'ipv6')) {
            if ((capturePolicy $checkedFamily) -cne $before[$checkedFamily]) { throw "Recovery changed unrelated native, driver, registry, or persistent policy evidence for $checkedFamily." }
        }
    }
    if (Test-Path -LiteralPath (Join-Path $dataRoot 'authorization.sqlite3')) { throw 'Exact-original recovery opened or created apply authorization storage.' }
    manage 'stop'
    journalFixture 'verify'
    $journalHash = (Get-FileHash -LiteralPath (Join-Path $dataRoot 'recovery.sqlite3') -Algorithm SHA256).Hash
    manage 'start'
    $again = waitRecovery
    if ($again.response.recovery.verifiedCount -ne 0 -or $again.response.checkpointStore.pendingRecoveryCount -ne 0) { throw 'Completed recovery was replayed after restart.' }
    manage 'stop'
    if ((Get-FileHash -LiteralPath (Join-Path $dataRoot 'recovery.sqlite3') -Algorithm SHA256).Hash -cne $journalHash) { throw 'Empty restart rewrote a completed recovery journal.' }
    Write-Host 'Installed recovery passed: two expired IPv4/IPv6 checkpoints, exact original MTU 1500, unchanged unrelated policy, no authorization database, and no replay after restart.'
    [ordered]@{ originalMtu = 1500; candidateMtu = 1372; restoredCount = 2; pendingCount = 0; session = 0; automaticCrashRestart = $true; applyAuthorizationRequired = $false; retained = $false; configurationPreserved = $true } | ConvertTo-Json -Compress
} catch {
    $failure = $_
    foreach ($log in @('Application', 'System')) {
        try {
            Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $startedAt } -MaxEvents 80 -ErrorAction Stop | Where-Object { $_.ProviderName -eq $serviceName -or $_.Message -match 'EstrogenPingPatch|estrogen ping patch|Dedicated service' } | Select-Object -First 5 TimeCreated, ProviderName, Message, @{ Name = 'Details'; Expression = { ($_.Properties | ForEach-Object { [string]$_.Value }) -join '; ' } } | Format-List | Out-Host
        } catch { Write-Host "Additional $log service diagnostics unavailable: $($_.Exception.Message)" }
    }
    throw $failure
} finally {
    try {
        if ($installationAttempted -and (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) { manage 'uninstall' }
    } finally {
        if ($instanceId) { [NativeMtuLabDevice]::remove($instanceId) }
        foreach ($name in @('EPP_RECOVERY_LAB_ACK', 'EPP_RECOVERY_LAB_GUID', 'EPP_RECOVERY_LAB_PATH', 'EPP_RECOVERY_LAB_OWNER', 'EPP_RECOVERY_LAB_PHASE', 'EPP_RECOVERY_LAB_FAMILY', 'EPP_RECOVERY_LAB_CAPTURE')) { Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue }
    }
}
