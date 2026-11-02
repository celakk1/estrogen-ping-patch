param([switch]$allowNetworkChanges)

$ErrorActionPreference = 'Stop'
$env:PSModulePath = "$PSHOME\Modules;$env:ProgramFiles\WindowsPowerShell\Modules"
if (-not $allowNetworkChanges -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'Preview tests create an owned loopback adapter and require -allowNetworkChanges on a fresh GitHub-hosted Windows runner. Development-machine execution is refused.'
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
$evidence = @()

function manage([string]$action) {
    & $systemPowerShell -NoLogo -NoProfile -ExecutionPolicy Bypass -File $manager -action $action
    if ($LASTEXITCODE -ne 0) { throw "Service $action failed with exit code $LASTEXITCODE." }
}

function client([string[]]$arguments) {
    $json = & $installedExe @arguments
    if ($LASTEXITCODE -ne 0) { throw "Service preview client failed for $($arguments[0])." }
    ($json -join "`n") | ConvertFrom-Json
}

function assertOldJobRefused([string]$jobId) {
    $ErrorActionPreference = 'Continue'
    $output = & $installedExe --preview-status $jobId 2>&1
    if ($LASTEXITCODE -ne 1 -or ($output -join "`n") -notmatch 'No MTU preview is available') { throw 'Restart did not invalidate the old in-memory preview.' }
}

function waitPhase([object]$report, [string]$expected) {
    $deadline = [DateTime]::UtcNow.AddSeconds(25)
    while ($report.phase -in @('capturing', 'authorizing', 'cancelling')) {
        if ([DateTime]::UtcNow -ge $deadline) { throw "Preview job exceeded its outer allowance while $($report.phase)." }
        Start-Sleep -Milliseconds 100
        $report = client -arguments @('--preview-status', $report.jobId)
    }
    if ($report.phase -cne $expected -or $report.executionAvailable -ne $false) { throw "Expected $expected without execution: $($report | ConvertTo-Json -Depth 8 -Compress)" }
    $report
}

function capturePolicy([string]$family) {
    $capture = client -arguments @('--inspect-ip-policy', $guid.ToString('D'), $family)
    if ($capture.native.adapterGuid -cne $guid.ToString('D') -or $capture.native.addressFamily -cne $family -or $capture.native.registryOrigins.status -cne 'captured') { throw 'Independent policy capture lacks the exact owned target or registry origins.' }
    $capture.native.PSObject.Properties.Remove('capturedAtUnixMs')
    $capture | ConvertTo-Json -Depth 24 -Compress
}

function assertReadOnly {
    $status = client -arguments @('--status')
    if ($status.state -cne 'ready' -or $status.response.mode -cne 'readOnly' -or $status.response.modificationsPermitted -ne $false -or $status.response.rollbackAvailable -ne $false -or $status.response.checkpointStore.pendingRecoveryCount -ne 0) { throw 'Preview metadata unexpectedly changed service execution or recovery state.' }
}

try {
    $instanceId = [NativeMtuLabDevice]::create()
    $deadline = [DateTime]::UtcNow.AddSeconds(45)
    do {
        $adapters = @(Get-NetAdapter -IncludeHidden | Where-Object { $_.PnPDeviceID -eq $instanceId })
        $ready = $adapters.Count -eq 1 -and @(Get-NetIPInterface -InterfaceIndex $adapters[0].ifIndex -ErrorAction SilentlyContinue).Count -eq 2
        if ($ready) { break }
        Start-Sleep -Milliseconds 300
    } while ([DateTime]::UtcNow -lt $deadline)
    if (-not $ready) { throw 'The newly owned loopback adapter was not uniquely ready for both families.' }
    $guid = [Guid]$adapters[0].InterfaceGuid
    if (@(Get-NetRoute -InterfaceIndex $adapters[0].ifIndex | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0', '::/0') }).Count -ne 0) { throw 'The disposable adapter unexpectedly owns a default route.' }
    $installationAttempted = $true
    manage 'install'
    $configuration = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if ($configuration.StartName -ine 'NT AUTHORITY\LocalService') { throw 'Preview service must use the production LocalService account.' }
    assertReadOnly
    foreach ($family in @('ipv4', 'ipv6')) {
        $before = capturePolicy $family
        $readyReport = waitPhase (client -arguments @('--preview-mtu', $guid.ToString('D'), $family, '1400', '120000')) 'ready'
        $preview = $readyReport.preview
        if ($preview.context.adapterGuid -cne $guid.ToString('D') -or $preview.addressFamily -cne $family -or $preview.originalMtu -ne 1500 -or $preview.proposedMtu -ne 1400 -or $preview.allowRetention -ne $false -or $null -ne $readyReport.grant) { throw 'The installed service preview did not preserve the exact temporary proposal.' }
        $approved = waitPhase (client -arguments @('--approve-mtu-preview', $readyReport.jobId, $preview.previewId, $preview.checkpointSha256)) 'approved'
        if ($approved.grant.checkpointSha256 -cne $preview.checkpointSha256 -or $approved.grant.checkpointId -cne $preview.checkpointId -or $approved.grant.expiresAtUnixMs -ne $preview.trialExpiresAtUnixMs -or $approved.grant.allowRetention -ne $false -or $approved.grant.revoked -ne $false) { throw 'The recorded grant differs from its reviewed scope.' }
        if (-not (Test-Path -LiteralPath (Join-Path $dataRoot 'authorization.sqlite3') -PathType Leaf)) { throw 'Approval did not create protected authorization storage.' }
        assertReadOnly
        if ((capturePolicy $family) -cne $before) { throw 'Approval changed native, driver, registry-origin, or active/persistent policy evidence.' }
        $cancelled = waitPhase (client -arguments @('--cancel-mtu-preview', $readyReport.jobId)) 'cancelled'
        if ($cancelled.grant.grantId -cne $approved.grant.grantId -or $cancelled.grant.revoked -ne $true) { throw 'Cancellation did not confirm revocation of the exact persisted grant.' }
        if ((capturePolicy $family) -cne $before) { throw 'Revocation changed interface configuration.' }
        manage 'stop'
        $authorizationHash = (Get-FileHash -LiteralPath (Join-Path $dataRoot 'authorization.sqlite3') -Algorithm SHA256).Hash
        manage 'start'
        assertReadOnly
        assertOldJobRefused $readyReport.jobId
        if ((Get-FileHash -LiteralPath (Join-Path $dataRoot 'authorization.sqlite3') -Algorithm SHA256).Hash -cne $authorizationHash) { throw 'Restart unexpectedly rewrote persisted permission records.' }
        $evidence += [ordered]@{ family = $family; originalMtu = 1500; proposedMtu = 1400; approved = $true; revoked = $true; configurationUnchanged = $true; executionAvailable = $false }
    }
    Write-Host 'Installed preview passed: LocalService native capture, exact approval, protected permission storage, revocation, restart invalidation, and unchanged IPv4/IPv6 settings on an owned loopback adapter.'
    $evidence | ConvertTo-Json -Depth 4
} catch {
    $failure = $_
    Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = $serviceName; StartTime = $startedAt } -MaxEvents 3 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message | Format-List | Out-Host
    throw $failure
} finally {
    try {
        if ($installationAttempted -and (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) { manage 'uninstall' }
    } finally {
        if ($instanceId) { [NativeMtuLabDevice]::remove($instanceId) }
    }
}
