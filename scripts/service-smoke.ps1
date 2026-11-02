param([switch]$allowServiceInstallation)

$ErrorActionPreference = 'Stop'
$env:PSModulePath = "$PSHOME\Modules;$env:ProgramFiles\WindowsPowerShell\Modules"
if (-not $allowServiceInstallation) { throw 'This check installs and removes the dedicated service. Run it only in a disposable Windows lab with -allowServiceInstallation.' }
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'The service smoke check requires an already elevated disposable test account; it will not request elevation automatically.' }
$serviceName = 'EstrogenPingPatch'
$installRoot = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'estrogen ping patch service'
$dataRoot = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'estrogen-ping-patch-service'
$journalPath = Join-Path $dataRoot 'recovery.sqlite3'
if ((Get-Service -Name $serviceName -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath $installRoot) -or (Test-Path -LiteralPath $dataRoot)) { throw 'An existing service installation or recovery directory was found; preserve it and use a clean Windows lab.' }
$manager = Join-Path $PSScriptRoot 'manage-service.ps1'
$installedExe = Join-Path $installRoot 'epp-network-service.exe'
$systemPowerShell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
$previousPause = $env:EPP_NO_PAUSE
$env:EPP_NO_PAUSE = '1'
$startedAt = Get-Date

function manage([string]$action) {
    & $systemPowerShell -NoLogo -NoProfile -ExecutionPolicy Bypass -File $manager -action $action
    if ($LASTEXITCODE -ne 0) { throw "Service $action failed with exit code $LASTEXITCODE." }
}

function readStatus {
    $json = & $installedExe --status
    if ($LASTEXITCODE -ne 0) { throw 'Service status client failed.' }
    return ($json -join "`n") | ConvertFrom-Json
}

function failedPreview([string]$requiredDetail) {
    $json = & $installedExe --preview-mtu ([Guid]::NewGuid().ToString('D')) ipv4 1400 120000
    if ($LASTEXITCODE -ne 0) { throw 'The installed preview client failed to start a read-only job.' }
    $report = ($json -join "`n") | ConvertFrom-Json
    $jobId = $report.jobId
    $deadline = (Get-Date).AddSeconds(30)
    while ($report.phase -eq 'capturing') {
        if ((Get-Date) -ge $deadline) { throw 'The read-only preview job exceeded its external test allowance.' }
        Start-Sleep -Milliseconds 100
        $json = & $installedExe --preview-status $jobId
        if ($LASTEXITCODE -ne 0) { throw 'The installed preview status client failed.' }
        $report = ($json -join "`n") | ConvertFrom-Json
    }
    if ($report.phase -ne 'failed' -or $report.executionAvailable -ne $false -or $null -ne $report.preview -or $null -ne $report.grant -or $report.detail -notmatch $requiredDetail) { throw 'A refused preview was hidden or exposed unexpected approval/execution state.' }
    $json = & $installedExe --cancel-mtu-preview $jobId
    if ($LASTEXITCODE -ne 0) { throw 'The installed preview cancellation client failed.' }
    $cancelled = ($json -join "`n") | ConvertFrom-Json
    if ($cancelled.phase -ne 'cancelled' -or $cancelled.executionAvailable -ne $false) { throw 'A failed preview could not be cleared without execution.' }
}

function seedCheckpoint([string]$phase) {
    $env:EPP_JOURNAL_LAB_ACK = 'disposable-lab-no-network-setter'
    $env:EPP_JOURNAL_LAB_PATH = $journalPath
    $env:EPP_JOURNAL_LAB_PHASE = $phase
    try {
        $testName = if ($phase -in @('policy-pending', 'policy-verified')) { 'recovery::tests::policy_tests::receipt_tests::serviceLabPolicyCheckpoint' } else { 'journal::tests::serviceLabPreparedCheckpoint' }
        & cargo test --locked -p epp-service $testName -- --exact --ignored
        if ($LASTEXITCODE -ne 0) { throw "Service lab checkpoint phase '$phase' failed." }
    } finally {
        Remove-Item Env:EPP_JOURNAL_LAB_ACK, Env:EPP_JOURNAL_LAB_PATH, Env:EPP_JOURNAL_LAB_PHASE -ErrorAction SilentlyContinue
    }
}

try {
    manage 'install'
    $configuration = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if ($configuration.StartName -ine 'NT AUTHORITY\LocalService' -or $configuration.StartMode -ne 'Auto') { throw 'Service account/startup configuration was unexpected.' }
    $binaryAcl = Get-Acl -LiteralPath $installedExe
    if ($binaryAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-32-544') { throw 'Installed service binary must be owned by Administrators.' }
    if ((Get-Acl -LiteralPath $installRoot).GetOwner([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-32-544') { throw 'Installed service directory must be owned by Administrators.' }
    foreach ($rule in $binaryAcl.Access) {
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        $writeMask = [Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
        if ($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band $writeMask) -and $sid -notin @('S-1-5-18', 'S-1-5-32-544')) { throw 'An unprivileged identity can replace the installed service executable.' }
    }
    1..5 | ForEach-Object {
        $status = readStatus
        if ($status.state -ne 'ready' -or $status.response.schemaVersion -ne 3 -or $status.response.servicePid -ne $configuration.ProcessId -or $status.response.mode -ne 'readOnly' -or $status.response.modificationsPermitted -ne $false -or $status.response.rollbackAvailable -ne $false -or $status.response.checkpointStore.schemaVersion -ne 4 -or $status.response.checkpointStore.pendingRecoveryCount -ne 0 -or $status.response.checkpointStore.verifiedAtUnixMs -le 0) { throw 'Service identity, storage, or safety response was unexpected.' }
    }
    failedPreview '.'
    if (Test-Path -LiteralPath (Join-Path $dataRoot 'authorization.sqlite3')) { throw 'A failed read-only preview unexpectedly initialized grant storage.' }
    if (-not (Test-Path -LiteralPath $journalPath -PathType Leaf)) { throw 'The service did not initialize its recovery journal.' }
    $serviceSid = ([Security.Principal.NTAccount]::new('NT SERVICE', $serviceName)).Translate([Security.Principal.SecurityIdentifier]).Value
    $directoryAcl = Get-Acl -LiteralPath $dataRoot
    if (-not $directoryAcl.AreAccessRulesProtected -or $directoryAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-32-544') { throw 'Recovery directory ownership/protection was unexpected.' }
    foreach ($path in @($dataRoot, $journalPath)) {
        $rules = (Get-Acl -LiteralPath $path).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
        if ($rules.Count -ne 4) { throw 'Recovery storage has unexpected access rules.' }
        foreach ($rule in $rules) {
            $sid = $rule.IdentityReference.Value
            if ($sid -notin @('S-1-5-18', 'S-1-5-32-544', $serviceSid, 'S-1-3-4')) { throw 'Recovery storage grants access to an unexpected identity.' }
            if ($sid -eq 'S-1-3-4' -and [int]$rule.FileSystemRights -ne 0x20000) { throw 'Shared file-owner access can change recovery permissions.' }
            if ($sid -eq $serviceSid -and [int]$rule.FileSystemRights -ne 0x1301bf) { throw 'The service SID has unexpected data rights.' }
        }
    }
    manage 'stop'
    if ((readStatus).state -ne 'stopped') { throw 'Stopped service was not reported accurately.' }
    seedCheckpoint 'prepare'
    manage 'start'
    $pending = readStatus
    if ($pending.state -ne 'recoveryRequired' -or $pending.response.checkpointStore.pendingRecoveryCount -ne 1 -or $pending.response.rollbackAvailable -ne $false) { throw 'An unresolved checkpoint was hidden or mistaken for available restoration.' }
    failedPreview 'Unfinished recovery'
    manage 'stop'
    seedCheckpoint 'cancel'
    seedCheckpoint 'policy-pending'
    manage 'start'
    $pending = readStatus
    if ($pending.state -ne 'recoveryRequired' -or $pending.response.checkpointStore.pendingRecoveryCount -ne 1 -or $pending.response.rollbackAvailable -ne $false) { throw 'Restored MTU with incomplete policy verification was hidden or mistaken for available restoration.' }
    manage 'stop'
    seedCheckpoint 'policy-verified'
    manage 'start'
    if ((readStatus).state -ne 'ready') { throw 'Completed policy verification did not clear the service attention status.' }
    manage 'stop'
    $originalBytes = [IO.File]::ReadAllBytes($journalPath)
    try {
        $corruptedBytes = [byte[]]$originalBytes.Clone()
        $corruptedBytes[0] = 0
        [IO.File]::WriteAllBytes($journalPath, $corruptedBytes)
        & $systemPowerShell -NoLogo -NoProfile -ExecutionPolicy Bypass -File $manager -action start
        if ($LASTEXITCODE -eq 0) { throw 'Corrupted recovery storage did not prevent service startup.' }
        if ((Get-Service -Name $serviceName).Status -ne 'Stopped') { throw 'Service remained running with corrupted recovery storage.' }
    } finally {
        if ((Get-Service -Name $serviceName).Status -ne 'Stopped') { manage 'stop' }
        [IO.File]::WriteAllBytes($journalPath, $originalBytes)
    }
    manage 'start'
    if ((readStatus).state -ne 'ready') { throw 'Service did not recover after restart.' }
    manage 'stop'
    $journalHash = (Get-FileHash -LiteralPath $journalPath -Algorithm SHA256).Hash
    manage 'uninstall'
    if ((Get-FileHash -LiteralPath $journalPath -Algorithm SHA256).Hash -ne $journalHash) { throw 'Service removal changed the recovery journal.' }
    manage 'install'
    if ((readStatus).state -ne 'ready') { throw 'Reinstallation did not reopen the preserved journal.' }
    Write-Host 'Service smoke passed: protected binary and journal, service SID, authenticated status, refused preview and cancellation, repeated connections, pending recovery and policy verification detection, corruption refusal, restart, preserved uninstall, and reinstall. No network setter or native restoration was exercised.'
} catch {
    $failure = $_
    Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = $serviceName; StartTime = $startedAt } -MaxEvents 3 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message | Format-List | Out-Host
    throw $failure
} finally {
    try {
        if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) { manage 'uninstall' }
        if ((Get-Service -Name $serviceName -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath $installedExe)) { throw 'Test service removal was incomplete; inspect the disposable lab.' }
    } finally {
        $env:EPP_NO_PAUSE = $previousPause
    }
}
