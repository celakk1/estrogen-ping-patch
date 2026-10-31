param([switch]$allowServiceInstallation)

$ErrorActionPreference = 'Stop'
$env:PSModulePath = "$PSHOME\Modules;$env:ProgramFiles\WindowsPowerShell\Modules"
if (-not $allowServiceInstallation) { throw 'This check installs and removes the dedicated service. Run it only in a disposable Windows lab with -allowServiceInstallation.' }
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'The service smoke check requires an already elevated disposable test account; it will not request elevation automatically.' }
$serviceName = 'EstrogenPingPatch'
$installRoot = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'estrogen ping patch service'
if ((Get-Service -Name $serviceName -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath $installRoot)) { throw 'An existing service installation was found; preserve it and use a clean Windows lab.' }
$manager = Join-Path $PSScriptRoot 'manage-service.ps1'
$installedExe = Join-Path $installRoot 'epp-network-service.exe'
$systemPowerShell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
$previousPause = $env:EPP_NO_PAUSE
$env:EPP_NO_PAUSE = '1'

function manage([string]$action) {
    & $systemPowerShell -NoLogo -NoProfile -ExecutionPolicy Bypass -File $manager -action $action
    if ($LASTEXITCODE -ne 0) { throw "Service $action failed with exit code $LASTEXITCODE." }
}

function readStatus {
    $json = & $installedExe --status
    if ($LASTEXITCODE -ne 0) { throw 'Service status client failed.' }
    return ($json -join "`n") | ConvertFrom-Json
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
        if ($status.state -ne 'ready' -or $status.response.servicePid -ne $configuration.ProcessId -or $status.response.mode -ne 'readOnly' -or $status.response.modificationsPermitted -ne $false -or $status.response.rollbackAvailable -ne $false) { throw 'Service identity or safety response was unexpected.' }
    }
    manage 'stop'
    if ((readStatus).state -ne 'stopped') { throw 'Stopped service was not reported accurately.' }
    manage 'start'
    if ((readStatus).state -ne 'ready') { throw 'Service did not recover after restart.' }
    Write-Host 'Service smoke passed: protected binary, LocalService account, automatic startup, authenticated status, repeated connections, stop and restart. No network setter was exercised.'
} finally {
    try {
        if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) { manage 'uninstall' }
        if ((Get-Service -Name $serviceName -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath $installedExe)) { throw 'Test service removal was incomplete; inspect the disposable lab.' }
    } finally {
        $env:EPP_NO_PAUSE = $previousPause
    }
}
