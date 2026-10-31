param(
    [Parameter(Mandatory = $true)][ValidateSet('install', 'uninstall', 'start', 'stop', 'status')][string]$action,
    [string]$ownerSid
)

$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -ne 'Desktop') { throw 'Use install-service.bat, uninstall-service.bat, or Windows PowerShell 5.1 to run this helper.' }
$env:PSModulePath = "$PSHOME\Modules;$env:ProgramFiles\WindowsPowerShell\Modules"
$serviceName = 'EstrogenPingPatch'
$installRoot = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'estrogen ping patch service'
$installedExe = Join-Path $installRoot 'epp-network-service.exe'
$createdDirectory = $false
$registeredService = $false

function assertSafeInstallPath {
    foreach ($path in @([Environment]::GetFolderPath('ProgramFiles'), $installRoot, $installedExe)) {
        if (Test-Path -LiteralPath $path) {
            if ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Refusing a reparse point in the service installation path: $path" }
        }
    }
}

function getRegisteredService {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service) {
        $configuration = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
        $expectedPrefix = '"' + $installedExe + '" --service --owner-sid '
        if (-not $configuration.PathName.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase) -or $configuration.StartName -ine 'NT AUTHORITY\LocalService') {
            throw 'An existing service with this name has an unexpected configuration. Inspect Windows Services; it will not be overwritten.'
        }
    }
    if ($service) { return [ServiceProcess.ServiceController]::new($serviceName) }
    return $null
}

function quoteArgument([string]$value) {
    if ($value.Contains('"') -or $value.Contains("`r") -or $value.Contains("`n")) { throw 'A service management path contains unsupported command-line characters.' }
    return '"' + $value + '"'
}

try {
    assertSafeInstallPath
    $sourceExe = Join-Path $PSScriptRoot 'epp-network-service.exe'
    if (-not (Test-Path -LiteralPath $sourceExe)) { $sourceExe = Join-Path $PSScriptRoot '..\target\release\epp-network-service.exe' }
    if (-not (Test-Path -LiteralPath $sourceExe)) { $sourceExe = Join-Path $PSScriptRoot '..\target\debug\epp-network-service.exe' }
    if ($action -eq 'status') {
        if (-not (Test-Path -LiteralPath $sourceExe)) { throw 'Build the service with build.bat, or run this helper from the installed application.' }
        & $sourceExe --status
        exit $LASTEXITCODE
    }
    if ($action -eq 'install' -and -not (Test-Path -LiteralPath $sourceExe -PathType Leaf)) { throw 'Service executable missing. Run build.bat or launch.bat first.' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $ownerSid) { $ownerSid = $identity.User.Value }
    $ownerSid = ([Security.Principal.SecurityIdentifier]::new($ownerSid)).Value
    $isAdministrator = ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdministrator) {
        $arguments = '-NoLogo -NoProfile -ExecutionPolicy Bypass -File ' + (quoteArgument $PSCommandPath) + ' -action ' + $action + ' -ownerSid ' + $ownerSid
        $systemPowerShell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
        $child = Start-Process -FilePath $systemPowerShell -ArgumentList $arguments -Verb RunAs -WindowStyle Hidden -Wait -PassThru
        exit $child.ExitCode
    }
    $service = getRegisteredService
    switch ($action) {
        'install' {
            if ($service) { throw 'The service is already installed. Uninstall it before changing the binary or authorized user.' }
            if (Test-Path -LiteralPath $installRoot) { throw "The service directory already exists. Inspect it before reinstalling: $installRoot" }
            $acl = [Security.AccessControl.DirectorySecurity]::new()
            $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
            $acl.SetAccessRuleProtection($true, $false)
            foreach ($rule in @(@('S-1-5-18', 'FullControl'), @('S-1-5-32-544', 'FullControl'), @('S-1-5-19', 'ReadAndExecute'), @('S-1-5-11', 'ReadAndExecute'))) {
                $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($rule[0]), $rule[1], 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
            }
            # establish administrative ownership at creation, before another process can retain write-dacl access.
            [IO.Directory]::CreateDirectory($installRoot, $acl) | Out-Null
            $createdDirectory = $true
            assertSafeInstallPath
            $sourceHash = (Get-FileHash -LiteralPath $sourceExe -Algorithm SHA256).Hash
            $fileAcl = [Security.AccessControl.FileSecurity]::new()
            $fileAcl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
            $fileAcl.SetAccessRuleProtection($true, $false)
            foreach ($rule in $acl.Access) {
                $fileAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($rule.IdentityReference, $rule.FileSystemRights, 'Allow'))
            }
            $inputStream = [IO.File]::OpenRead($sourceExe)
            try {
                $outputStream = [IO.FileStream]::new($installedExe, [IO.FileMode]::CreateNew, [Security.AccessControl.FileSystemRights]::FullControl, [IO.FileShare]::None, 4096, [IO.FileOptions]::WriteThrough, $fileAcl)
                try { $inputStream.CopyTo($outputStream); $outputStream.Flush($true) } finally { $outputStream.Dispose() }
            } finally { $inputStream.Dispose() }
            if ((Get-FileHash -LiteralPath $installedExe -Algorithm SHA256).Hash -ne $sourceHash) { throw 'Copied service executable checksum mismatch.' }
            $binaryPath = '"' + $installedExe + '" --service --owner-sid ' + $ownerSid
            $credential = [Management.Automation.PSCredential]::new('NT AUTHORITY\LocalService', [Security.SecureString]::new())
            New-Service -Name $serviceName -DisplayName 'estrogen ping patch service' -Description 'Authenticated local read-only service. Network changes and automatic restoration are disabled.' -BinaryPathName $binaryPath -StartupType Automatic -Credential $credential | Out-Null
            $registeredService = $true
            # windows powershell disposes the controller emitted by new-service.
            $service = [ServiceProcess.ServiceController]::new($serviceName)
            $service.Start()
            $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(20))
            Write-Host "Service installed as LocalService for Windows user $ownerSid. Network changes remain disabled."
        }
        'start' {
            if (-not $service) { throw 'The service is not installed. Run install-service.bat first.' }
            $service.Start()
            $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(20))
            Write-Host 'Dedicated service started.'
        }
        { $_ -in @('stop', 'uninstall') } {
            if ($service -and $service.Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped) {
                $service.Stop()
                $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(20))
            }
            if ($action -eq 'uninstall' -and $service) {
                $service.Dispose()
                & (Join-Path ([Environment]::SystemDirectory) 'sc.exe') delete $serviceName
                if ($LASTEXITCODE -ne 0) { throw "Service removal failed with exit code $LASTEXITCODE." }
                $deadline = [DateTime]::UtcNow.AddSeconds(20)
                while (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
                    if ([DateTime]::UtcNow -ge $deadline) { throw 'Service deletion is pending; close Windows Services and retry. The executable was preserved.' }
                    Start-Sleep -Milliseconds 200
                }
                assertSafeInstallPath
                if (Test-Path -LiteralPath $installedExe) { Remove-Item -LiteralPath $installedExe -Force }
                if ((Test-Path -LiteralPath $installRoot) -and [IO.Directory]::GetFileSystemEntries($installRoot).Count -eq 0) { [IO.Directory]::Delete($installRoot) }
            }
            Write-Host "Service action '$action' completed. User backups and measurements were preserved."
        }
    }
    exit 0
} catch {
    Write-Host "ERROR: $($_.Exception.Message)"
    if ($createdDirectory -and -not $registeredService) {
        assertSafeInstallPath
        if (Test-Path -LiteralPath $installedExe) { Remove-Item -LiteralPath $installedExe -Force }
        if ((Test-Path -LiteralPath $installRoot) -and [IO.Directory]::GetFileSystemEntries($installRoot).Count -eq 0) { [IO.Directory]::Delete($installRoot) }
    }
    if (-not $env:CI -and -not $env:EPP_NO_PAUSE) {
        Add-Type -AssemblyName System.Windows.Forms
        [Windows.Forms.MessageBox]::Show($_.Exception.Message, 'estrogen ping patch service', 'OK', 'Error') | Out-Null
    }
    exit 1
}
