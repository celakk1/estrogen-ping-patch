param(
    [switch]$allowNetworkChanges,
    [string]$executablePath = (Join-Path $PSScriptRoot '..\target\native-mtu-lab\release\epp-network-service.exe')
)

$ErrorActionPreference = 'Stop'
$env:PSModulePath = "$PSHOME\Modules;$env:ProgramFiles\WindowsPowerShell\Modules"
if (-not $allowNetworkChanges -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'Native MTU tests create a disposable loopback adapter and require explicit -allowNetworkChanges on a GitHub-hosted Windows runner. Development-machine execution is refused.'
}
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'The native lab requires an already elevated disposable account; it never requests elevation.' }
$executablePath = (Resolve-Path -LiteralPath $executablePath).Path
$serviceName = 'EstrogenPingPatchMtuLab'
$installRoot = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'estrogen ping patch mtu lab'
$dataRoot = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'estrogen-ping-patch-mtu-lab'
$installedExe = Join-Path $installRoot 'epp-network-service.exe'
$sc = Join-Path ([Environment]::SystemDirectory) 'sc.exe'
if ((Get-Service -Name $serviceName -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath $installRoot) -or (Test-Path -LiteralPath $dataRoot)) { throw 'Existing lab service or recovery storage found; use a fresh disposable runner.' }
foreach ($device in @(Get-PnpDevice -Class Net -PresentOnly)) {
    $ids = (Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName DEVPKEY_Device_HardwareIds -ErrorAction SilentlyContinue).Data
    if (@($ids | Where-Object { $_ -ieq '*msloop' }).Count -gt 0) { throw 'An existing Microsoft loopback adapter was found; refusing global driver matching.' }
}
Add-Type -Path (Join-Path $PSScriptRoot 'native-mtu-lab-device.cs')
$ownerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$instanceId = $null
$serviceCreated = $false
$evidence = @()

function invokeSc([string[]]$arguments) {
    $output = & $sc @arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "SCM lab operation failed ($LASTEXITCODE): $($output -join ' ')" }
}

function waitStopped {
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $service = Get-Service -Name $serviceName
        if ($service.Status -eq 'Stopped') { return }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Native lab service did not stop within 30 seconds.'
}

function readEvents([DateTime]$after, [string]$trialId) {
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = $after } -ErrorAction SilentlyContinue | Where-Object { $_.ProviderName -eq $serviceName })
    foreach ($entry in $events) {
        if ($entry.Properties.Count -gt 0) {
            try {
                $value = [string]$entry.Properties[0].Value | ConvertFrom-Json
                if ($value.trialId -eq $trialId) { $value }
            } catch { throw "Malformed native lab event at record $($entry.RecordId)." }
        }
    }
}

function waitEvent([DateTime]$after, [string]$trialId, [string]$phase, [string]$purpose) {
    $deadline = [DateTime]::UtcNow.AddSeconds(40)
    do {
        $events = @(readEvents $after $trialId)
        $errors = @($events | Where-Object { $_.phase -in @('error', 'applyFailed', 'recoveryIncomplete') })
        if ($errors.Count -gt 0) { throw "Native lab failed: $($errors | ConvertTo-Json -Depth 8 -Compress)" }
        $found = @($events | Where-Object { $_.phase -eq $phase -and (-not $purpose -or $_.purpose -eq $purpose) })
        if ($found.Count -gt 0) { return $found[0] }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Native lab event '$phase/$purpose' was not observed; service state: $((Get-Service $serviceName).Status)."
}

function captureNative([Guid]$guid, [string]$family) {
    $json = & $installedExe --inspect-mtu $guid.ToString('D') $family
    if ($LASTEXITCODE -ne 0) { throw "Native $family interface inspection failed." }
    ($json -join "`n") | ConvertFrom-Json
}

function settingsJson([object]$settings) {
    if ($null -eq $settings) { throw 'Native interface settings are missing.' }
    $ordered = [ordered]@{}
    foreach ($property in @($settings.PSObject.Properties | Sort-Object Name -CaseSensitive)) {
        $ordered[$property.Name] = $property.Value
    }
    $ordered | ConvertTo-Json -Depth 4 -Compress
}

function persistentPolicy([int]$interfaceIndex) {
    $rows = @(Get-NetIPInterface -InterfaceIndex $interfaceIndex -PolicyStore PersistentStore | Sort-Object AddressFamily | Select-Object AddressFamily, NlMtu, InterfaceMetric, AutomaticMetric, Dhcp, RouterDiscovery, Forwarding, WeakHostSend, WeakHostReceive, Advertising, ManagedAddressConfiguration, OtherStatefulConfiguration)
    if ($rows.Count -ne 2) { throw 'Both persistent address-family rows are required for the native lab.' }
    $rows | ConvertTo-Json -Depth 6 -Compress
}

function dnsPolicy([Guid]$guid, [int]$interfaceIndex) {
    $registry = @()
    foreach ($stack in @('Tcpip', 'Tcpip6')) {
        $path = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$stack\Parameters\Interfaces\$($guid.ToString('B'))"
        if (-not (Test-Path -LiteralPath $path)) {
            $registry += [ordered]@{ stack = $stack; keyPresent = $false; values = @() }
            continue
        }
        $key = Get-Item -LiteralPath $path
        $values = @()
        try {
            foreach ($name in @('NameServer', 'DhcpNameServer', 'ProfileNameServer', 'Dhcpv6DNSServers')) {
                $present = @($key.GetValueNames()) -contains $name
                $values += [ordered]@{ name = $name; present = $present; kind = $(if ($present) { $key.GetValueKind($name).ToString() } else { $null }); value = $(if ($present) { $key.GetValue($name) } else { $null }) }
            }
        } finally { $key.Dispose() }
        $registry += [ordered]@{ stack = $stack; keyPresent = $true; values = $values }
    }
    [ordered]@{ registry = $registry; addresses = @(Get-DnsClientServerAddress -InterfaceIndex $interfaceIndex | Sort-Object AddressFamily | Select-Object AddressFamily, ServerAddresses) } | ConvertTo-Json -Depth 8 -Compress
}

try {
    $instanceId = [NativeMtuLabDevice]::create()
    $deadline = [DateTime]::UtcNow.AddSeconds(45)
    do {
        $adapters = @(Get-NetAdapter -IncludeHidden | Where-Object { $_.PnPDeviceID -eq $instanceId })
        if ($adapters.Count -eq 1 -and @(Get-NetIPInterface -InterfaceIndex $adapters[0].ifIndex -ErrorAction SilentlyContinue).Count -eq 2) { break }
        Start-Sleep -Milliseconds 300
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($adapters.Count -ne 1) { throw 'Newly created loopback adapter was not uniquely discovered.' }
    $adapter = $adapters[0]
    $guid = [Guid]$adapter.InterfaceGuid
    $interfaceIndex = [int]$adapter.ifIndex
    Rename-NetAdapter -InputObject $adapter -NewName "epp-mtu-lab-$($guid.ToString('D'))"
    if (@(Get-NetRoute -InterfaceIndex $interfaceIndex | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0', '::/0') }).Count -ne 0) { throw 'Disposable adapter unexpectedly owns a default route.' }
    $binaryAcl = [Security.AccessControl.DirectorySecurity]::new()
    $binaryAcl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    [IO.Directory]::CreateDirectory($installRoot, $binaryAcl) | Out-Null
    $fileAcl = [Security.AccessControl.FileSecurity]::new()
    $fileAcl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)')
    $inputStream = [IO.File]::OpenRead($executablePath)
    try {
        $outputStream = [IO.FileStream]::new($installedExe, [IO.FileMode]::CreateNew, [Security.AccessControl.FileSystemRights]::FullControl, [IO.FileShare]::None, 4096, [IO.FileOptions]::WriteThrough, $fileAcl)
        try { $inputStream.CopyTo($outputStream); $outputStream.Flush($true) } finally { $outputStream.Dispose() }
    } finally { $inputStream.Dispose() }
    if ((Get-FileHash -LiteralPath $executablePath).Hash -ne (Get-FileHash -LiteralPath $installedExe).Hash) { throw 'Protected lab service binary hash differs.' }
    $seedTrialId = [Guid]::NewGuid().ToString('D')
    $seedImagePath = "`"$installedExe`" --native-mtu-lab-service $ownerSid $($guid.ToString('D')) ipv4 complete $seedTrialId"
    New-Service -Name $serviceName -DisplayName 'estrogen ping patch native MTU lab' -BinaryPathName $seedImagePath -StartupType Manual | Out-Null
    $serviceCreated = $true
    invokeSc -arguments @('sidtype', $serviceName, 'unrestricted')
    invokeSc -arguments @('privs', $serviceName, 'SeChangeNotifyPrivilege')
    $serviceSid = [Security.Principal.NTAccount]::new("NT SERVICE\$serviceName").Translate([Security.Principal.SecurityIdentifier]).Value
    $dataAcl = [Security.AccessControl.DirectorySecurity]::new()
    $dataAcl.SetSecurityDescriptorSddlForm("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;$serviceSid)(A;OICI;RC;;;OW)")
    [IO.Directory]::CreateDirectory($dataRoot, $dataAcl) | Out-Null
    $dnsBefore = dnsPolicy $guid $interfaceIndex
    $policyBefore = persistentPolicy $interfaceIndex
    foreach ($family in @('ipv4', 'ipv6')) {
        $original = captureNative $guid $family
        if ($original.driver.status -ne 'captured' -or $original.driver.identity.infPath -ine 'netloop.inf' -or $original.driver.identity.deviceInstanceId -ine $instanceId) { throw 'Native evidence does not match the newly created loopback device.' }
        Write-Host "Native pre-trial evidence: family=$family; MTU=$($original.settings.nlMtu); SitePrefixLength=$($original.settings.sitePrefixLength)."
        foreach ($phase in @('complete', 'apply', 'restore')) {
            $trialId = [Guid]::NewGuid().ToString('D')
            $imagePath = "`"$installedExe`" --native-mtu-lab-service $ownerSid $($guid.ToString('D')) $family $phase $trialId"
            $registered = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
            $configured = Invoke-CimMethod -InputObject $registered -MethodName Change -Arguments @{ PathName = $imagePath }
            if ($configured.ReturnValue -ne 0) { throw "SCM lab configuration failed: $($configured.ReturnValue)" }
            $registered = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
            if ($registered.PathName -cne $imagePath) { throw 'SCM did not preserve the quoted, fixed lab executable path.' }
            $startedAt = Get-Date
            invokeSc -arguments @('start', $serviceName)
            if ($phase -ne 'complete') {
                $purpose = $(if ($phase -eq 'apply') { 'Apply' } else { 'Restore' })
                $written = waitEvent $startedAt $trialId 'nativeWriteReturned' $purpose
                $live = captureNative $guid $family
                $expected = $(if ($phase -eq 'apply') { 1400 } else { $original.settings.nlMtu })
                if ($live.settings.nlMtu -ne $expected) { throw 'Native write marker does not match independently read effective MTU.' }
                if ((persistentPolicy $interfaceIndex) -cne $policyBefore) { throw 'Native setter changed persistent policy during the interrupted trial.' }
                $registered = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
                if ($registered.ProcessId -ne $written.processId -or $registered.StartName -ne 'LocalSystem') { throw 'Crash target does not match the dedicated lab service.' }
                Stop-Process -Id $registered.ProcessId -Force
                waitStopped
                invokeSc -arguments @('start', $serviceName)
            }
            $complete = waitEvent $startedAt $trialId 'complete' ''
            waitStopped
            $current = captureNative $guid $family
            if ($complete.state -ne 'restored' -or $complete.pendingRecoveryCount -ne 0 -or $current.settings.nlMtu -ne $original.settings.nlMtu -or (settingsJson $current.settings) -cne (settingsJson $original.settings)) { throw 'Native recovery failed exact MTU/unrelated-settings verification.' }
            if ((settingsJson $complete.original.settings) -cne (settingsJson $original.settings)) { throw 'Durable native original does not match the independent pre-trial capture.' }
            if ((persistentPolicy $interfaceIndex) -cne $policyBefore -or (dnsPolicy $guid $interfaceIndex) -cne $dnsBefore) { throw 'Native trial changed persistent interface or automatic/static DNS origin values.' }
            $expectedWrites = $(if ($phase -eq 'complete') { 2 } elseif ($phase -eq 'apply') { 1 } else { 0 })
            if ($complete.writesThisProcess -ne $expectedWrites) { throw 'Restart recovery wrote an unexpected number of MTU values.' }
            $evidence += @{ family = $family; phase = $phase; originalMtu = $original.settings.nlMtu; finalMtu = $current.settings.nlMtu; state = $complete.state; writesAfterRestart = $complete.writesThisProcess }
        }
    }
    Write-Host 'Native MTU lab passed: exact IPv4/IPv6 restore, process termination during apply/restore, preserved unrelated fields, persistent policy, and DNS origin values on an owned Microsoft loopback adapter.'
    $evidence | ConvertTo-Json -Depth 5
} finally {
    if ($serviceCreated) {
        $service = Get-Service $serviceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -ne 'Stopped') { Stop-Service $serviceName; waitStopped }
        invokeSc -arguments @('delete', $serviceName)
    }
    if ($instanceId) { [NativeMtuLabDevice]::remove($instanceId) }
    if (Test-Path -LiteralPath $installedExe) { Remove-Item -LiteralPath $installedExe -Force }
    if ((Test-Path -LiteralPath $installRoot) -and @(Get-ChildItem -LiteralPath $installRoot -Force).Count -eq 0) { Remove-Item -LiteralPath $installRoot -Force }
    Write-Host "Native lab recovery evidence retained at $dataRoot."
}
