param(
    [string]$executablePath = (Join-Path $PSScriptRoot '..\target\release\epp-network-service.exe'),
    [Guid]$adapterGuid = [Guid]::Empty
)

$ErrorActionPreference = 'Stop'
$executablePath = (Resolve-Path -LiteralPath $executablePath).Path
$env:PSModulePath = "$PSHOME\Modules;$env:ProgramFiles\WindowsPowerShell\Modules"
$adapter = if ($adapterGuid -eq [Guid]::Empty) {
    Get-NetAdapter -IncludeHidden | Where-Object Status -eq 'Up' | Select-Object -First 1
} else {
    $adapters = @(Get-NetAdapter -IncludeHidden | Where-Object { ([Guid]$_.InterfaceGuid) -eq $adapterGuid })
    if ($adapters.Count -ne 1) { throw 'The explicitly selected policy adapter was not uniquely discovered.' }
    $adapters[0]
}
if ($null -eq $adapter) { throw 'Read-only policy validation requires a connected adapter.' }
$guid = ([Guid]$adapter.InterfaceGuid).ToString('D')
$workDirectory = Join-Path ([IO.Path]::GetTempPath()) ('epp-policy-smoke-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($workDirectory) | Out-Null
$types = @{ UInt8 = 17; UInt16 = 18; UInt32 = 19 }
$fieldNames = @('NlMtu', 'InterfaceMetric', 'AutomaticMetric', 'Dhcp', 'RouterDiscovery', 'Forwarding', 'WeakHostSend', 'WeakHostReceive', 'Advertising', 'ManagedAddressConfiguration', 'OtherStatefulConfiguration')
$verifiedFields = 0

foreach ($family in @('ipv4', 'ipv6')) {
    $outputPath = Join-Path $workDirectory "$family.json"
    $errorPath = Join-Path $workDirectory "$family.stderr.txt"
    $process = $null
    try {
        $process = Start-Process -FilePath $executablePath -ArgumentList @('--inspect-ip-policy', $guid, $family) -PassThru -WindowStyle Hidden -RedirectStandardOutput $outputPath -RedirectStandardError $errorPath
        # retain the handle before a fast worker exits so windows powershell can read its exit code.
        $null = $process.Handle
        if (-not $process.WaitForExit(25000)) { throw 'The isolated policy reader exceeded its twenty-five-second outer allowance, including worker cleanup.' }
        if ($process.ExitCode -ne 0) { throw "The read-only policy worker failed: $(Get-Content -LiteralPath $errorPath -Raw)" }
        if ((Get-Item -LiteralPath $outputPath).Length -gt 65536) { throw 'The read-only policy worker exceeded its 64-KiB evidence bound.' }
        $capture = Get-Content -LiteralPath $outputPath -Raw | ConvertFrom-Json
        if ($capture.schemaVersion -ne 1 -or $capture.native.schemaVersion -ne 2 -or $capture.native.adapterGuid -cne $guid -or $capture.native.addressFamily -cne $family -or $capture.native.interfaceIndex -ne $adapter.ifIndex) { throw 'The policy worker returned a different schema, adapter, or family.' }
        foreach ($store in @('ActiveStore', 'PersistentStore')) {
            $rows = @(Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily $family -PolicyStore $store)
            $record = $(if ($store -eq 'ActiveStore') { $capture.active } else { $capture.persistent })
            if ($rows.Count -eq 0) {
                if ($null -ne $record) { throw 'The policy worker invented an absent policy row.' }
                continue
            }
            if ($rows.Count -ne 1 -or $null -eq $record) { throw 'Policy row presence disagrees with the independent reader.' }
            $row = $rows[0]
            if ($record.interfaceIndex -ne $adapter.ifIndex -or $record.addressFamily -ne $row.CimInstanceProperties['AddressFamily'].Value -or $record.store -ne $row.CimInstanceProperties['Store'].Value) { throw 'Policy row identity disagrees with the independent reader.' }
            if ($record.compartmentId.value -ne $row.CimInstanceProperties['CompartmentId'].Value) { throw 'Policy compartment disagrees with the independent reader.' }
            $names = @($record.values.PSObject.Properties.Name)
            if ($names.Count -ne $fieldNames.Count -or @(Compare-Object $names $fieldNames -CaseSensitive).Count -ne 0) { throw 'The policy worker substituted or omitted expected fields.' }
            foreach ($name in $fieldNames) {
                $expected = $row.CimInstanceProperties[$name]
                $actual = $record.values.PSObject.Properties[$name].Value
                if ($null -eq $expected -or -not $types.ContainsKey($expected.CimType.ToString()) -or $types[$expected.CimType.ToString()] -ne $actual.cimType) { throw "Policy CIM type differs for $name." }
                if (($null -eq $expected.Value) -ne ($null -eq $actual.value)) { throw "Policy null value differs for $name." }
                if ($null -ne $expected.Value -and [UInt32]$expected.Value -ne [UInt32]$actual.value) { throw "Policy value differs for $name." }
                $verifiedFields++
            }
        }
    } finally {
        if ($null -ne $process) {
            if (-not $process.HasExited) {
                $process.Kill()
                if (-not $process.WaitForExit(5000)) { throw "Read-only policy worker exit could not be verified; inspect process $($process.Id)." }
            }
            $process.Dispose()
        }
    }
}
Write-Host "Read-only IP policy smoke passed: two families, $verifiedFields setting fields matched independent cmdlet reads, null/presence and CIM types preserved. No settings changed. Evidence: $workDirectory"
