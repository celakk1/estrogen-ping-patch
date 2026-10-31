$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)

function readFields {
    param($row, [string[]]$fields)
    $record = [ordered]@{}
    $unavailableFields = [Collections.Generic.List[string]]::new()
    foreach ($field in $fields) {
        $property = $row.CimInstanceProperties[$field]
        if ($null -eq $property) { $record[$field] = $null; $unavailableFields.Add($field); continue }
        $value = $property.Value
        if ($value -is [Array]) { $record[$field] = @($value | ForEach-Object { $_ }) } else { $record[$field] = $value }
    }
    $record['unavailableFields'] = @($unavailableFields.ToArray())
    return $record
}

function readSection {
    param([string]$name, [string]$adapterId, [scriptblock]$reader)
    try {
        $values = @(& $reader)
        return [ordered]@{ name = $name; adapterId = $adapterId; status = 'captured'; values = $values; error = $null }
    } catch {
        return [ordered]@{ name = $name; adapterId = $adapterId; status = 'unavailable'; values = @(); error = $_.Exception.Message }
    }
}

$sections = [Collections.Generic.List[object]]::new()
$sections.Add((readSection 'ipAddresses' '' { Get-NetIPAddress | ForEach-Object { readFields $_ @('InterfaceIndex','AddressFamily','IPAddress','PrefixLength','PrefixOrigin','SuffixOrigin','SkipAsSource','Type') } }))
$sections.Add((readSection 'ipInterfaces' '' { Get-NetIPInterface | ForEach-Object { readFields $_ @('InterfaceIndex','AddressFamily','Dhcp','NlMtu','InterfaceMetric','AutomaticMetric','RouterDiscovery','Forwarding','WeakHostSend','WeakHostReceive') } }))
$sections.Add((readSection 'routes' '' { Get-NetRoute | ForEach-Object { readFields $_ @('InterfaceIndex','AddressFamily','DestinationPrefix','NextHop','RouteMetric','Protocol','Publish','ValidLifetime','PreferredLifetime') } }))
$sections.Add((readSection 'dnsServers' '' { Get-DnsClientServerAddress | ForEach-Object { readFields $_ @('InterfaceIndex','AddressFamily','ServerAddresses') } }))
$sections.Add((readSection 'dnsClient' '' { Get-DnsClient | ForEach-Object { readFields $_ @('InterfaceIndex','ConnectionSpecificSuffix','RegisterThisConnectionsAddress','UseSuffixWhenRegistering') } }))
$sections.Add((readSection 'tcpTemplates' '' { Get-NetTCPSetting | ForEach-Object { readFields $_ @('SettingName','AutoTuningLevelLocal','AutoTuningLevelGroupPolicy','AutoTuningLevelEffective','CongestionProvider','EcnCapability','Timestamps','ScalingHeuristics','MinRtoMs','InitialCongestionWindowMss') } }))

foreach ($adapter in @(Get-NetAdapter -IncludeHidden)) {
    $adapterId = $adapter.InterfaceGuid.ToString()
    $adapterDescription = $adapter.InterfaceDescription
    $sections.Add((readSection 'driverAdvancedProperties' $adapterId { Get-NetAdapterAdvancedProperty -InterfaceDescription $adapterDescription -AllProperties -IncludeHidden | ForEach-Object { readFields $_ @('RegistryKeyword','RegistryValue','RegistryDataType','DisplayName','DisplayValue','ValidRegistryValues','ValidDisplayValues') } }))
    $sections.Add((readSection 'rss' $adapterId { Get-NetAdapterRss -InterfaceDescription $adapterDescription -IncludeHidden | ForEach-Object { readFields $_ @('Enabled','NumberOfReceiveQueues','Profile','BaseProcessorGroup','BaseProcessorNumber','MaxProcessorGroup','MaxProcessorNumber','MaxProcessors') } }))
    $sections.Add((readSection 'rsc' $adapterId { Get-NetAdapterRsc -InterfaceDescription $adapterDescription -IncludeHidden | ForEach-Object { readFields $_ @('IPv4Enabled','IPv6Enabled') } }))
    $sections.Add((readSection 'powerManagement' $adapterId { Get-NetAdapterPowerManagement -InterfaceDescription $adapterDescription -IncludeHidden | ForEach-Object { readFields $_ @('AllowComputerToTurnOffDevice','D0PacketCoalescing','DeviceSleepOnDisconnect','SelectiveSuspend','WakeOnMagicPacket','WakeOnPattern') } }))
}

[ordered]@{ capturedAt = [DateTime]::UtcNow.ToString('o'); sections = @($sections.ToArray()) } | ConvertTo-Json -Depth 12 -Compress
