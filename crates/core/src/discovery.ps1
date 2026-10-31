$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$adapters = @(Get-NetAdapter -IncludeHidden | Select-Object @{n='interfaceIndex';e={$_.ifIndex}}, @{n='id';e={$_.InterfaceGuid.ToString()}}, @{n='name';e={$_.Name}}, @{n='description';e={$_.InterfaceDescription}}, @{n='status';e={$_.Status.ToString()}}, @{n='linkSpeed';e={$_.LinkSpeed}}, @{n='mediaType';e={$_.MediaType.ToString()}}, @{n='physical';e={$_.HardwareInterface}}, @{n='driverVersion';e={$_.DriverVersionString}})
$routes = @(Get-NetRoute -ErrorAction Stop | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','::/0') } | Select-Object @{n='interfaceIndex';e={$_.InterfaceIndex}}, @{n='nextHop';e={$_.NextHop}}, @{n='routeMetric';e={$_.RouteMetric}}, @{n='destination';e={$_.DestinationPrefix}})
$interfaces = @(Get-NetIPInterface | Select-Object @{n='interfaceIndex';e={$_.InterfaceIndex}}, @{n='addressFamily';e={$_.AddressFamily.ToString()}}, @{n='mtu';e={$_.NlMtu}}, @{n='metric';e={$_.InterfaceMetric}}, @{n='dhcp';e={$_.Dhcp.ToString()}}, @{n='state';e={$_.ConnectionState.ToString()}})
$dns = @(Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses.Count -gt 0 } | ForEach-Object { [ordered]@{ interfaceIndex = [int]$_.InterfaceIndex; servers = [string[]]$_.ServerAddresses } })
$os = Get-CimInstance Win32_OperatingSystem
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
[ordered]@{
    capturedAt = [DateTime]::UtcNow.ToString('o')
    os = [ordered]@{ version = $os.Version; build = $os.BuildNumber; architecture = $os.OSArchitecture; elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
    adapters = $adapters
    routes = $routes
    interfaces = $interfaces
    dns = $dns
    limitations = @('Inventory is read-only. No system settings have been changed.', 'VPN, management policy, battery state, and advanced driver capabilities require additional discovery before modifications are permitted.')
} | ConvertTo-Json -Depth 8 -Compress
