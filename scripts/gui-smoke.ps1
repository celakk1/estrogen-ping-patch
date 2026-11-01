param([string]$executablePath = (Join-Path $PSScriptRoot '..\target\release\estrogen-ping-patch.exe'))

$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if (-not (Test-Path -LiteralPath $executablePath -PathType Leaf)) { throw 'Build the production desktop with build.bat before running this smoke check.' }
$executablePath = (Resolve-Path -LiteralPath $executablePath).Path
if (-not (Get-Command node.exe -ErrorAction SilentlyContinue)) { throw 'Node.js is required; run setup.bat first.' }
$testDirectory = Join-Path ([IO.Path]::GetTempPath()) ('epp-gui-smoke-' + [Guid]::NewGuid().ToString('N'))
$previousEnvironment = @{}
foreach ($name in @('EPP_DATA_DIR', 'EPP_CDP_URL', 'WEBVIEW2_USER_DATA_FOLDER', 'WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS')) {
    $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
$application = $null
$portListener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
Push-Location -LiteralPath $projectRoot
try {
    $portListener.Start()
    $port = $portListener.LocalEndpoint.Port
    $portListener.Stop()
    $env:EPP_DATA_DIR = Join-Path $testDirectory 'data'
    $env:WEBVIEW2_USER_DATA_FOLDER = Join-Path $testDirectory 'webview'
    $env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = "--remote-debugging-port=$port"
    $env:EPP_CDP_URL = "http://127.0.0.1:$port"
    $application = Start-Process -FilePath $executablePath -WindowStyle Hidden -PassThru
    $deadline = [DateTime]::UtcNow.AddSeconds(45)
    $ready = $false
    do {
        $application.Refresh()
        if ($application.HasExited) { throw "Test desktop exited before startup (exit code: $($application.ExitCode))." }
        try {
            $request = [Net.HttpWebRequest]::Create("$env:EPP_CDP_URL/json/version")
            $request.Timeout = 1000
            $request.Proxy = $null
            $response = $request.GetResponse()
            $response.Dispose()
            $ready = $true
        } catch {
            Start-Sleep -Milliseconds 200
        }
    } while (-not $ready -and [DateTime]::UtcNow -lt $deadline)
    if (-not $ready) { throw 'Test WebView2 debugging endpoint did not become ready within 45 seconds.' }
    foreach ($script in @('desktop-smoke.mjs', 'load-smoke.mjs', 'packet-smoke.mjs', 'backup-smoke.mjs')) {
        & node.exe (Join-Path $PSScriptRoot $script)
        if ($LASTEXITCODE -ne 0) { throw "$script failed with exit code $LASTEXITCODE. Test data retained at $testDirectory" }
    }
    Write-Host "Packaged GUI smoke passed with isolated data: $testDirectory"
} finally {
    $portListener.Stop()
    foreach ($name in $previousEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], 'Process')
    }
    Pop-Location
    if ($null -ne $application -and -not $application.HasExited) {
        $deadline = [DateTime]::UtcNow.AddSeconds(45)
        $accepted = $false
        do {
            $application.Refresh()
            if ($application.HasExited) { break }
            if (-not $accepted) { $accepted = $application.CloseMainWindow() }
            if ($application.WaitForExit(250)) { break }
        } while ([DateTime]::UtcNow -lt $deadline)
        if (-not $application.HasExited) { throw "Test desktop did not close; inspect process $($application.Id) and $testDirectory" }
    }
}
