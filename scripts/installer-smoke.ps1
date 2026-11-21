param([Parameter(Mandatory = $true)][string]$installerPath)

$ErrorActionPreference = 'Stop'
$installerPath = (Resolve-Path -LiteralPath $installerPath).Path
$installDirectory = Join-Path ([IO.Path]::GetTempPath()) ('epp-installed-smoke-' + [Guid]::NewGuid().ToString('N'))
$shortcutDirectory = Join-Path ([Environment]::GetFolderPath('StartMenu')) 'Programs\estrogen ping patch'
if (Test-Path -LiteralPath $shortcutDirectory) { throw 'An existing Start menu installation was found. Run installer smoke tests in an isolated Windows account instead.' }
$application = $null
$installed = $false
$previousDataDirectory = $env:EPP_DATA_DIR
$previousWebViewDirectory = $env:WEBVIEW2_USER_DATA_FOLDER
$env:EPP_DATA_DIR = Join-Path $installDirectory 'test-data'
$env:WEBVIEW2_USER_DATA_FOLDER = Join-Path $installDirectory 'webview-profile'

try {
    $installer = Start-Process -FilePath $installerPath -ArgumentList "/S /D=$installDirectory" -WindowStyle Hidden -PassThru
    if (-not $installer.WaitForExit(60000)) { throw 'Installer did not exit within 60 seconds.' }
    if ($installer.ExitCode -ne 0) { throw "Installer failed with exit code $($installer.ExitCode)." }
    $installed = $true
    $executablePath = Join-Path $installDirectory 'estrogen-ping-patch.exe'
    if (-not (Test-Path -LiteralPath $executablePath)) { throw 'Installer did not produce the expected desktop executable.' }
    foreach ($resource in @('service\epp-network-service.exe', 'service\manage-service.ps1', 'install-service.bat', 'uninstall-service.bat')) {
        if (-not (Test-Path -LiteralPath (Join-Path $installDirectory $resource) -PathType Leaf)) { throw "Installer omitted service resource: $resource" }
    }
    $sourceFiles = @{
        'iconoir-license.txt' = (Join-Path $PSScriptRoot '..\assets\iconoir-license.txt')
        'service\epp-network-service.exe' = (Join-Path $PSScriptRoot '..\target\release\epp-network-service.exe')
        'service\manage-service.ps1' = (Join-Path $PSScriptRoot 'manage-service.ps1')
        'install-service.bat' = (Join-Path $PSScriptRoot '..\install-service.bat')
        'uninstall-service.bat' = (Join-Path $PSScriptRoot '..\uninstall-service.bat')
    }
    foreach ($resource in $sourceFiles.Keys) {
        if ((Get-FileHash -LiteralPath $sourceFiles[$resource] -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath (Join-Path $installDirectory $resource) -Algorithm SHA256).Hash) { throw "Installed service resource does not match the checked build: $resource" }
    }
    $bytes = [IO.File]::ReadAllBytes($executablePath)
    $peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
    $subsystem = [BitConverter]::ToUInt16($bytes, $peOffset + 4 + 20 + 68)
    if ($subsystem -ne 2) { throw 'Production executable does not use the Windows GUI subsystem.' }
    $shortcutPath = Join-Path $shortcutDirectory 'estrogen ping patch.lnk'
    if (-not (Test-Path -LiteralPath $shortcutPath)) { throw 'Installer did not create its Start menu shortcut.' }
    $shortcut = (New-Object -ComObject WScript.Shell).CreateShortcut($shortcutPath)
    if (-not $shortcut.TargetPath.Equals($executablePath, [StringComparison]::OrdinalIgnoreCase)) { throw 'Start menu shortcut targets an unexpected executable.' }
    $application = Start-Process -FilePath $shortcutPath -WindowStyle Normal -PassThru
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        Start-Sleep -Milliseconds 200
        $application.Refresh()
        if ($application.HasExited) { throw "Installed desktop application exited before opening its window (exit code: $($application.ExitCode))." }
    } while (-not $application.MainWindowHandle -and [DateTime]::UtcNow -lt $deadline)
    if (-not $application.MainWindowHandle) { throw 'Installed desktop application did not open its GUI.' }
    if ($application.MainWindowTitle -ne 'estrogen ping patch') { throw 'Installed desktop title was unexpected.' }
    Write-Host 'Installer smoke passed: per-user install, Windows GUI subsystem, Start menu shortcut, and desktop window.'
} finally {
    $env:EPP_DATA_DIR = $previousDataDirectory
    $env:WEBVIEW2_USER_DATA_FOLDER = $previousWebViewDirectory
    if ($null -ne $application -and -not $application.HasExited) {
        $shutdownDeadline = [DateTime]::UtcNow.AddSeconds(45)
        $closeRequestAccepted = $false
        do {
            $application.Refresh()
            if ($application.HasExited) { break }
            # windows can reject close requests while the owner window is disabled.
            if (-not $closeRequestAccepted) { $closeRequestAccepted = $application.CloseMainWindow() }
            if ($application.WaitForExit(250)) { break }
        } while ([DateTime]::UtcNow -lt $shutdownDeadline)
        Write-Host "Shutdown request accepted: $closeRequestAccepted. Test process exited: $($application.HasExited)."
        if (-not $application.HasExited) { throw "Test application did not close within its shutdown deadline (close request accepted: $closeRequestAccepted); preserve the test installation for inspection." }
    }
    if ($installed) {
        $uninstallerPath = Join-Path $installDirectory 'uninstall.exe'
        if (Test-Path -LiteralPath $uninstallerPath) {
            # keep nsis in this process so its exit code covers the full uninstall.
            $uninstaller = Start-Process -FilePath $uninstallerPath -ArgumentList "/S _?=$installDirectory" -WindowStyle Hidden -PassThru
            if (-not $uninstaller.WaitForExit(60000) -or $uninstaller.ExitCode -ne 0) { throw 'Test uninstallation failed; inspect the temporary installation.' }
            if (Test-Path -LiteralPath $executablePath) { throw 'Uninstaller left the test executable installed.' }
            if (Test-Path -LiteralPath $shortcutPath) { throw 'Uninstaller left the test Start menu shortcut installed.' }
            Write-Host 'Test uninstallation passed: executable and shortcut removed; original user data was not used.'
        } else { throw 'Test installation has no uninstaller; preserve it for inspection.' }
    }
}
