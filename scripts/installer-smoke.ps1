param([Parameter(Mandatory = $true)][string]$installerPath)

$ErrorActionPreference = 'Stop'
$installerPath = (Resolve-Path -LiteralPath $installerPath).Path
$installDirectory = Join-Path ([IO.Path]::GetTempPath()) ('epp-installed-smoke-' + [Guid]::NewGuid().ToString('N'))
$shortcutDirectory = Join-Path ([Environment]::GetFolderPath('StartMenu')) 'Programs\estrogen ping patch'
if (Test-Path -LiteralPath $shortcutDirectory) { throw 'An existing Start menu installation was found. Run installer smoke tests in an isolated Windows account instead.' }
$application = $null
$installed = $false
$previousDataDirectory = $env:EPP_DATA_DIR
$env:EPP_DATA_DIR = Join-Path $installDirectory 'test-data'

try {
    $installer = Start-Process -FilePath $installerPath -ArgumentList "/S /D=$installDirectory" -WindowStyle Hidden -PassThru
    if (-not $installer.WaitForExit(60000)) { throw 'Installer did not exit within 60 seconds.' }
    if ($installer.ExitCode -ne 0) { throw "Installer failed with exit code $($installer.ExitCode)." }
    $installed = $true
    $executablePath = Join-Path $installDirectory 'estrogen-ping-patch.exe'
    if (-not (Test-Path -LiteralPath $executablePath)) { throw 'Installer did not produce the expected desktop executable.' }
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
        if ($application.HasExited) { throw 'Installed desktop application exited before opening its window.' }
    } while (-not $application.MainWindowHandle -and [DateTime]::UtcNow -lt $deadline)
    if (-not $application.MainWindowHandle) { throw 'Installed desktop application did not open its GUI.' }
    if ($application.MainWindowTitle -ne 'estrogen ping patch') { throw 'Installed desktop title was unexpected.' }
    Write-Host 'Installer smoke passed: per-user install, Windows GUI subsystem, Start menu shortcut, and desktop window.'
} finally {
    $env:EPP_DATA_DIR = $previousDataDirectory
    if ($null -ne $application -and -not $application.HasExited) {
        [void]$application.CloseMainWindow()
        if (-not $application.WaitForExit(10000)) { throw 'Test application did not close; preserve the test installation for inspection.' }
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
