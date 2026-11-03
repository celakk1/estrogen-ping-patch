param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('launch', 'build', 'test', 'setup', 'clean', 'package')]
    [string]$task
)

$ErrorActionPreference = 'Stop'
# cmd can pass powershell 7 module paths into windows powershell 5.1.
$env:PSModulePath = "$PSHOME\Modules;$env:ProgramFiles\WindowsPowerShell\Modules;$([Environment]::GetFolderPath('MyDocuments'))\WindowsPowerShell\Modules"
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$script:failureCode = 1
$workspaceMutex = $null
$ownsMutex = $false

function invokeChecked {
    param([string]$program, [string[]]$arguments)
    & $program @arguments
    if ($LASTEXITCODE -ne 0) {
        $script:failureCode = $LASTEXITCODE
        throw "$program failed with exit code $LASTEXITCODE. See the error above."
    }
}

function testToolchain {
    foreach ($tool in @('rustc.exe', 'cargo.exe', 'node.exe', 'npm.cmd')) {
        if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
            throw "Missing $tool. Install Rust from https://rustup.rs and Node.js 24 LTS from https://nodejs.org, then reopen this launcher. See docs/setup.md."
        }
    }
    $nodeMajor = [int](& node.exe -p 'parseInt(process.versions.node)')
    if ($nodeMajor -ne 24) { throw 'This project requires Node.js 24 LTS. Install it from https://nodejs.org.' }
    $npmMajor = [int]((& npm.cmd --version).Split('.')[0])
    if ($npmMajor -lt 11 -or $npmMajor -gt 12) { throw 'Use npm 11 or 12, supplied with a current Node.js 24 LTS installation.' }
    $hostTriple = (& rustc.exe -vV | Select-String '^host:').ToString()
    if ($hostTriple -notmatch 'x86_64-pc-windows-msvc') { throw 'Install the Rust x86_64-pc-windows-msvc toolchain with rustup. GNU and ARM builds are not supported by these launchers.' }
    $vswherePath = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswherePath)) { throw 'Install Visual Studio 2022 Build Tools with Desktop development with C++ and the Windows SDK: https://visualstudio.microsoft.com/visual-cpp-build-tools/' }
    $vsPath = & $vswherePath -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $vsPath) { throw 'Visual Studio is missing the C++ x64 tools. Modify Build Tools and select Desktop development with C++ and a Windows SDK.' }
    $webView = @('HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\*', 'HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\*', 'HKCU:\Software\Microsoft\EdgeUpdate\Clients\*') |
        ForEach-Object { Get-ItemProperty -Path $_ -ErrorAction SilentlyContinue } |
        Where-Object { $_.name -match 'WebView2' -and $_.pv -and $_.pv -ne '0.0.0.0' }
    if (-not $webView) { throw 'Install Microsoft Edge WebView2 Evergreen Runtime: https://developer.microsoft.com/microsoft-edge/webview2/ then reopen the launcher.' }
    Write-Host 'Toolchain ready: Rust MSVC x64, Node.js 24, npm, C++ tools, WebView2.'
}

function getDependencyFingerprint {
    $manifestHash = (Get-FileHash -LiteralPath (Join-Path $projectRoot 'package.json') -Algorithm SHA256).Hash
    $lockHash = (Get-FileHash -LiteralPath (Join-Path $projectRoot 'package-lock.json') -Algorithm SHA256).Hash
    $nodeAbi = & node.exe -p 'process.versions.modules'
    return "$manifestHash/$lockHash/$nodeAbi"
}

function installProjectDependencies {
    $stampPath = Join-Path $projectRoot 'node_modules\.epp-dependencies'
    $fingerprint = getDependencyFingerprint
    $needsInstall = -not (Test-Path -LiteralPath $stampPath)
    if (-not $needsInstall) {
        $needsInstall = (Get-Content -LiteralPath $stampPath -Raw).Trim() -ne $fingerprint
    }
    if (-not (Test-Path -LiteralPath (Join-Path $projectRoot 'node_modules\.bin\tauri.cmd'))) { $needsInstall = $true }
    if (-not $needsInstall) {
        & npm.cmd ls --depth=0 --silent *> $null
        $needsInstall = $LASTEXITCODE -ne 0
    }
    if ($needsInstall) {
        Write-Host 'Installing locked JavaScript dependencies with npm ci...'
        invokeChecked 'npm.cmd' @('ci', '--no-audit', '--no-fund')
        Set-Content -LiteralPath $stampPath -Value $fingerprint -Encoding ASCII
    } else {
        Write-Host 'JavaScript dependencies are already installed and match the lockfile.'
    }
}

function buildServiceResources {
    invokeChecked 'cargo.exe' @('build', '--release', '--locked', '-p', 'epp-service')
    $releaseDirectory = Join-Path $projectRoot 'target\release'
    $serviceResources = Join-Path $releaseDirectory 'service'
    New-Item -ItemType Directory -Force -Path $serviceResources | Out-Null
    Copy-Item -LiteralPath (Join-Path $releaseDirectory 'epp-network-service.exe'), (Join-Path $projectRoot 'scripts\manage-service.ps1') -Destination $serviceResources
    Copy-Item -LiteralPath (Join-Path $projectRoot 'install-service.bat'), (Join-Path $projectRoot 'uninstall-service.bat') -Destination $releaseDirectory
}

function removeGeneratedDirectory {
    param([string]$relativePath)
    $targetPath = [IO.Path]::GetFullPath((Join-Path $projectRoot $relativePath))
    if (-not $targetPath.StartsWith($projectRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove a path outside the repository: $targetPath"
    }
    if (Test-Path -LiteralPath $targetPath) {
        $entry = Get-Item -LiteralPath $targetPath -Force
        if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Refusing to clean a linked directory: $targetPath" }
        $linkedChild = Get-ChildItem -LiteralPath $targetPath -Force -Recurse -Attributes ReparsePoint -ErrorAction Stop | Select-Object -First 1
        if ($linkedChild) { throw "Refusing to recurse through a link: $($linkedChild.FullName). Remove the link manually." }
        Remove-Item -LiteralPath $targetPath -Recurse -Force
        Write-Host "Removed $relativePath"
    }
}

try {
    Push-Location -LiteralPath $projectRoot
    if (-not (Test-Path -LiteralPath (Join-Path $projectRoot 'Cargo.toml'))) { throw 'Cannot locate the project root. Keep scripts/dev.ps1 inside the repository.' }
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { $rootHash = [BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($projectRoot.ToUpperInvariant()))).Replace('-', '') } finally { $hasher.Dispose() }
    $workspaceMutex = [Threading.Mutex]::new($false, "Local\epp-workspace-$rootHash")
    try { $ownsMutex = $workspaceMutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $ownsMutex = $true }
    if (-not $ownsMutex) { throw 'Another development task is already running in this checkout. Close its GUI and launcher or wait for it to finish, then rerun this script. Do not run as administrator.' }
    if ($task -eq 'clean') {
        foreach ($generatedPath in @('target', 'dist', 'coverage', '.cache', 'src-tauri\gen')) { removeGeneratedDirectory $generatedPath }
        Write-Host 'Build artifacts removed. Installed dependencies and application data were preserved.'
        exit 0
    }
    testToolchain
    installProjectDependencies
    switch ($task) {
        'setup' {
            invokeChecked 'cargo.exe' @('fetch', '--locked')
            invokeChecked 'npm.cmd' @('run', 'check')
            invokeChecked 'cargo.exe' @('run', '--locked', '-p', 'epp-core', '--bin', 'epp-check')
            Write-Host 'Setup complete. Double-click launch.bat to open the desktop application.'
        }
        'launch' {
            invokeChecked 'cargo.exe' @('run', '--locked', '-p', 'epp-core', '--bin', 'epp-check')
            invokeChecked 'cargo.exe' @('build', '--locked', '-p', 'epp-service')
            invokeChecked 'npm.cmd' @('run', 'tauri', '--', 'dev')
        }
        'build' {
            buildServiceResources
            invokeChecked 'npm.cmd' @('run', 'tauri', '--', 'build', '--no-bundle', '--config', 'src-tauri/service.bundle.json')
            Write-Host 'Executable: target\release\estrogen-ping-patch.exe'
        }
        'test' {
            invokeChecked 'npm.cmd' @('run', 'format:check')
            invokeChecked 'npm.cmd' @('run', 'check')
            invokeChecked 'npm.cmd' @('test')
            invokeChecked 'cargo.exe' @('fmt', '--all', '--', '--check')
            invokeChecked 'cargo.exe' @('test', '--workspace', '--locked')
            invokeChecked 'cargo.exe' @('clippy', '--workspace', '--all-targets', '--locked', '--', '-D', 'warnings')
            invokeChecked 'cargo.exe' @('test', '--locked', '-p', 'epp-service', '--features', 'automatic-trials')
            invokeChecked 'cargo.exe' @('clippy', '--locked', '-p', 'epp-service', '--features', 'automatic-trials', '--all-targets', '--', '-D', 'warnings')
            invokeChecked 'node.exe' @('--test', 'scripts/launcher.test.mjs', 'scripts/webview-test.test.mjs', 'scripts/service-manager.test.mjs', 'scripts/native-mtu-lab.test.mjs', 'scripts/dns-listeners.test.mjs')
        }
        'package' {
            buildServiceResources
            invokeChecked 'npm.cmd' @('run', 'tauri', '--', 'build', '--bundles', 'nsis', '--config', 'src-tauri/service.bundle.json')
            $installers = @(Get-ChildItem -LiteralPath (Join-Path $projectRoot 'target\release\bundle\nsis') -Filter '*-setup.exe')
            if ($installers.Count -eq 0) { throw 'Tauri returned success but no NSIS installer was found.' }
            $installers | ForEach-Object { Write-Host "Installer: $($_.FullName)" }
        }
    }
    exit 0
} catch {
    Write-Host ''
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Task '$task' failed. See docs/setup.md for recovery instructions. No launcher elevation is required."
    exit $script:failureCode
} finally {
    if ($ownsMutex) { $workspaceMutex.ReleaseMutex() }
    if ($null -ne $workspaceMutex) { $workspaceMutex.Dispose() }
    Pop-Location
}
