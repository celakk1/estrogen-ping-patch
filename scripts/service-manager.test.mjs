import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, realpathSync, rmSync, utimesSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const shell = path.join(
  process.env.SystemRoot ?? 'C:\\Windows',
  'System32',
  'WindowsPowerShell',
  'v1.0',
  'powershell.exe',
);

test(
  'checkout service management selects the latest build while packaged resources stay together',
  {
    skip: process.platform !== 'win32',
  },
  () => {
    const directory = mkdtempSync(path.join(tmpdir(), 'epp service selection '));
    const debugExe = path.join(directory, 'target/debug/epp-network-service.exe');
    const releaseExe = path.join(directory, 'target/release/epp-network-service.exe');
    const bundleExe = path.join(directory, 'bundle.exe');
    const manager = path.join(directory, 'scripts/manage-service.ps1');
    try {
      for (const folder of ['scripts', 'target/debug', 'target/release']) {
        mkdirSync(path.join(directory, folder), { recursive: true });
      }
      cpSync(path.join(projectRoot, 'scripts/manage-service.ps1'), manager);
      const compileScript = String.raw`
$ErrorActionPreference = 'Stop'
foreach ($entry in @(@('DebugFixture', 'target/debug/epp-network-service.exe'), @('ReleaseFixture', 'target/release/epp-network-service.exe'), @('BundleFixture', 'bundle.exe'))) {
    $source = 'public static class ' + $entry[0] + ' { public static void Main() { System.Console.WriteLine("' + $entry[0] + '"); } }'
    Add-Type -TypeDefinition $source -OutputType ConsoleApplication -OutputAssembly (Join-Path $env:EPP_FIXTURE_ROOT $entry[1])
}
`;
      const compilation = spawnSync(
        shell,
        [
          '-NoLogo',
          '-NoProfile',
          '-EncodedCommand',
          Buffer.from(compileScript, 'utf16le').toString('base64'),
        ],
        {
          env: { ...process.env, EPP_FIXTURE_ROOT: directory },
          encoding: 'utf8',
          windowsHide: true,
          timeout: 30_000,
        },
      );
      assert.equal(compilation.status, 0, compilation.stderr);
      function selectedBuild(blockPrivateData = false) {
        const wrapper = String.raw`
$ErrorActionPreference = 'Stop'
function Test-Path {
    param([string]$LiteralPath, [string]$PathType)
    $privateRoot = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'estrogen-ping-patch-service'
    if ($LiteralPath.StartsWith($privateRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Status must not inspect private recovery storage before elevation.' }
    Microsoft.PowerShell.Management\Test-Path @PSBoundParameters
}
& $env:EPP_FIXTURE_MANAGER -action status
`;
        const args = blockPrivateData
          ? [
              '-NoLogo',
              '-NoProfile',
              '-EncodedCommand',
              Buffer.from(wrapper, 'utf16le').toString('base64'),
            ]
          : [
              '-NoLogo',
              '-NoProfile',
              '-ExecutionPolicy',
              'Bypass',
              '-File',
              manager,
              '-action',
              'status',
            ];
        const result = spawnSync(shell, args, {
          env: { ...process.env, EPP_FIXTURE_MANAGER: manager, EPP_NO_PAUSE: '1' },
          encoding: 'utf8',
          windowsHide: true,
          timeout: 15_000,
        });
        assert.equal(result.status, 0, result.stdout + result.stderr);
        return result.stdout.trim();
      }
      utimesSync(releaseExe, new Date('2020-01-01'), new Date('2020-01-01'));
      utimesSync(debugExe, new Date('2021-01-01'), new Date('2021-01-01'));
      assert.equal(selectedBuild(), 'DebugFixture');
      utimesSync(releaseExe, new Date('2022-01-01'), new Date('2022-01-01'));
      assert.equal(selectedBuild(), 'ReleaseFixture');
      cpSync(bundleExe, path.join(directory, 'scripts/epp-network-service.exe'));
      assert.equal(selectedBuild(), 'BundleFixture');
      assert.equal(selectedBuild(true), 'BundleFixture');
    } finally {
      assert.equal(path.dirname(realpathSync(directory)), realpathSync(tmpdir()));
      assert.ok(path.basename(directory).startsWith('epp service selection '));
      rmSync(directory, { recursive: true, force: true });
    }
  },
);
