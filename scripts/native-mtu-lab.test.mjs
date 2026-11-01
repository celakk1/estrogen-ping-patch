import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const scriptsRoot = path.dirname(fileURLToPath(import.meta.url));
const shell = path.join(
  process.env.SystemRoot ?? 'C:\\Windows',
  'System32/WindowsPowerShell/v1.0/powershell.exe',
);
const options = { skip: process.platform !== 'win32' };

function powershell(script, environment = {}) {
  const source =
    String.raw`$env:PSModulePath = "$PSHOME\Modules;$env:ProgramFiles\WindowsPowerShell\Modules"` +
    '\n' +
    script;
  return spawnSync(
    shell,
    [
      '-NoLogo',
      '-NoProfile',
      '-NonInteractive',
      '-EncodedCommand',
      Buffer.from(source, 'utf16le').toString('base64'),
    ],
    {
      encoding: 'utf8',
      timeout: 30_000,
      windowsHide: true,
      env: {
        ...process.env,
        EPP_LAB_SCRIPT: path.join(scriptsRoot, 'native-mtu-lab.ps1'),
        EPP_LAB_DEVICE_SOURCE: path.join(scriptsRoot, 'native-mtu-lab-device.cs'),
        ...environment,
      },
    },
  );
}

test(
  'native MTU lab refuses missing consent and development-machine execution before setup',
  options,
  () => {
    for (const argumentsText of ['', '-allowNetworkChanges']) {
      const result = powershell(
        `$ErrorActionPreference = 'Stop'\n& $env:EPP_LAB_SCRIPT ${argumentsText}`,
        { GITHUB_ACTIONS: '', RUNNER_ENVIRONMENT: '' },
      );
      assert.equal(result.error, undefined);
      assert.notEqual(result.status, 0);
      assert.match(result.stdout + result.stderr, /Development-machine execution is refused/);
    }
  },
);

test(
  'native device fixture compiles for Windows PowerShell and refuses unowned cleanup',
  options,
  () => {
    const result = powershell(String.raw`
$ErrorActionPreference = 'Stop'
Add-Type -Path $env:EPP_LAB_DEVICE_SOURCE
$rejected = $false
try { [NativeMtuLabDevice]::remove('ROOT\NET\NOT_OWNED') } catch {
    if ($_.Exception.Message -notlike '*not created by this lab process*') { throw }
    $rejected = $true
}
$deviceInfo = [NativeMtuLabDevice].GetNestedType('DeviceInfo', [Reflection.BindingFlags]::NonPublic)
$installParams = [NativeMtuLabDevice].GetNestedType('InstallParams', [Reflection.BindingFlags]::NonPublic)
@{ rejected = $rejected; deviceInfoBytes = [Runtime.InteropServices.Marshal]::SizeOf([Activator]::CreateInstance($deviceInfo)); installParamsBytes = [Runtime.InteropServices.Marshal]::SizeOf([Activator]::CreateInstance($installParams)) } | ConvertTo-Json -Compress
`);
    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), {
      rejected: true,
      deviceInfoBytes: 32,
      installParamsBytes: 584,
    });
  },
);

test(
  'native lab security descriptors parse with protected administrator ownership',
  options,
  () => {
    const result = powershell(String.raw`
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($env:EPP_LAB_SCRIPT, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw 'Native lab script failed parsing.' }
$calls = $ast.FindAll({ param($node) $node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Member.Value -eq 'SetSecurityDescriptorSddlForm' }, $true)
$counts = @()
foreach ($call in $calls) {
    if ($call.Arguments.Count -ne 1) { throw 'Unexpected security descriptor arguments.' }
    $value = $call.Arguments[0].Value.Replace('$serviceSid', 'S-1-5-80-1-2-3-4-5')
    $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($value)
    if ($descriptor.Owner.Value -ne 'S-1-5-32-544' -or -not ($descriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected)) { throw 'Native lab descriptor lacks protected administrator ownership.' }
    $counts += $descriptor.DiscretionaryAcl.Count
}
@{ descriptors = $calls.Count; ruleCounts = @($counts | Sort-Object) } | ConvertTo-Json -Compress
`);
    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), { descriptors: 3, ruleCounts: [2, 2, 4] });
  },
);

test('native settings comparison ignores key order and preserves exact values', options, () => {
  const result = powershell(String.raw`
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($env:EPP_LAB_SCRIPT, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw 'Native lab script failed parsing.' }
$function = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'settingsJson' }, $true)
if ($null -eq $function) { throw 'Native settings comparison function is missing.' }
. ([scriptblock]::Create($function.Extent.Text))
$first = [pscustomobject][ordered]@{ nlMtu = 1500; sitePrefixLength = 64; useAutomaticMetric = $true; zoneIndices = @(0, 1) }
$second = [pscustomobject][ordered]@{ zoneIndices = @(0, 1); useAutomaticMetric = $true; sitePrefixLength = 64; nlMtu = 1500 }
if (($first | ConvertTo-Json -Compress) -ceq ($second | ConvertTo-Json -Compress)) { throw 'Fixture does not reproduce the key-order difference.' }
if ((settingsJson $first) -cne (settingsJson $second)) { throw 'Equal settings were rejected because of key order.' }
foreach ($changed in @(
    [pscustomobject]@{ nlMtu = 1400; sitePrefixLength = 64; useAutomaticMetric = $true; zoneIndices = @(0, 1) },
    [pscustomobject]@{ nlMtu = 1500; sitePrefixLength = 0; useAutomaticMetric = $true; zoneIndices = @(0, 1) },
    [pscustomobject]@{ nlMtu = 1500; sitePrefixLength = 64; useAutomaticMetric = 1; zoneIndices = @(0, 1) },
    [pscustomobject]@{ nlMtu = 1500; sitePrefixLength = 64; useAutomaticMetric = $true; zoneIndices = @(1, 0) },
    [pscustomobject]@{ nlMtu = 1500; sitePrefixLength = 64; zoneIndices = @(0, 1) }
)) {
    if ((settingsJson $first) -ceq (settingsJson $changed)) { throw 'A changed value, type, array order, or missing field was accepted.' }
}
Write-Output 'comparison verified'
`);
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /comparison verified/);
});

test(
  'native origin comparison preserves nested values while ignoring object key order',
  options,
  () => {
    const result = powershell(String.raw`
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($env:EPP_LAB_SCRIPT, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw 'Native lab script failed parsing.' }
foreach ($name in @('orderedJsonValue', 'originsJson')) {
    $function = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    if ($null -ne $function) { . ([scriptblock]::Create($function.Extent.Text)) }
}
$first = '{"status":"captured","evidence":{"schemaVersion":1,"stacks":[{"name":"Tcpip","keyPresent":true,"values":[{"name":"NameServer","value":null},{"name":"MTU","value":{"valueType":4,"dataHex":"dc050000"}}]}]}}' | ConvertFrom-Json
$second = '{"evidence":{"stacks":[{"values":[{"value":null,"name":"NameServer"},{"value":{"dataHex":"dc050000","valueType":4},"name":"MTU"}],"keyPresent":true,"name":"Tcpip"}],"schemaVersion":1},"status":"captured"}' | ConvertFrom-Json
if (($first | ConvertTo-Json -Depth 12 -Compress) -ceq ($second | ConvertTo-Json -Depth 12 -Compress)) { throw 'Fixture does not reproduce nested serializer key-order differences.' }
$original = originsJson $first
if ($original -cne (originsJson $second)) { throw 'Equal origin evidence was rejected because of nested key order.' }
for ($fault = 0; $fault -lt 10; $fault++) {
    $changed = $first | ConvertTo-Json -Depth 12 | ConvertFrom-Json
    switch ($fault) {
        0 { $changed.evidence.stacks[0].values[1].value.dataHex = 'dc040000' }
        1 { $changed.evidence.stacks[0].values[1].value.valueType = 1 }
        2 { $changed.evidence.stacks[0].keyPresent = 1 }
        3 { $changed.evidence.stacks[0].values[0].value = '' }
        4 { $changed.evidence.stacks[0].values = @($changed.evidence.stacks[0].values[1], $changed.evidence.stacks[0].values[0]) }
        5 { $changed.evidence.stacks[0].PSObject.Properties.Remove('keyPresent') }
        6 { $changed.evidence | Add-Member -NotePropertyName extra -NotePropertyValue 1 }
        7 { $changed.evidence.stacks[0].values = @() }
        8 { $changed.evidence.stacks[0].values[0].value = @() }
        9 { $changed.evidence.stacks[0].values[1].value.dataHex = 'DC050000' }
    }
    if ($original -ceq (originsJson $changed)) { throw "Changed origin evidence was accepted for fault $fault." }
}
Write-Output 'nested origin comparison verified'
originsJson ([pscustomobject]@{ emptyArray = @(); singleArray = @($null); emptyObject = [pscustomobject]@{}; nullValue = $null; boolean = $true; numeric = 1; text = '1' })
`);
    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.match(result.stdout, /nested origin comparison verified/);
    assert.deepEqual(JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1)), {
      emptyArray: [],
      singleArray: [null],
      emptyObject: {},
      nullValue: null,
      boolean: true,
      numeric: 1,
      text: '1',
    });
  },
);

test('authorization fault fixture preserves the original database and sidecars', options, () => {
  const result = powershell(String.raw`
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($env:EPP_LAB_SCRIPT, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw 'Native lab script failed parsing.' }
foreach ($name in @('blockAuthorization', 'restoreAuthorization')) {
    $function = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    if ($null -eq $function) { throw 'Authorization fault fixture function is missing.' }
    . ([scriptblock]::Create($function.Extent.Text))
}
$dataRoot = Join-Path ([IO.Path]::GetTempPath()) ('epp-authorization-fixture-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($dataRoot) | Out-Null
$path = Join-Path $dataRoot 'authorization.sqlite3'
$wal = "$path-wal"
$state = $null
try {
    [IO.File]::WriteAllText($path, 'original database fixture')
    [IO.File]::WriteAllText($wal, 'original wal fixture')
    $originalHash = (Get-FileHash -LiteralPath $path).Hash
    $walHash = (Get-FileHash -LiteralPath $wal).Hash
    $state = blockAuthorization
    if (-not (Test-Path -LiteralPath $path -PathType Container) -or (Get-FileHash -LiteralPath $state.backup).Hash -cne $originalHash) { throw 'Authorization was not blocked without changing the original bytes.' }
    if ((Get-FileHash -LiteralPath $wal).Hash -cne $walHash) { throw 'Authorization WAL was changed.' }
    restoreAuthorization $state
    $state = $null
    if ((Get-FileHash -LiteralPath $path).Hash -cne $originalHash) { throw 'Authorization database was not restored exactly.' }
    [IO.File]::WriteAllText("$path.lab-blocked", 'existing fixture')
    $refused = $false
    try { $null = blockAuthorization } catch { $refused = $true }
    if (-not $refused -or [IO.File]::ReadAllText($path) -cne 'original database fixture') { throw 'A backup collision was not refused safely.' }
    Write-Output 'authorization fault fixture verified'
} finally {
    if ($state) { restoreAuthorization $state }
    foreach ($file in @($path, $wal, "$path.lab-blocked")) { if (Test-Path -LiteralPath $file -PathType Leaf) { Remove-Item -LiteralPath $file } }
    if (@(Get-ChildItem -LiteralPath $dataRoot -Force).Count -eq 0) { Remove-Item -LiteralPath $dataRoot }
}
`);
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /authorization fault fixture verified/);
});
