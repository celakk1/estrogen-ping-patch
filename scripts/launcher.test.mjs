import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const windows = process.platform === 'win32';
const shell = path.join(
  process.env.SystemRoot ?? 'C:\\Windows',
  'System32',
  'WindowsPowerShell',
  'v1.0',
  'powershell.exe',
);

function fixture() {
  const directory = mkdtempSync(path.join(tmpdir(), 'epp launcher with spaces '));
  mkdirSync(path.join(directory, 'scripts'));
  cpSync(path.join(projectRoot, 'scripts', 'dev.ps1'), path.join(directory, 'scripts', 'dev.ps1'));
  cpSync(path.join(projectRoot, 'clean.bat'), path.join(directory, 'clean.bat'));
  writeFileSync(path.join(directory, 'Cargo.toml'), '[workspace]\n');
  return directory;
}

function runScript(directory, task, environment = {}) {
  return spawnSync(
    process.env.ComSpec,
    ['/d', '/s', '/c', `""${path.join(directory, `${task}.bat`)}""`],
    {
      cwd: tmpdir(),
      encoding: 'utf8',
      timeout: 30_000,
      windowsVerbatimArguments: true,
      env: { ...process.env, EPP_NO_PAUSE: '1', ...environment },
    },
  );
}

test(
  'a running workspace task prevents cleanup and dependency replacement',
  { skip: !windows, timeout: 15_000 },
  async () => {
    const directory = fixture();
    const rootHash = createHash('sha256')
      .update(directory.toUpperCase())
      .digest('hex')
      .toUpperCase();
    const holderPath = path.join(directory, 'hold-mutex.ps1');
    writeFileSync(
      holderPath,
      "param([string]$mutexName)\n$mutex = [Threading.Mutex]::new($true, $mutexName)\n[Console]::WriteLine('ready')\n[void][Console]::ReadLine()\n$mutex.ReleaseMutex()\n$mutex.Dispose()\n",
    );
    mkdirSync(path.join(directory, 'target'));
    writeFileSync(path.join(directory, 'target', 'keep.txt'), 'active build');
    const holder = spawn(
      shell,
      [
        '-NoLogo',
        '-NoProfile',
        '-File',
        holderPath,
        '-mutexName',
        `Local\\epp-workspace-${rootHash}`,
      ],
      { stdio: ['pipe', 'pipe', 'pipe'] },
    );
    try {
      const [ready] = await once(holder.stdout, 'data');
      assert.match(ready.toString(), /ready/);
      const result = runScript(directory, 'clean');
      assert.equal(result.status, 1, result.stdout + result.stderr);
      assert.match(result.stdout, /Another development task is already running/);
      assert.equal(
        readFileSync(path.join(directory, 'target', 'keep.txt'), 'utf8'),
        'active build',
      );
    } finally {
      const stopped = once(holder, 'exit');
      holder.stdin.end('\n');
      await stopped;
      rmSync(directory, { recursive: true, force: true });
    }
  },
);

test(
  'cleanup works from a different directory with spaces and preserves private data',
  { skip: !windows },
  () => {
    const directory = fixture();
    try {
      for (const generated of ['target', 'dist', 'coverage', '.cache', 'src-tauri/gen']) {
        mkdirSync(path.join(directory, generated), { recursive: true });
        writeFileSync(path.join(directory, generated, 'artifact.txt'), 'generated');
      }
      for (const preserved of ['node_modules', 'data']) {
        mkdirSync(path.join(directory, preserved));
        writeFileSync(path.join(directory, preserved, 'keep.txt'), 'preserve');
      }
      const result = runScript(directory, 'clean');
      assert.equal(result.status, 0, result.stdout + result.stderr);
      assert.equal(existsSync(path.join(directory, 'target')), false);
      assert.equal(readFileSync(path.join(directory, 'data', 'keep.txt'), 'utf8'), 'preserve');
      assert.equal(existsSync(path.join(directory, 'node_modules', 'keep.txt')), true);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  },
);

test(
  'cleanup rejects junction targets without removing external content',
  { skip: !windows },
  () => {
    const directory = fixture();
    const externalDirectory = mkdtempSync(path.join(tmpdir(), 'epp external sentinel '));
    try {
      writeFileSync(path.join(externalDirectory, 'keep.txt'), 'external');
      symlinkSync(externalDirectory, path.join(directory, 'target'), 'junction');
      const result = runScript(directory, 'clean');
      assert.notEqual(result.status, 0);
      assert.match(result.stdout, /Refusing to clean a linked directory/);
      assert.equal(readFileSync(path.join(externalDirectory, 'keep.txt'), 'utf8'), 'external');
    } finally {
      rmSync(path.join(directory, 'target'), { force: true, recursive: true });
      rmSync(directory, { recursive: true, force: true });
      rmSync(externalDirectory, { recursive: true, force: true });
    }
  },
);

test('every launcher propagates dependency failures without elevation', { skip: !windows }, () => {
  const directory = fixture();
  try {
    for (const task of ['launch', 'build', 'test', 'setup', 'package']) {
      const name = `${task}.bat`;
      cpSync(path.join(projectRoot, name), path.join(directory, name));
      const source = readFileSync(path.join(directory, name), 'utf8');
      assert.match(source, /%~dp0scripts\\dev\.ps1/);
      assert.doesNotMatch(source, /runas|Verb\s+RunAs/i);
      const result = spawnSync(
        process.env.ComSpec,
        ['/d', '/s', '/c', `""${path.join(directory, name)}""`],
        {
          cwd: tmpdir(),
          encoding: 'utf8',
          timeout: 30_000,
          windowsVerbatimArguments: true,
          env: { ...process.env, PATH: path.dirname(shell), EPP_NO_PAUSE: '1' },
        },
      );
      assert.equal(result.status, 1, `${task}: ${result.stdout} ${result.stderr}`);
      assert.match(
        result.stdout,
        /Missing rustc.exe/,
        `${task}: ${result.stdout} ${result.stderr}`,
      );
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
