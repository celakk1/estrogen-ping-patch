import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import path from 'node:path';

const executable = path.resolve(process.argv[2] ?? 'target/release/estrogen-ping-patch.exe');
const child = spawn(executable, ['--mcp'], { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
const deadline = setTimeout(() => child.kill(), 10_000);
let output = '';
let errors = '';
child.stdout.setEncoding('utf8').on('data', (data) => {
  output += data;
});
child.stderr.setEncoding('utf8').on('data', (data) => {
  errors += data;
});
const finished = once(child, 'exit');
child.stdin.end(
  [
    {
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2025-06-18',
        capabilities: {},
        clientInfo: { name: 'smoke-test', version: '1' },
      },
    },
    { jsonrpc: '2.0', method: 'notifications/initialized' },
    { jsonrpc: '2.0', id: 2, method: 'tools/list' },
    {
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: { name: 'execute_command', arguments: {} },
    },
  ]
    .map((message) => JSON.stringify(message))
    .join('\n') + '\n',
);
try {
  const [code] = await finished;
  assert.equal(code, 0, errors);
  const responses = output
    .trim()
    .split('\n')
    .map((line) => JSON.parse(line));
  assert.equal(responses.length, 3);
  assert.equal(responses[0].result.protocolVersion, '2025-06-18');
  assert.equal(responses[1].result.tools.length, 2);
  assert.equal(responses[2].error.code, -32602);
  console.log(
    'Packaged MCP smoke passed: stdio initialization, read-only tool discovery, and command rejection.',
  );
} finally {
  clearTimeout(deadline);
}
