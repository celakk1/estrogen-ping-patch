import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { createSocket } from 'node:dgram';
import { createConnection } from 'node:net';
import { once } from 'node:events';
import test from 'node:test';
import { dnsListeners } from './dns-listeners.mjs';

test('DNS fixture reserves the same port for actual TCP and UDP in both families', async () => {
  for (const ip of ['127.0.0.1', '::1']) {
    const { udp, tcp, port } = await dnsListeners(ip);
    const client = createSocket(ip.includes(':') ? 'udp6' : 'udp4');
    let connection;
    let accepted;
    try {
      const message = once(udp, 'message');
      client.send(Buffer.from('probe'), port, ip);
      assert.equal((await message)[0].toString(), 'probe');
      const pending = once(tcp, 'connection');
      connection = createConnection({ host: ip, port });
      [accepted] = await pending;
      assert.equal(accepted.localPort, port);
    } finally {
      accepted?.destroy();
      connection?.destroy();
      client.close();
      udp.close();
      tcp.close();
    }
  }
});

function fixturePair(error, listeners) {
  const udp = new EventEmitter();
  const tcp = new EventEmitter();
  for (const listener of [udp, tcp]) {
    listener.closed = false;
    listener.close = () => (listener.closed = true);
  }
  udp.bind = () => queueMicrotask(() => udp.emit('listening'));
  udp.address = () => ({ port: 12345 });
  tcp.listen = () =>
    queueMicrotask(() =>
      error
        ? tcp.emit('error', Object.assign(new Error(error), { code: error }))
        : tcp.emit('listening'),
    );
  listeners.push(udp, tcp);
  return { udp, tcp };
}

test('reserved or occupied pairs are closed before trying a new port', async () => {
  const listeners = [];
  const failures = ['EACCES', 'EADDRINUSE'];
  const pair = await dnsListeners('127.0.0.1', () => fixturePair(failures.shift(), listeners));
  assert.equal(listeners.length, 6);
  assert.ok(listeners.slice(0, 4).every((listener) => listener.closed));
  assert.ok(listeners.slice(4).every((listener) => !listener.closed));
  pair.udp.close();
  pair.tcp.close();
});

test('binding failure is bounded and unrelated errors are propagated immediately', async () => {
  for (const [error, attempts] of [
    ['EACCES', 12],
    ['EAFNOSUPPORT', 1],
  ]) {
    const listeners = [];
    await assert.rejects(
      dnsListeners('127.0.0.1', () => fixturePair(error, listeners)),
      { code: error },
    );
    assert.equal(listeners.length, attempts * 2);
    assert.ok(listeners.every((listener) => listener.closed));
  }
});
