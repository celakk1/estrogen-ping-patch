import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { pathToFileURL } from 'node:url';
import path from 'node:path';

const maxPayload = 512 * 1024 * 1024;
const maxSessionPayload = 2 * 1024 * 1024 * 1024;

export async function createBenchmarkServer({ host = '127.0.0.1', port = 0, throttleMs = 0 } = {}) {
  if (
    !['127.0.0.1', '::1'].includes(host) ||
    !Number.isInteger(port) ||
    port < 0 ||
    port > 65535 ||
    !Number.isFinite(throttleMs) ||
    throttleMs < 0 ||
    throttleMs > 1000
  )
    throw new Error('Use a literal loopback host, a valid port, and a 0..1000 ms throttle.');
  const sockets = new Set();
  const totals = { downloadBytes: 0, uploadBytes: 0, requests: 0 };
  let active = 0;
  let reserved = 0;
  const payload = randomBytes(32 * 1024);
  const server = createServer({ maxHeaderSize: 8192 }, async (request, response) => {
    let url;
    try {
      url = new URL(request.url, 'http://127.0.0.1/');
    } catch {
      response.writeHead(400, { Connection: 'close' }).end();
      return;
    }
    const download = request.method === 'GET' && url.pathname === '/epp/v1/download';
    const upload = request.method === 'POST' && url.pathname === '/epp/v1/upload';
    const rawSize = download ? url.searchParams.get('bytes') : request.headers['content-length'];
    const size = typeof rawSize === 'string' && /^\d{1,9}$/.test(rawSize) ? Number(rawSize) : 0;
    if (!download && !upload) {
      response.writeHead(404, { Connection: 'close' }).end();
      return;
    }
    if (size < 1 || size > maxPayload) {
      response.writeHead(413, { Connection: 'close' }).end();
      return;
    }
    if (active >= 4 || reserved + size > maxSessionPayload) {
      response.writeHead(429, { 'Retry-After': '60', Connection: 'close' }).end();
      return;
    }
    reserved += size;
    active += 1;
    totals.requests += 1;
    try {
      if (download) {
        response.writeHead(200, {
          'Content-Length': size,
          'Content-Type': 'application/octet-stream',
          'Content-Encoding': 'identity',
          'Cache-Control': 'no-store',
          'X-Epp-Benchmark-Protocol': '1',
        });
        async function* chunks() {
          let remaining = size;
          while (remaining > 0 && !response.destroyed) {
            if (throttleMs) await delay(throttleMs);
            const count = Math.min(remaining, payload.length);
            remaining -= count;
            totals.downloadBytes += count;
            yield payload.subarray(0, count);
          }
        }
        await pipeline(Readable.from(chunks()), response);
      } else {
        let received = 0;
        for await (const chunk of request) {
          received += chunk.length;
          totals.uploadBytes += chunk.length;
          if (received > size) throw new Error('Upload exceeds declared size.');
          if (throttleMs) await delay(throttleMs);
        }
        if (received !== size) throw new Error('Upload body is incomplete.');
        response
          .writeHead(200, {
            'Content-Length': '0',
            'Cache-Control': 'no-store',
            'X-Epp-Benchmark-Protocol': '1',
            'X-Epp-Received-Bytes': String(received),
          })
          .end();
      }
    } catch {
      response.destroy();
    } finally {
      active -= 1;
    }
  });
  server.requestTimeout = 60_000;
  server.headersTimeout = 5000;
  server.keepAliveTimeout = 1000;
  server.maxConnections = 12;
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, resolve);
  });
  return {
    origin: `http://${host.includes(':') ? `[${host}]` : host}:${server.address().port}/`,
    totals,
    async close() {
      for (const socket of sockets) socket.destroy();
      await new Promise((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    },
  };
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  const supplied = process.argv.slice(2);
  if (supplied.length !== 0 && !(supplied.length === 2 && supplied[0] === '--port'))
    throw new Error('Usage: node scripts/benchmark-server.mjs [--port 8088]');
  const fixture = await createBenchmarkServer({
    port: supplied.length ? Number(supplied[1]) : 8088,
  });
  console.log(
    `EPP benchmark protocol v1 listening at ${fixture.origin}; loopback only, 512 MiB per request, 2 GiB process payload quota. Stop with Ctrl+C.`,
  );
  process.once('SIGINT', async () => {
    await fixture.close();
    process.exitCode = 0;
  });
}
