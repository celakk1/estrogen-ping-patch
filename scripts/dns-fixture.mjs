import assert from 'node:assert/strict';
import { createSocket } from 'node:dgram';
import { createServer } from 'node:net';

export async function dnsFixture(ip, fallback = false) {
  const sockets = new Set();
  let requests = 0;
  const answer = (request, truncated = false) => {
    assert.ok(request.length >= 17 && request.length <= 512);
    assert.equal(request.readUInt16BE(4), 1);
    const type = request.readUInt16BE(request.length - 4);
    assert.ok(type === 1 || type === 28);
    const header = Buffer.from(request.subarray(0, 12));
    header.writeUInt16BE(truncated ? 0x8380 : 0x8180, 2);
    header.writeUInt16BE(truncated ? 0 : 1, 6);
    const question = request.subarray(12);
    if (truncated) return Buffer.concat([header, question]);
    const address =
      type === 1
        ? Buffer.from([192, 0, 2, 10])
        : Buffer.from('20010db8000000000000000000000010', 'hex');
    const record = Buffer.alloc(12);
    record.writeUInt16BE(0xc00c, 0);
    record.writeUInt16BE(type, 2);
    record.writeUInt16BE(1, 4);
    record.writeUInt32BE(60, 6);
    record.writeUInt16BE(address.length, 10);
    requests += 1;
    return Buffer.concat([header, question, record, address]);
  };
  const tcp = createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => {});
    socket.setTimeout(3000, () => socket.destroy());
    let pending = Buffer.alloc(0);
    socket.on('data', (chunk) => {
      pending = Buffer.concat([pending, chunk]);
      if (pending.length < 2 || pending.length < pending.readUInt16BE(0) + 2) return;
      const response = answer(pending.subarray(2, pending.readUInt16BE(0) + 2));
      const length = Buffer.alloc(2);
      length.writeUInt16BE(response.length);
      socket.end(Buffer.concat([length, response]));
    });
  });
  const udp = createSocket(ip.includes(':') ? 'udp6' : 'udp4');
  try {
    await new Promise((resolve, reject) => {
      tcp.once('error', reject);
      tcp.listen(0, ip, resolve);
    });
    const port = tcp.address().port;
    udp.on('message', (request, peer) =>
      udp.send(answer(request, fallback), peer.port, peer.address),
    );
    await new Promise((resolve, reject) => {
      udp.once('error', reject);
      udp.bind(port, ip, resolve);
    });
    return {
      address: `${ip.includes(':') ? `[${ip}]` : ip}:${port}`,
      get requests() {
        return requests;
      },
      close() {
        udp.close();
        for (const socket of sockets) socket.destroy();
        tcp.close();
      },
    };
  } catch (error) {
    try {
      udp.close();
    } catch {}
    for (const socket of sockets) socket.destroy();
    tcp.close();
    throw error;
  }
}
