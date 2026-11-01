import { createSocket } from 'node:dgram';
import { createServer } from 'node:net';

function bind(listener, event, start) {
  return new Promise((resolve, reject) => {
    const failed = (error) => {
      listener.off(event, ready);
      reject(error);
    };
    const ready = () => {
      listener.off('error', failed);
      resolve();
    };
    listener.once('error', failed);
    listener.once(event, ready);
    start();
  });
}

function close(listener) {
  try {
    listener.close();
  } catch {}
}

export async function dnsListeners(
  ip,
  pair = () => ({
    udp: createSocket(ip.includes(':') ? 'udp6' : 'udp4'),
    tcp: createServer(),
  }),
) {
  for (let attempt = 0; attempt < 12; attempt += 1) {
    const { udp, tcp } = pair();
    try {
      // windows can reserve different port ranges for tcp and udp.
      await bind(udp, 'listening', () => udp.bind(0, ip));
      const port = udp.address().port;
      await bind(tcp, 'listening', () => tcp.listen(port, ip));
      return { udp, tcp, port };
    } catch (error) {
      close(udp);
      close(tcp);
      if (!['EADDRINUSE', 'EACCES'].includes(error.code) || attempt === 11) throw error;
    }
  }
}
