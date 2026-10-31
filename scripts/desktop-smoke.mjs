import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import { chromium } from 'playwright-core';
import { mkdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { waitForDesktopPage } from './webview-test.mjs';
import { dnsFixture } from './dns-fixture.mjs';

const endpoint = process.env.EPP_CDP_URL;
if (!endpoint || !/^http:\/\/127\.0\.0\.1:\d+$/.test(endpoint)) {
  throw new Error(
    'Set EPP_CDP_URL to the loopback WebView2 debugging URL of an explicitly launched test instance.',
  );
}

async function listener() {
  const server = createServer((socket) => socket.end());
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return { server, address: `127.0.0.1:${server.address().port}` };
}

const first = await listener();
const second = await listener();
let browser;
let session;
let firstDns;
let secondDns;
try {
  firstDns = await dnsFixture('127.0.0.1');
  secondDns = await dnsFixture('::1', true);
  browser = await chromium.connectOverCDP(endpoint, { timeout: 15_000 });
  const page = await waitForDesktopPage(browser);
  await page.waitForFunction(() => Boolean(window.__TAURI_INTERNALS__));
  if (process.env.EPP_DATA_DIR) {
    const status = await page.evaluate(() => window.__TAURI_INTERNALS__.invoke('status'));
    assert.equal(
      path.resolve(status.dataDirectory).toLowerCase(),
      path.resolve(process.env.EPP_DATA_DIR).toLowerCase(),
      'Selected WebView must use the isolated test profile',
    );
  }
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('console', (message) => {
    if (message.type() === 'error') console.error(message.text());
  });
  await page.reload();
  await page.getByRole('button', { name: 'Start baseline', exact: true }).waitFor();
  await page.getByRole('button', { name: 'System inventory', exact: true }).click();
  await page.getByRole('columnheader', { name: 'Interface', exact: true }).waitFor();
  await page.waitForFunction(() => /Windows \d/.test(document.body.innerText), undefined, {
    timeout: 35_000,
  });
  const rows = page.locator('tbody tr');
  assert.ok((await rows.count()) > 0, 'Expected real Windows network adapters');
  await page.getByRole('button', { name: 'Overview', exact: true }).click();
  await page.getByLabel('Samples per endpoint').fill('3');
  await page.getByLabel('First destination (IP:port)').fill(first.address);
  await page.getByLabel('Second destination (IP:port)').fill(second.address);
  await page.getByRole('button', { name: 'Start baseline', exact: true }).click();
  await page.getByRole('button', { name: 'Export JSON', exact: true }).waitFor({ timeout: 30_000 });
  assert.equal(await page.getByText('3/3 successful connections', { exact: true }).count(), 2);
  assert.equal(await page.getByRole('alert').count(), 0);
  mkdirSync('artifacts', { recursive: true });
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: 'artifacts/desktop-baseline.png', fullPage: true });
  await page.getByLabel('Network benchmark').selectOption('icmpEcho');
  await page.getByLabel('First destination (IP or IPv6%scopeId)').fill('127.0.0.1');
  await page.getByLabel('Second destination (IP or IPv6%scopeId)').fill('::1');
  await page.getByRole('button', { name: 'Start baseline', exact: true }).click();
  await page
    .getByRole('img', { name: 'Measured ICMP echo round-trip times', exact: true })
    .waitFor();
  await page.getByRole('button', { name: 'Export JSON', exact: true }).waitFor({ timeout: 30_000 });
  assert.equal(await page.getByText('3/3 echo replies', { exact: true }).count(), 2);
  const echoRun = await page.evaluate(
    async () => (await window.__TAURI_INTERNALS__.invoke('getHistory'))[0],
  );
  assert.equal(echoRun.protocol, 'icmpEcho');
  assert.equal(echoRun.samples.length, 6);
  for (const sample of echoRun.samples) {
    assert.equal(sample.connectMs, null);
    assert.equal(sample.echo.status, 'reply');
    assert.equal(sample.echo.rttUnitMs, 1);
    assert.equal(sample.echo.nativeCode, 0);
    assert.ok(Number.isInteger(sample.echo.rttMs));
  }
  for (const result of echoRun.results) {
    assert.equal(result.summary.connectionFailurePercent, undefined);
    assert.equal(result.summary.echoTimeoutPercent, 0);
  }
  session = await page.context().newCDPSession(page);
  await session.send('Browser.setDownloadBehavior', {
    behavior: 'allow',
    downloadPath: path.resolve('artifacts'),
    eventsEnabled: true,
  });
  for (const format of ['JSON', 'HTML']) {
    const downloaded = page.waitForEvent('download', { timeout: 15_000 });
    await page.getByRole('button', { name: `Export ${format}`, exact: true }).click();
    const download = await downloaded;
    assert.equal(await download.failure(), null);
    const content = readFileSync(path.resolve('artifacts', download.suggestedFilename()), 'utf8');
    if (format === 'JSON') assert.deepEqual(JSON.parse(content), echoRun);
    else {
      assert.match(content, /ICMP echo RTT/);
      assert.match(content, /ICMP echo timeouts/);
      assert.doesNotMatch(content, /TCP connection establishment/);
    }
  }
  await session.send('Browser.setDownloadBehavior', { behavior: 'default' });
  await page.screenshot({ path: 'artifacts/desktop-echo-baseline.png', fullPage: true });
  await page.reload();
  await page.getByRole('button', { name: 'Benchmark history', exact: true }).click();
  await page.getByRole('cell', { name: 'ICMP echo', exact: true }).waitFor();
  await page.getByRole('button', { name: 'View', exact: true }).first().click();
  assert.equal(await page.getByText('3/3 echo replies', { exact: true }).count(), 2);
  await page.getByLabel('Network benchmark').selectOption('dnsLookup');
  await page.getByLabel('Samples per endpoint').fill('3');
  await page.getByLabel('First destination (IP:port)').fill(firstDns.address);
  await page.getByLabel('Second destination (IP:port)').fill(secondDns.address);
  await page.getByLabel('DNS query name').fill('example.test');
  let dnsRun;
  for (const recordType of ['A', 'AAAA']) {
    await page.getByLabel('DNS record type').selectOption(recordType);
    await page.getByRole('button', { name: 'Start baseline', exact: true }).click();
    await page
      .getByRole('button', { name: 'Export JSON', exact: true })
      .waitFor({ timeout: 30_000 });
    assert.equal(await page.getByText('3/3 resolved lookups', { exact: true }).count(), 2);
    dnsRun = await page.evaluate(
      async () => (await window.__TAURI_INTERNALS__.invoke('getHistory'))[0],
    );
    assert.equal(dnsRun.protocol, 'dnsLookup');
    assert.equal(dnsRun.samples.length, 6);
    for (const sample of dnsRun.samples) {
      assert.equal(sample.connectMs, null);
      assert.equal(sample.echo, undefined);
      assert.equal(sample.dns.status, 'resolved');
      assert.equal(sample.dns.query.recordType, recordType);
      assert.equal(sample.dns.query.name, 'example.test.');
      assert.equal(sample.dns.cacheMode, 'directResolverCacheUnknown');
      assert.equal(sample.dns.responseCode, 0);
      assert.equal(sample.dns.answers[0].ttlSeconds, 60);
      assert.equal(
        sample.dns.answers[0].address,
        recordType === 'A' ? '192.0.2.10' : '2001:db8::10',
      );
      assert.ok(sample.dns.lookupMs >= sample.dns.responseMs);
      assert.equal(
        sample.dns.transport,
        sample.endpointId === 'First destination' ? 'udp' : 'tcpFallback',
      );
    }
    for (const [index, result] of dnsRun.results.entries()) {
      assert.equal(result.summary.dnsFailurePercent, 0);
      assert.equal(result.summary.connectionFailurePercent, undefined);
      assert.equal(result.summary.echoTimeoutPercent, undefined);
      assert.equal(result.dnsCounts.tcpFallbacks, index === 0 ? 0 : 3);
      assert.equal(result.dnsCounts.addressSetChanges, 0);
    }
  }
  assert.equal(firstDns.requests, 6);
  assert.equal(secondDns.requests, 6);
  await session.send('Browser.setDownloadBehavior', {
    behavior: 'allow',
    downloadPath: path.resolve('artifacts'),
    eventsEnabled: true,
  });
  for (const format of ['JSON', 'HTML']) {
    const downloaded = page.waitForEvent('download', { timeout: 15_000 });
    await page.getByRole('button', { name: `Export ${format}`, exact: true }).click();
    const download = await downloaded;
    assert.equal(await download.failure(), null);
    const content = readFileSync(path.resolve('artifacts', download.suggestedFilename()), 'utf8');
    if (format === 'JSON') assert.deepEqual(JSON.parse(content), dnsRun);
    else {
      assert.match(content, /DNS resolution/);
      assert.match(content, /example.test. AAAA/);
      assert.match(content, /2001:db8::10/);
      assert.match(content, /Resolver cache state is unknown/);
      assert.doesNotMatch(content, /TCP connection establishment/);
    }
  }
  await session.send('Browser.setDownloadBehavior', { behavior: 'default' });
  await page.screenshot({ path: 'artifacts/desktop-dns-baseline.png', fullPage: true });
  await page.reload();
  await page.getByRole('button', { name: 'Benchmark history', exact: true }).click();
  await page.getByRole('cell', { name: 'DNS resolution', exact: true }).first().waitFor();
  await page.getByRole('button', { name: 'View', exact: true }).first().click();
  assert.equal(await page.getByText('3/3 resolved lookups', { exact: true }).count(), 2);
  await page.getByRole('button', { name: 'Benchmark history', exact: true }).click();
  assert.ok((await page.getByRole('cell', { name: 'completed', exact: true }).count()) > 0);
  await page.getByRole('button', { name: 'Safety & policy', exact: true }).click();
  assert.ok((await page.getByText('Disabled in this build', { exact: true }).count()) > 0);
  const service = await page.evaluate(() =>
    window.__TAURI_INTERNALS__.invoke('getPrivilegedService'),
  );
  assert.equal(typeof service.state, 'string');
  assert.ok(service.detail.length > 0);
  if (service.state === 'notInstalled') {
    await page.getByRole('button', { name: 'Install optional service', exact: true }).waitFor();
  }
  await page.getByRole('button', { name: 'Refresh service status', exact: true }).click();
  const rejectedAction = await page.evaluate(async () => {
    try {
      await window.__TAURI_INTERNALS__.invoke('manageService', { action: 'runCommand' });
      return false;
    } catch {
      return true;
    }
  });
  assert.equal(
    rejectedAction,
    true,
    'Service management must reject unknown actions before execution',
  );
  assert.deepEqual(errors, []);
  console.log(
    'Desktop smoke passed: Windows inventory, six TCP, six IPv4/IPv6 ICMP, and twelve direct DNS A/AAAA loopback measurements over UDP and TCP fallback; protocol-specific statistics, persisted history/reload, actual JSON/HTML downloads, service status, rejected unknown management action, and visible safety boundary.',
  );
} finally {
  first.server.close();
  second.server.close();
  firstDns?.close();
  secondDns?.close();
  if (session)
    await session.send('Browser.setDownloadBehavior', { behavior: 'default' }).catch(() => {});
  if (browser) await browser.close();
}
