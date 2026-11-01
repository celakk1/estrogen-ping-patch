import assert from 'node:assert/strict';
import { mkdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { chromium } from 'playwright-core';
import { verifyTestActionFits, waitForDesktopPage } from './webview-test.mjs';

const endpoint = process.env.EPP_CDP_URL;
if (!endpoint || !/^http:\/\/127\.0\.0\.1:\d+$/.test(endpoint) || !process.env.EPP_DATA_DIR)
  throw new Error(
    'An explicitly launched isolated desktop with loopback EPP_CDP_URL and EPP_DATA_DIR is required.',
  );

let browser;
let session;
try {
  browser = await chromium.connectOverCDP(endpoint, { timeout: 15_000 });
  const page = await waitForDesktopPage(browser);
  const status = await page.evaluate(() => window.__TAURI_INTERNALS__.invoke('status'));
  assert.equal(
    path.resolve(status.dataDirectory).toLowerCase(),
    path.resolve(process.env.EPP_DATA_DIR).toLowerCase(),
  );
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.getByRole('button', { name: 'Network tests', exact: true }).click();
  await page.getByRole('button', { name: /^Large packet check\b/ }).click();
  await page.getByRole('button', { name: 'Start packet check', exact: true }).waitFor();
  const viewport = await page.evaluate(() => ({
    width: window.innerWidth,
    height: window.innerHeight,
  }));
  mkdirSync('artifacts', { recursive: true });
  await page.setViewportSize({ width: 1024, height: 768 });
  await page.evaluate(() => window.scrollTo(0, 0));
  await verifyTestActionFits(page, 'Start packet check', 'artifacts/desktop-packets-start-narrow');
  await page.setViewportSize(viewport);
  const action = await page
    .getByRole('button', { name: 'Start packet check', exact: true })
    .boundingBox();
  await page.screenshot({ path: 'artifacts/desktop-packets-start.png', fullPage: true });
  assert.ok(
    action && action.y >= 0 && action.y + action.height <= viewport.height - 24,
    `Packet check action must fit the desktop viewport: ${JSON.stringify({ action, viewport })}`,
  );
  await page.getByLabel('Packet check destination (IPv4)').fill('127.0.0.1');
  await page.getByRole('button', { name: 'Start packet check', exact: true }).click();
  await page
    .getByRole('button', { name: 'Export packet data (JSON)', exact: true })
    .waitFor({ timeout: 10_000 });
  const checks = await page.evaluate(() => window.__TAURI_INTERNALS__.invoke('getPacketHistory'));
  const check = checks[0];
  assert.equal(check.report.outcome, 'testedLimitReached');
  assert.equal(check.contextUnchanged, true);
  assert.equal(check.report.plan.source, '127.0.0.1');
  assert.equal(check.report.plan.destination, '127.0.0.1');
  assert.equal(check.report.confirmedBoundaryBytes, null);
  assert.equal(check.report.samples.length, 10);
  assert.ok(
    check.report.samples.every((sample) => sample.dontFragment && sample.echo.status === 'reply'),
  );
  assert.equal(
    check.report.requestedIpv4Bytes,
    check.report.samples.reduce((total, sample) => total + sample.packetBytes, 0),
  );
  session = await browser.newBrowserCDPSession();
  await session.send('Browser.setDownloadBehavior', {
    behavior: 'allow',
    downloadPath: path.resolve('artifacts'),
    eventsEnabled: true,
  });
  const downloaded = page.waitForEvent('download', { timeout: 15_000 });
  await page.getByRole('button', { name: 'Export packet data (JSON)', exact: true }).click();
  const download = await downloaded;
  assert.equal(await download.failure(), null);
  assert.deepEqual(
    JSON.parse(readFileSync(path.resolve('artifacts', download.suggestedFilename()), 'utf8')),
    check,
  );
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: 'artifacts/desktop-packets-result.png', fullPage: true });
  await page.reload();
  await page.getByRole('button', { name: /^Large packet check\b/ }).click();
  await page.getByRole('button', { name: `Open packet check ${check.id}`, exact: true }).click();
  await page.getByRole('button', { name: 'Export packet data (JSON)', exact: true }).waitFor();
  await page.getByLabel('Packet check destination (IPv4)').fill('127.0.0.1');
  await page.getByRole('button', { name: 'Start packet check', exact: true }).click();
  await page.waitForFunction(() =>
    document.body.textContent.includes('requests recorded. Last size:'),
  );
  await page.getByRole('button', { name: 'Stop packet check', exact: true }).click();
  await page
    .getByRole('heading', { name: 'Check stopped', exact: true })
    .waitFor({ timeout: 10_000 });
  const partial = await page.evaluate(
    async () => (await window.__TAURI_INTERNALS__.invoke('getPacketHistory'))[0],
  );
  assert.equal(partial.report.outcome, 'cancelled');
  assert.equal(partial.report.confirmedBoundaryBytes, null);
  assert.ok(partial.report.samples.length > 0 && partial.report.samples.length < 10);
  assert.deepEqual(errors, []);
  console.log(
    'Packet smoke passed: native source-bound loopback probes, route and adapter evidence, verified history/reload, JSON download, partial cancellation, and narrow-layout action visibility. No settings changed.',
  );
} finally {
  if (session)
    await session.send('Browser.setDownloadBehavior', { behavior: 'default' }).catch(() => {});
  if (browser) await browser.close();
}
