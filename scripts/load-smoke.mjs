import assert from 'node:assert/strict';
import { chromium } from 'playwright-core';
import { mkdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { createBenchmarkServer } from './benchmark-server.mjs';
import { waitForDesktopPage } from './webview-test.mjs';

const endpoint = process.env.EPP_CDP_URL;
if (!endpoint || !/^http:\/\/127\.0\.0\.1:\d+$/.test(endpoint))
  throw new Error(
    'A loopback EPP_CDP_URL for an explicitly launched isolated desktop is required.',
  );
const fixture = await createBenchmarkServer({ throttleMs: 25 });
let browser;
let session;
try {
  browser = await chromium.connectOverCDP(endpoint, { timeout: 15_000 });
  const page = await waitForDesktopPage(browser);
  if (process.env.EPP_DATA_DIR) {
    const status = await page.evaluate(() => window.__TAURI_INTERNALS__.invoke('status'));
    assert.equal(
      path.resolve(status.dataDirectory).toLowerCase(),
      path.resolve(process.env.EPP_DATA_DIR).toLowerCase(),
    );
  }
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.getByRole('button', { name: 'Network tests', exact: true }).click();
  await page.getByRole('button', { name: /^Speed test\b/ }).click();
  assert.equal(await page.getByLabel('Use Cloudflare for the speed test').isVisible(), false);
  await page.evaluate(() => window.scrollTo(0, 0));
  mkdirSync('artifacts', { recursive: true });
  await page.screenshot({ path: 'artifacts/desktop-beginner-load.png', fullPage: true });
  const viewport = await page.evaluate(() => ({
    width: window.innerWidth,
    height: window.innerHeight,
  }));
  await page.setViewportSize({ width: 1024, height: 768 });
  await page.screenshot({ path: 'artifacts/desktop-beginner-load-narrow.png', fullPage: true });
  const startBounds = await page
    .getByRole('button', { name: 'Start speed test', exact: true })
    .boundingBox();
  assert.ok(
    startBounds && startBounds.y >= 0 && startBounds.y + startBounds.height <= 744,
    `Start speed test must fit with 24 pixels to spare at 1024 by 768: ${JSON.stringify(startBounds)}`,
  );
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
  await page.setViewportSize(viewport);
  async function configure() {
    const advanced = page
      .getByLabel('Use Cloudflare for the speed test')
      .locator('..')
      .locator('..')
      .locator('..');
    if ((await advanced.getAttribute('open')) == null) {
      await advanced.locator(':scope > summary').click();
    }
    await page.getByLabel('Use Cloudflare for the speed test').uncheck();
    await page.getByLabel('Your own test server URL (optional)').fill(fixture.origin);
    await page.getByLabel('Download amount per server (MiB)').fill('2');
    await page.getByLabel('Upload amount per server (MiB)').fill('2');
    await page.getByLabel('Transfers at the same time').selectOption('2');
    await page.getByLabel('Response test server 1 (IP)').fill('127.0.0.1');
    await page.getByLabel('Response test server 2 (IP)').fill('::1');
    await advanced.locator(':scope > summary').click();
  }
  await configure();
  await page.getByRole('button', { name: 'Start speed test', exact: true }).click();
  await page
    .getByRole('button', { name: 'Export raw data (JSON)', exact: true })
    .waitFor({ timeout: 30_000 });
  const run = await page.evaluate(
    async () => (await window.__TAURI_INTERNALS__.invoke('getLoadHistory'))[0],
  );
  assert.equal(run.status, 'completed');
  assert.equal(run.transfers.length, 2);
  assert.equal(run.plan.providers.length, 1);
  for (const phase of run.transfers) {
    assert.equal(phase.result.status, 'completed');
    assert.equal(phase.result.provider.origin, fixture.origin);
    assert.equal(phase.result.acceptedPayloadBytes, 2 * 1024 * 1024);
    assert.equal(phase.result.streams.length, 2);
    assert.ok(phase.result.applicationGoodputMbps > 0);
    for (const stream of phase.result.streams) {
      assert.equal(stream.httpStatus, 200);
      assert.equal(stream.status, 'completed');
      assert.match(stream.remoteAddress, /^127\.0\.0\.1:/);
    }
  }
  assert.equal(fixture.totals.downloadBytes, 2 * 1024 * 1024);
  assert.equal(fixture.totals.uploadBytes, 2 * 1024 * 1024);
  assert.equal(fixture.totals.requests, 4);
  for (const phase of ['idle', 'recovery']) {
    assert.equal(run.latencySamples.filter((sample) => sample.phase === phase).length, 6);
  }
  assert.ok(
    run.latencySamples.some(
      (sample) =>
        ['download', 'upload'].includes(sample.phase) &&
        sample.inFlightRequestsAtStart > 0 &&
        sample.inFlightRequestsAtEnd > 0,
    ),
  );
  assert.ok(
    run.latencySamples.every(
      (sample) => sample.sample.echo.status === 'reply' && sample.sample.connectMs === null,
    ),
  );
  session = await page.context().newCDPSession(page);
  mkdirSync('artifacts', { recursive: true });
  await session.send('Browser.setDownloadBehavior', {
    behavior: 'allow',
    downloadPath: path.resolve('artifacts'),
    eventsEnabled: true,
  });
  for (const format of ['JSON', 'HTML']) {
    const downloaded = page.waitForEvent('download', { timeout: 15_000 });
    await page
      .getByRole('button', {
        name: format === 'HTML' ? 'Save report' : 'Export raw data (JSON)',
        exact: true,
      })
      .click();
    const download = await downloaded;
    assert.equal(await download.failure(), null);
    const content = readFileSync(path.resolve('artifacts', download.suggestedFilename()), 'utf8');
    if (format === 'JSON') assert.deepEqual(JSON.parse(content), run);
    else {
      assert.match(content, /Measured speed/);
      assert.match(content, /Saturation is not guaranteed/);
      assert.match(content, /After traffic/);
    }
  }
  await session.send('Browser.setDownloadBehavior', { behavior: 'default' });
  await page.evaluate(() => window.scrollTo(0, 0));
  assert.ok(
    await page
      .getByRole('table', { name: 'Response times by stage for test server 1' })
      .isVisible(),
  );
  await page.screenshot({ path: 'artifacts/desktop-load-session.png', fullPage: true });
  await page.reload();
  await page.getByRole('button', { name: /^Speed test\b/ }).click();
  await page.getByRole('button', { name: 'View report', exact: true }).first().click();
  await page.getByRole('button', { name: 'Export raw data (JSON)', exact: true }).waitFor();
  await configure();
  await page.getByRole('button', { name: 'Start speed test', exact: true }).click();
  await page.getByRole('button', { name: 'Stop speed test', exact: true }).click();
  await page
    .getByRole('button', { name: 'Export raw data (JSON)', exact: true })
    .waitFor({ timeout: 10_000 });
  const cancelled = await page.evaluate(
    async () => (await window.__TAURI_INTERNALS__.invoke('getLoadHistory'))[0],
  );
  assert.equal(cancelled.status, 'cancelled');
  assert.equal(cancelled.transfers.length, 0);
  assert.equal(fixture.totals.requests, 4);
  assert.deepEqual(errors, []);
  console.log(
    'Load smoke passed: two-stream download/upload against a loopback server, exact accepted payload budgets, concurrent IPv4/IPv6 ICMP and recovery samples, saved history, JSON/HTML downloads, and idle cancellation without transfer requests.',
  );
} finally {
  if (session)
    await session.send('Browser.setDownloadBehavior', { behavior: 'default' }).catch(() => {});
  if (browser) await browser.close();
  await fixture.close();
}
