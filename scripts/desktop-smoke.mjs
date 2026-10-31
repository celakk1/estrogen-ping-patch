import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import { chromium } from 'playwright-core';
import { mkdirSync } from 'node:fs';

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
try {
  browser = await chromium.connectOverCDP(endpoint, { timeout: 15_000 });
  const page = browser
    .contexts()
    .flatMap((context) => context.pages())
    .find((page) => /127\.0\.0\.1:1420|tauri\.localhost/.test(page.url()));
  assert.ok(page, 'No estrogen ping patch test WebView found');
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
  await page.getByRole('button', { name: 'Benchmark history', exact: true }).click();
  assert.ok((await page.getByRole('cell', { name: 'completed', exact: true }).count()) > 0);
  await page.getByRole('button', { name: 'Safety & policy', exact: true }).click();
  assert.ok((await page.getByText('Disabled in this build', { exact: true }).count()) > 0);
  assert.deepEqual(errors, []);
  console.log(
    'Desktop smoke passed: real Windows inventory, six successful loopback measurements, persisted history, and visible safety boundary.',
  );
} finally {
  first.server.close();
  second.server.close();
  if (browser) await browser.close();
}
