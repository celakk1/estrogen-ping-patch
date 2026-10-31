import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { chromium } from 'playwright-core';
import { waitForDesktopPage } from './webview-test.mjs';

const endpoint = process.env.EPP_CDP_URL;
if (!endpoint || !/^http:\/\/127\.0\.0\.1:\d+$/.test(endpoint)) {
  throw new Error('EPP_CDP_URL must identify an explicitly launched loopback test instance.');
}
const browser = await chromium.connectOverCDP(endpoint, { timeout: 15_000 });
let session;
try {
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
  await page.reload();
  await page.getByRole('button', { name: 'Configuration backups', exact: true }).click();
  await page.getByRole('button', { name: 'Capture backup', exact: true }).click();
  await page.getByRole('heading', { name: /^Backup #/ }).waitFor({ timeout: 100_000 });
  assert.equal(await page.getByRole('alert').count(), 0);
  const record = await page.evaluate(async () => {
    const summaries = await window.__TAURI_INTERNALS__.invoke('getBackups');
    return window.__TAURI_INTERNALS__.invoke('exportBackup', { id: summaries[0].id });
  });
  const snapshot = JSON.parse(record.payloadJson);
  assert.equal(
    createHash('sha256').update(record.payloadJson, 'utf8').digest('hex'),
    record.summary.sha256,
  );
  assert.equal(snapshot.restoreStatus, 'notImplemented');
  assert.equal(snapshot.modificationsPermitted, false);
  assert.ok(snapshot.settings.sections.length >= 6);
  const capturedRecords = snapshot.settings.sections.flatMap((section) => section.values);
  assert.ok(capturedRecords.length > 0);
  assert.ok(capturedRecords.every((record) => Array.isArray(record.unavailableFields)));
  assert.equal(
    snapshot.settings.sections.length,
    record.summary.capturedSections + record.summary.unavailableSections,
  );
  const adapterIds = new Set(snapshot.inventory.adapters.map((adapter) => adapter.id));
  const nativeDns = snapshot.settings.sections.filter(
    (section) => section.name === 'nativeInterfaceDns',
  );
  assert.equal(nativeDns.length, snapshot.inventory.adapters.length);
  for (const section of nativeDns) {
    if (section.status === 'captured') {
      const value = section.values[0];
      assert.equal(value.api, 'GetInterfaceDnsSettings');
      assert.equal(value.version, 1);
      assert.match(value.flagsHex, /^0x[a-f0-9]{16}$/);
      for (const key of ['domain', 'nameServer', 'searchList', 'profileNameServer']) {
        assert.ok(value[key] === null || typeof value[key] === 'string');
      }
    } else {
      assert.equal(section.status, 'unavailable');
      assert.equal(typeof section.error, 'string');
    }
  }
  assert.ok(
    snapshot.settings.sections
      .filter((section) => section.adapterId)
      .every((section) => adapterIds.has(section.adapterId)),
  );
  mkdirSync('artifacts', { recursive: true });
  session = await page.context().newCDPSession(page);
  await session.send('Browser.setDownloadBehavior', {
    behavior: 'allow',
    downloadPath: path.resolve('artifacts'),
    eventsEnabled: true,
  });
  const downloaded = page.waitForEvent('download', { timeout: 15_000 });
  await page.getByRole('button', { name: 'Export backup', exact: true }).first().click();
  const download = await downloaded;
  assert.equal(await download.failure(), null);
  assert.match(download.suggestedFilename(), /^epp-network-backup-\d+-[a-f0-9]{64}\.json$/);
  const exportPath = path.resolve('artifacts', download.suggestedFilename());
  assert.equal(
    createHash('sha256').update(readFileSync(exportPath)).digest('hex'),
    record.summary.sha256,
  );
  await page.reload();
  await page.getByRole('button', { name: 'Configuration backups', exact: true }).click();
  await page.getByRole('button', { name: 'View details', exact: true }).first().waitFor();
  const previousCount = await page.evaluate(
    async () => (await window.__TAURI_INTERNALS__.invoke('getBackups')).length,
  );
  await page.getByRole('button', { name: 'Capture backup', exact: true }).click();
  await page.getByRole('button', { name: 'Cancel capture', exact: true }).click();
  await page.getByRole('status').waitFor({ timeout: 15_000 });
  assert.match(await page.getByRole('status').innerText(), /Capture cancelled/);
  const currentCount = await page.evaluate(
    async () => (await window.__TAURI_INTERNALS__.invoke('getBackups')).length,
  );
  assert.equal(currentCount, previousCount, 'Cancelled capture must not persist a partial backup');
  console.log(
    `Backup smoke passed: ${record.summary.capturedSections} captured sections, ${record.summary.unavailableSections} explicitly unavailable, ${nativeDns.filter((section) => section.status === 'captured').length}/${nativeDns.length} native DNS readers succeeded, persisted history, matching adapter GUIDs, downloaded JSON with verified SHA-256, and cancellation without a partial record. Automatic restore remains disabled.`,
  );
} finally {
  if (session)
    await session.send('Browser.setDownloadBehavior', { behavior: 'default' }).catch(() => {});
  await browser.close();
}
