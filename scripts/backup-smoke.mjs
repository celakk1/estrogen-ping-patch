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
  await page.getByRole('button', { name: 'Saved settings', exact: true }).click();
  await page.getByRole('button', { name: 'Save settings copy', exact: true }).click();
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
  const nativeMtu = snapshot.settings.sections.filter(
    (section) => section.name === 'nativeIpInterface',
  );
  assert.equal(nativeMtu.length, snapshot.inventory.adapters.length * 2);
  let nativeDrivers = 0;
  for (const section of nativeMtu) {
    assert.ok(['ipv4', 'ipv6'].includes(section.addressFamily));
    if (section.status === 'captured') {
      const value = section.values[0];
      assert.equal(value.api, 'GetIpInterfaceEntry');
      assert.equal(value.linkApi, 'GetIfEntry2');
      assert.equal(value.schemaVersion, 2);
      assert.equal(value.registryApi, 'RegOpenKeyExW/RegQueryValueExW');
      if (value.registryOrigins.status === 'captured') {
        const evidence = value.registryOrigins.evidence;
        assert.equal(evidence.schemaVersion, 1);
        assert.equal(evidence.adapterGuid, value.adapterGuid);
        assert.deepEqual(
          evidence.stacks.map((stack) => stack.name),
          ['Tcpip', 'Tcpip6'],
        );
        let bytes = 0;
        for (const stack of evidence.stacks) {
          assert.equal(typeof stack.keyPresent, 'boolean');
          assert.deepEqual(
            stack.values.map((entry) => entry.name),
            [
              'MTU',
              'EnableDHCP',
              'IPAddress',
              'SubnetMask',
              'DefaultGateway',
              'NameServer',
              'DhcpNameServer',
              'ProfileNameServer',
              'Dhcpv6DNSServers',
            ],
          );
          for (const entry of stack.values) {
            if (!stack.keyPresent) assert.equal(entry.value, null);
            if (entry.value !== null) {
              assert.ok(Number.isInteger(entry.value.valueType));
              assert.match(entry.value.dataHex, /^(?:[0-9a-f]{2})*$/);
              bytes += entry.value.dataHex.length / 2;
            }
          }
        }
        assert.ok(bytes <= 4096);
      } else {
        assert.equal(value.registryOrigins.status, 'unavailable');
        assert.equal(typeof value.registryOrigins.error, 'string');
        assert.ok(value.unavailableFields.includes('registryOrigins'));
      }
      assert.equal(value.restorationVerified, false);
      assert.match(value.interfaceLuid, /^[0-9]+$/);
      assert.ok(value.os.build > 0 && value.os.major >= 10);
      assert.ok(Number.isInteger(value.os.updateRevision));
      assert.equal(value.settings.zoneIndices.length, 16);
      assert.ok(Number.isInteger(value.settings.nlMtu));
      assert.equal(typeof value.settings.useAutomaticMetric, 'boolean');
      assert.equal(
        value.adapterGuid.toLowerCase(),
        section.adapterId.replaceAll(/[{}]/g, '').toLowerCase(),
      );
      const adapter = snapshot.inventory.adapters.find(
        (adapter) => adapter.id === section.adapterId,
      );
      assert.equal(value.interfaceIndex, adapter.interfaceIndex);
      if (value.driver.status === 'captured') {
        nativeDrivers += 1;
        assert.ok(value.driver.identity.version.length > 0);
        assert.ok(value.driver.identity.deviceInstanceId.length > 0);
      } else {
        assert.equal(value.driver.status, 'unavailable');
        assert.equal(typeof value.driver.error, 'string');
        assert.ok(value.unavailableFields.includes('driverContext'));
      }
      assert.ok(value.unavailableFields.includes('persistentPolicyStore'));
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
  await page.getByRole('button', { name: 'Download settings copy', exact: true }).first().click();
  const download = await downloaded;
  assert.equal(await download.failure(), null);
  assert.match(download.suggestedFilename(), /^epp-network-backup-\d+-[a-f0-9]{64}\.json$/);
  const exportPath = path.resolve('artifacts', download.suggestedFilename());
  assert.equal(
    createHash('sha256').update(readFileSync(exportPath)).digest('hex'),
    record.summary.sha256,
  );
  await page.reload();
  await page.getByRole('button', { name: 'Saved settings', exact: true }).click();
  await page.getByRole('button', { name: 'View details', exact: true }).first().waitFor();
  const previousCount = await page.evaluate(
    async () => (await window.__TAURI_INTERNALS__.invoke('getBackups')).length,
  );
  await page.getByRole('button', { name: 'Save settings copy', exact: true }).click();
  await page.getByRole('button', { name: 'Cancel copy', exact: true }).click();
  await page.getByRole('status').waitFor({ timeout: 15_000 });
  assert.match(await page.getByRole('status').innerText(), /Copy cancelled/);
  const currentCount = await page.evaluate(
    async () => (await window.__TAURI_INTERNALS__.invoke('getBackups')).length,
  );
  assert.equal(currentCount, previousCount, 'Cancelled capture must not persist a partial backup');
  console.log(
    `Backup smoke passed: ${record.summary.capturedSections} captured sections, ${record.summary.unavailableSections} explicitly unavailable, ${nativeDns.filter((section) => section.status === 'captured').length}/${nativeDns.length} native DNS readers and ${nativeMtu.filter((section) => section.status === 'captured').length}/${nativeMtu.length} native IP rows succeeded (${nativeDrivers} with driver context), persisted history, matching adapter GUIDs, downloaded JSON with verified SHA-256, and cancellation without a partial record. Automatic restore remains disabled.`,
  );
} finally {
  if (session)
    await session.send('Browser.setDownloadBehavior', { behavior: 'default' }).catch(() => {});
  await browser.close();
}
