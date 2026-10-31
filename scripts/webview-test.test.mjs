import assert from 'node:assert/strict';
import test from 'node:test';
import { waitForDesktopPage } from './webview-test.mjs';

test('browser endpoint readiness does not require the desktop page to exist yet', async () => {
  const started = performance.now();
  const desktop = {
    url: () => (performance.now() - started < 60 ? 'about:blank' : 'http://tauri.localhost/'),
  };
  const browser = {
    contexts: () => [{ pages: () => (performance.now() - started < 20 ? [] : [desktop]) }],
  };
  assert.equal(await waitForDesktopPage(browser, 2000), desktop);
});

test('an unexpected page cannot satisfy desktop readiness and is reported on timeout', async () => {
  const browser = { contexts: () => [{ pages: () => [{ url: () => 'about:blank' }] }] };
  await assert.rejects(waitForDesktopPage(browser, 20), /Observed URLs: \["about:blank"\]/);
});
