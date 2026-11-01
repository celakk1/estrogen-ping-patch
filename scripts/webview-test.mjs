import { setTimeout } from 'node:timers/promises';
import assert from 'node:assert/strict';

export async function verifyTestActionFits(page, label, screenshotPrefix) {
  const originalFont = await page.evaluate(() => document.documentElement.style.fontFamily);
  try {
    for (const [name, font] of [
      ['default', originalFont],
      ['windows-font', "'Segoe UI', sans-serif"],
    ]) {
      await page.evaluate((font) => {
        document.documentElement.style.fontFamily = font;
      }, font);
      await page.screenshot({ path: `${screenshotPrefix}-${name}.png`, fullPage: true });
      const bounds = await page.getByRole('button', { name: label, exact: true }).boundingBox();
      assert.ok(
        bounds && bounds.y >= 0 && bounds.y + bounds.height <= 744,
        `${label} must fit with 24 pixels to spare at 1024 by 768 (${name}): ${JSON.stringify(bounds)}`,
      );
      assert.ok(
        await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
        'Narrow layout must not overflow horizontally',
      );
    }
  } finally {
    await page.evaluate((font) => {
      document.documentElement.style.fontFamily = font;
    }, originalFont);
  }
}

export async function waitForDesktopPage(browser, timeoutMs = 15_000) {
  const deadline = performance.now() + timeoutMs;
  let observedUrls = [];
  do {
    const pages = browser.contexts().flatMap((context) => context.pages());
    const desktop = pages.find((page) =>
      /^https?:\/\/(?:127\.0\.0\.1:1420|tauri\.localhost)(?:\/|$)/.test(page.url()),
    );
    if (desktop) return desktop;
    observedUrls = pages.map((page) => page.url());
    await setTimeout(Math.min(50, Math.max(0, deadline - performance.now())));
  } while (performance.now() < deadline);
  throw new Error(
    `Desktop WebView did not become ready within ${timeoutMs} ms. Observed URLs: ${JSON.stringify(observedUrls)}`,
  );
}
