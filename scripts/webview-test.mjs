import { setTimeout } from 'node:timers/promises';

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
