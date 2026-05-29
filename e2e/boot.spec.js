// T1: App boots, login screen is bypassed via storageState, map view is reachable,
// and no uncaught console errors / page errors fire during boot.
// Guards the "single inline-script syntax error kills the entire frontend" class
// (the failure mode that caused the prior login outage).

const { test, expect } = require('@playwright/test');

test('app boots without console or page errors', async ({ page }) => {
  const consoleErrors = [];
  const pageErrors = [];
  page.on('console', msg => {
    if (msg.type() === 'error') consoleErrors.push(msg.text());
  });
  page.on('pageerror', err => {
    pageErrors.push(err.message);
  });

  await page.goto('/');

  // Login screen must auto-hide because storageState seeded hm_token.
  await expect(page.locator('#login-screen')).toHaveClass(/hidden/, { timeout: 10_000 });
  await expect(page.locator('#map')).toBeVisible();

  // Give late-init (Leaflet tiles, marker render) a beat to finish.
  await page.waitForTimeout(500);

  // pageerror = uncaught exception in the page context. Zero tolerance —
  // a single inline-script syntax error would surface here.
  expect(pageErrors, `Page errors:\n${pageErrors.join('\n')}`).toEqual([]);

  // Console errors are noisier (CDN 404s, etc.). Filter to ones that look
  // like real JS errors, not network noise.
  const realErrors = consoleErrors.filter(t =>
    !/favicon|net::ERR_|Failed to load resource|net::ERR_INTERNET_DISCONNECTED/i.test(t)
  );
  expect(realErrors, `Console errors:\n${realErrors.join('\n')}`).toEqual([]);
});
