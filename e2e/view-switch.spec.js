// T6 (post-onclick-refactor): every nav tab is wired through the click
// dispatcher — clicking each one must switch the active view and produce no
// console errors. Guards the regression class "I missed converting one
// onclick to data-click" by exercising EVERY tab in sequence.

const { test, expect } = require('@playwright/test');

const TABS = [
  ['stats-view',       'Stats'],
  ['chrono-view',      'Chronology'],
  ['trips-view',       'Trips'],
  ['transits-view',    'Transits'],
  ['collections-view', 'Collections'],
  ['regions-view',     'Regions'],
  ['bulk-view',        'Bulk Edit'],
  ['import-view',      'Import'],
  ['map-view',         'Map'],
];

test('every nav tab switches the active view via the dispatcher', async ({ page }) => {
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });

  await page.goto('/');
  await expect(page.locator('#login-screen')).toHaveClass(/hidden/);
  await expect(page.locator('#map-view')).toHaveClass(/active/);

  for (const [viewId, label] of TABS) {
    await page.locator(`.nav-tab[data-arg0="${viewId}"]`).click();
    await expect(page.locator(`#${viewId}`)).toHaveClass(/active/, { timeout: 3_000 });
  }

  const real = errors.filter(t => !/favicon|net::ERR_|Failed to load resource/i.test(t));
  expect(real, `Console / page errors:\n${real.join('\n')}`).toEqual([]);
});
