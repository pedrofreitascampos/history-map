// Guards against crashes on empty data and on filter combinations that match
// nothing. The map view currently has NO empty-state message overlay for
// either case — this spec intentionally does NOT assert one exists (that
// would be asserting a feature that doesn't exist). It only asserts the
// no-error / no-marker baseline. See TODO below for the missing UX.

const { test, expect } = require('@playwright/test');
const { loginAs, authHeaders } = require('./helpers');

async function sweepLocations(request, headers) {
  const existing = await (await request.get('/api/locations', { headers })).json();
  for (const l of existing) {
    await request.delete('/api/locations/' + (l._id || l.id), { headers });
  }
}

function attachErrorCollectors(page) {
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });
  return errors;
}
function realErrors(errors) {
  return errors.filter(t => !/favicon|net::ERR_|Failed to load resource/i.test(t));
}

test.describe('empty and filter states', () => {
  // Leave the store exactly as this file found it (empty) — downstream specs
  // in file order (e.g. filter-category, marker-diff) sweep themselves, but
  // keep the invariant tight regardless.
  test.afterEach(async ({ request }) => {
    const token = await loginAs(request);
    const headers = authHeaders(token);
    await sweepLocations(request, headers);
  });

  test('zero-location account renders the map cleanly with no markers', async ({ page, request }) => {
    const token = await loginAs(request);
    const headers = authHeaders(token);
    await sweepLocations(request, headers);

    const errors = attachErrorCollectors(page);

    await page.goto('/');
    await expect(page.locator('#login-screen')).toHaveClass(/hidden/);
    await expect(page.locator('#map')).toBeVisible();
    await page.waitForTimeout(500);

    await expect.poll(() => page.evaluate(() => window._renderState?.markerById?.size ?? -1))
      .toBe(0);
    await expect(page.locator('.leaflet-marker-icon')).toHaveCount(0);

    // TODO: the map view has no empty-state message for a zero-location
    // account (unlike trip-detail / people-manager / trips-manager, which do
    // show one). Consider adding a "No places yet — click + to add one"
    // overlay here.

    expect(realErrors(errors), realErrors(errors).join('\n')).toEqual([]);
  });

  test('a filter combination matching nothing renders no markers and no errors', async ({ page, request }) => {
    const token = await loginAs(request);
    const headers = authHeaders(token);
    await sweepLocations(request, headers);

    const errors = attachErrorCollectors(page);

    const seeds = [
      { name: 'EFS-R1', lat: 38.71, lng: -9.14, category: 'restaurant', status: 'been' },
      { name: 'EFS-H1', lat: 38.72, lng: -9.13, category: 'hotel', status: 'been' },
    ];
    for (const s of seeds) {
      const res = await request.post('/api/locations', { headers, data: s });
      expect(res.status()).toBe(200);
    }

    await page.goto('/');
    await expect(page.locator('#login-screen')).toHaveClass(/hidden/);
    await expect.poll(() => page.evaluate(() => window._renderState?.markerById?.size ?? 0))
      .toBe(2);

    // Narrow to "hotel" only, then also apply a status filter of "bucket"
    // (wishlist) — both seeded locations are status "been", so no location
    // can match both filters, yielding zero results.
    await page.locator('#sidebar button', { hasText: /^clear all$/ }).first().click();
    await page.locator('#category-filters .filter-chip[data-cat="hotel"]').click();
    await page.locator('#sidebar button[data-status="bucket"]').click();

    await expect.poll(() => page.evaluate(() => window._renderState?.markerById?.size ?? -1), { timeout: 5_000 })
      .toBe(0);
    await expect(page.locator('.leaflet-marker-icon')).toHaveCount(0);

    // TODO: no empty-state message is shown in the map view when a filter
    // combination matches nothing — the sidebar and map simply go quiet.

    expect(realErrors(errors), realErrors(errors).join('\n')).toEqual([]);
  });
});
