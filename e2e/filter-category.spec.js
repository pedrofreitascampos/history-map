// T8 (post-onclick-refactor): clicking a category filter chip narrows the
// rendered marker set. Exercises the sidebar's data-click="toggleCategory"
// conversion AND confirms the marker-diff path actually responds to the
// filter (which renderMarkers reads from the active category set).

const { test, expect } = require('@playwright/test');
const { loginAs, authHeaders } = require('./helpers');

test('category filter chip narrows the marker set', async ({ page, request }) => {
  const token = await loginAs(request);
  const headers = authHeaders(token);

  // Sweep any leftovers from earlier specs — this assertion is sensitive to
  // exact marker count, so we need a known baseline.
  const existing = await (await request.get('/api/locations', { headers })).json();
  for (const l of existing) {
    await request.delete('/api/locations/' + (l._id || l.id), { headers });
  }

  const seeds = [
    { name: 'CF-R1', lat: 38.71, lng: -9.14, category: 'restaurant', status: 'been' },
    { name: 'CF-R2', lat: 38.72, lng: -9.13, category: 'restaurant', status: 'been' },
    { name: 'CF-H1', lat: 38.73, lng: -9.12, category: 'hotel',      status: 'been' },
  ];
  for (const s of seeds) {
    const res = await request.post('/api/locations', { headers, data: s });
    expect(res.status()).toBe(200);
  }

  await page.goto('/');
  await expect(page.locator('#login-screen')).toHaveClass(/hidden/);
  await expect(page.locator('#map')).toBeVisible();

  await expect.poll(() => page.evaluate(() => window._renderState?.markerById?.size ?? 0))
    .toBe(3);

  // Sidebar category chips wire onclick via Element.onclick property
  // assignment (in populateCategoryFilters) — NOT an inline attribute, so
  // CSP doesn't gate them. Locate by the data-cat attribute the renderer sets.
  const hotelChip = page.locator('#category-filters .filter-chip[data-cat="hotel"]');
  await expect(hotelChip).toBeVisible();
  // Chips start ACTIVE (all categories selected). Click hotel ONCE to remove
  // it from the filter, then click each non-hotel chip to remove those too —
  // simplest path to "hotel only" without a dedicated select-one action.
  // Actually the existing chip toggles individually, so we need to remove
  // each non-hotel chip. Shortcut: click "clear all" then click hotel.
  await page.locator('#sidebar button', { hasText: /^clear all$/ }).first().click();
  await hotelChip.click();

  // After narrowing to hotel-only, only 1 marker should remain registered.
  await expect.poll(() => page.evaluate(() => window._renderState?.markerById?.size ?? 0))
    .toBe(1);
});
