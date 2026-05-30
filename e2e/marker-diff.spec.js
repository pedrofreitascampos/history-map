// Guards the marker layer-diff perf refactor (2026-05-30).
//
// What it covers:
//   1. After login + initial render, _renderState.markerById tracks all 3 seeded
//      locations.
//   2. Clicking the "hotel" category filter shrinks the registry to 1 (the
//      restaurants are removed); the hotel marker is the SAME instance (not
//      rebuilt — diff path is in effect).
//   3. Clearing the filter brings restaurants back; the hotel marker is STILL
//      the same instance from step 2.
//
// A regression that reverts to clear-and-rebuild would cause every marker
// reference to change between renders → step 3's identity check would fail.

const { test, expect } = require('@playwright/test');
const { loginAs, authHeaders } = require('./helpers');

test('marker diff: category filter touches only deltas, untouched markers keep identity', async ({ page, request }) => {
  const token = await loginAs(request);
  const headers = authHeaders(token);

  // Sweep any leftovers from earlier specs — assertion is sensitive to count.
  const existing = await (await request.get('/api/locations', { headers })).json();
  for (const l of existing) {
    await request.delete('/api/locations/' + (l._id || l.id), { headers });
  }

  const seeds = [
    { name: 'E2E-R1', lat: 38.71, lng: -9.14, category: 'restaurant', status: 'been' },
    { name: 'E2E-R2', lat: 38.72, lng: -9.13, category: 'restaurant', status: 'been' },
    { name: 'E2E-H1', lat: 38.73, lng: -9.12, category: 'hotel',      status: 'been' },
  ];
  const ids = [];
  for (const s of seeds) {
    const res = await request.post('/api/locations', { headers, data: s });
    expect(res.status()).toBe(200);
    const body = await res.json();
    ids.push(body._id || body.id);
  }

  await page.goto('/');
  await expect(page.locator('#login-screen')).toHaveClass(/hidden/);
  await expect(page.locator('#map')).toBeVisible();

  // All 3 markers registered.
  await expect.poll(() => page.evaluate(() => window._renderState?.markerById?.size ?? 0))
    .toBe(3);

  // Capture the hotel marker's identity (object reference index) before filtering.
  // We tag each marker with a sentinel property and recover it after the diff.
  const hotelTaggedBefore = await page.evaluate((hotelId) => {
    const e = window._renderState.markerById.get(hotelId);
    if (!e) return false;
    e.marker.__e2eSentinel = 'before-filter';
    return true;
  }, ids[2]);
  expect(hotelTaggedBefore).toBe(true);

  // Click the hotel-only category chip (toggling "hotel" alone leaves it selected
  // since no other category is selected; with categories.size===1 the filter
  // requires hotel category).
  await page.locator('#category-filters button[data-cat="hotel"]').click();

  // Diff path removes the 2 restaurants. Wait for the debounced applyFilters.
  await expect.poll(() => page.evaluate(() => window._renderState?.markerById?.size ?? -1))
    .toBe(1);

  // The remaining marker is the hotel — its sentinel must still be there
  // (proves the diff path did NOT rebuild it).
  const hotelStillTagged = await page.evaluate((hotelId) => {
    const e = window._renderState.markerById.get(hotelId);
    return !!(e && e.marker.__e2eSentinel === 'before-filter');
  }, ids[2]);
  expect(hotelStillTagged, 'hotel marker was rebuilt — diff path regressed to clear+rebuild').toBe(true);

  // Clear the filter — restaurants come back; hotel still unchanged.
  await page.locator('#category-filters button[data-cat="hotel"]').click();
  await expect.poll(() => page.evaluate(() => window._renderState?.markerById?.size ?? -1))
    .toBe(3);

  const hotelSentinelAfterRestore = await page.evaluate((hotelId) => {
    const e = window._renderState.markerById.get(hotelId);
    return e?.marker?.__e2eSentinel || null;
  }, ids[2]);
  expect(hotelSentinelAfterRestore, 'hotel marker rebuilt during restore — diff registry lost identity').toBe('before-filter');
});
