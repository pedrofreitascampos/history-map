// Covers the trip lifecycle end to end: create a trip through the UI, assign a
// seeded location to it, verify the trip-detail view lists the stop, verify a
// cost set on a trip location actually persists (the server allowlist used to
// silently drop `cost` until it was fixed), then delete the trip and confirm
// the location survives with its tripId cleared.

const { test, expect } = require('@playwright/test');
const { loginAs, authHeaders } = require('./helpers');

async function sweepAll(request, headers) {
  const locs = await (await request.get('/api/locations', { headers })).json();
  for (const l of locs) await request.delete('/api/locations/' + (l._id || l.id), { headers });
  const trips = await (await request.get('/api/trips', { headers })).json();
  for (const t of trips) await request.delete('/api/trips/' + (t._id || t.id), { headers });
}

test.describe('trip lifecycle', () => {
  test.afterEach(async ({ request }) => {
    const token = await loginAs(request);
    const headers = authHeaders(token);
    await sweepAll(request, headers);
  });

  test('create trip, assign location, cost persists, delete trip unlinks location', async ({ page, request }) => {
    const token = await loginAs(request);
    const headers = authHeaders(token);
    await sweepAll(request, headers);

    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });

    const seedRes = await request.post('/api/locations', {
      headers,
      data: { name: 'E2E Trip Stop', lat: 38.71, lng: -9.14, category: 'hotel', status: 'been' },
    });
    expect(seedRes.status()).toBe(200);
    const seeded = await seedRes.json();
    const locId = seeded._id || seeded.id;

    await page.goto('/');
    await expect(page.locator('#login-screen')).toHaveClass(/hidden/);

    // Create a trip through the trips view UI.
    await page.locator('.nav-tab[data-arg0="trips-view"]').click();
    await expect(page.locator('#trips-view')).toHaveClass(/active/);

    await page.locator('#trips-view button', { hasText: '+ New Trip' }).click();
    const promptOverlay = page.locator('.confirm-overlay');
    await expect(promptOverlay).toBeVisible();
    await promptOverlay.locator('.mp-field[data-idx="0"]').fill('E2E Lifecycle Trip');
    await promptOverlay.locator('button.btn-primary', { hasText: 'OK' }).click();
    await expect(promptOverlay).toHaveCount(0);

    // Confirm the trip now exists server-side and grab its id.
    const trips = await (await request.get('/api/trips', { headers })).json();
    const trip = trips.find(t => t.name === 'E2E Lifecycle Trip');
    expect(trip, 'trip was not created').toBeTruthy();
    const tripId = trip._id || trip.id;

    // Assign the seeded location to the trip via its edit modal, and set a cost.
    await page.evaluate((id) => window.openEditModal(id), locId);
    await expect(page.locator('#edit-modal')).toHaveClass(/open/);
    await page.locator('#loc-trip').selectOption(tripId);
    await page.locator('#loc-cost').fill('123.45');
    await page.locator('#save-loc-btn').click();
    await expect(page.locator('#edit-modal')).not.toHaveClass(/open/, { timeout: 5_000 });

    // Open the trip detail and assert the stop is listed.
    await page.locator('#trip-selector').selectOption(tripId);
    await expect(page.locator('#trip-detail')).toContainText('E2E Trip Stop', { timeout: 5_000 });

    // Reopen the location's edit modal and assert the cost persisted server-side
    // AND is reflected back into the form (guards the server allowlist fix).
    const afterAssign = await (await request.get('/api/locations', { headers })).json();
    const stop = afterAssign.find(l => (l._id || l.id) === locId);
    expect(stop.tripId).toBe(tripId);
    expect(stop.cost).toBe(123.45);

    await page.evaluate((id) => window.openEditModal(id), locId);
    await expect(page.locator('#edit-modal')).toHaveClass(/open/);
    await expect(page.locator('#loc-cost')).toHaveValue('123.45');
    await page.locator('#edit-modal .modal-close').click();

    // Delete the trip; the location must survive with tripId cleared.
    await page.evaluate(() => window.openTripManager());
    const deleteBtn = page.locator(`#trips-manager-list button[data-click="deleteTrip"][data-arg0="${tripId}"]`);
    await expect(deleteBtn).toBeVisible({ timeout: 5_000 });
    await deleteBtn.click();
    const confirmDanger = page.locator('.confirm-overlay .confirm-danger');
    await expect(confirmDanger).toBeVisible();
    await confirmDanger.click();
    await expect(deleteBtn).toHaveCount(0, { timeout: 5_000 });

    const tripsAfter = await (await request.get('/api/trips', { headers })).json();
    expect(tripsAfter.find(t => (t._id || t.id) === tripId)).toBeUndefined();

    const locsAfter = await (await request.get('/api/locations', { headers })).json();
    const survivor = locsAfter.find(l => (l._id || l.id) === locId);
    expect(survivor, 'location was deleted along with the trip').toBeTruthy();
    expect(survivor.tripId).toBeFalsy();

    const realErrors = errors.filter(t => !/favicon|net::ERR_|Failed to load resource/i.test(t));
    expect(realErrors, realErrors.join('\n')).toEqual([]);
  });
});
