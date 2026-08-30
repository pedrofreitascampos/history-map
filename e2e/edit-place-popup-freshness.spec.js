// Guards a just-fixed bug: markerHash() must include every field the popup
// renders (name, notes, tags, ...), or an edit that only touches one of those
// fields won't change the hash, renderMarkers() will skip rebuilding the
// marker, and its popup keeps a closure over the pre-edit location object
// (saveLocation replaces state.locations[idx] rather than mutating in place)
// — the popup then shows stale data indefinitely.

const { test, expect } = require('@playwright/test');
const { loginAs, authHeaders } = require('./helpers');

async function sweepLocations(request, headers) {
  const existing = await (await request.get('/api/locations', { headers })).json();
  for (const l of existing) {
    await request.delete('/api/locations/' + (l._id || l.id), { headers });
  }
}

async function openPopupForMarker(page) {
  await page.locator('.leaflet-marker-icon').first().click();
  await page.addStyleTag({ content: '.leaflet-popup-close-button{display:none!important;}' });
  await expect(page.locator('.leaflet-popup-content')).toBeVisible();
}

test.describe('edit-place popup freshness', () => {
  // Leave the store exactly as this file found it (empty) — downstream specs
  // in file order (e.g. filter-category, marker-diff) sweep themselves, but
  // keep the invariant tight regardless.
  test.afterEach(async ({ request }) => {
    const token = await loginAs(request);
    const headers = authHeaders(token);
    await sweepLocations(request, headers);
  });

  test('editing only name + notes refreshes the popup', async ({ page, request }) => {
    const token = await loginAs(request);
    const headers = authHeaders(token);
    await sweepLocations(request, headers);

    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });

    const seedRes = await request.post('/api/locations', {
      headers,
      data: {
        name: 'E2E Freshness Original', lat: 38.71, lng: -9.14,
        category: 'restaurant', status: 'been', notes: 'original notes',
      },
    });
    expect(seedRes.status()).toBe(200);
    const seeded = await seedRes.json();
    const locId = seeded._id || seeded.id;

    await page.goto('/');
    await expect(page.locator('#login-screen')).toHaveClass(/hidden/);
    await expect(page.locator('.leaflet-marker-icon')).toHaveCount(1, { timeout: 10_000 });

    // Open popup, confirm the ORIGINAL name/notes render.
    await openPopupForMarker(page);
    await expect(page.locator('.leaflet-popup-content h3')).toContainText('E2E Freshness Original');
    await expect(page.locator('.leaflet-popup-content')).toContainText('original notes');

    // Edit ONLY name + notes — category/status/rating/coords untouched.
    const editBtn = page.locator('.popup-btn', { hasText: 'Edit' }).first();
    await editBtn.click();
    await expect(page.locator('#edit-modal')).toHaveClass(/open/);
    await expect(page.locator('#loc-name')).toHaveValue('E2E Freshness Original');

    await page.locator('#loc-name').fill('E2E Freshness UPDATED');
    await page.locator('#loc-notes').fill('updated notes');
    await page.locator('#save-loc-btn').click();
    await expect(page.locator('#edit-modal')).not.toHaveClass(/open/, { timeout: 5_000 });

    // Re-open the popup — must reflect the NEW name/notes, not stale data.
    await page.locator('.leaflet-marker-icon').first().click();
    await expect(page.locator('.leaflet-popup-content h3')).toContainText('E2E Freshness UPDATED', { timeout: 5_000 });
    await expect(page.locator('.leaflet-popup-content')).toContainText('updated notes');
    await expect(page.locator('.leaflet-popup-content')).not.toContainText('E2E Freshness Original');

    const realErrors = errors.filter(t => !/favicon|net::ERR_|Failed to load resource/i.test(t));
    expect(realErrors, realErrors.join('\n')).toEqual([]);
  });

  test('editing only tags refreshes the popup', async ({ page, request }) => {
    const token = await loginAs(request);
    const headers = authHeaders(token);
    await sweepLocations(request, headers);

    const seedRes = await request.post('/api/locations', {
      headers,
      data: {
        name: 'E2E Tags Freshness', lat: 38.72, lng: -9.15,
        category: 'restaurant', status: 'been', tags: ['old-tag'],
      },
    });
    expect(seedRes.status()).toBe(200);

    await page.goto('/');
    await expect(page.locator('#login-screen')).toHaveClass(/hidden/);
    await expect(page.locator('.leaflet-marker-icon')).toHaveCount(1, { timeout: 10_000 });

    await openPopupForMarker(page);
    await expect(page.locator('.leaflet-popup-content')).toContainText('old-tag');

    const editBtn = page.locator('.popup-btn', { hasText: 'Edit' }).first();
    await editBtn.click();
    await expect(page.locator('#edit-modal')).toHaveClass(/open/);

    // Remove the old tag chip and add a new one — name/category/etc untouched.
    await page.locator('#loc-tag-chips button[aria-label="Remove old-tag"]').click();
    await page.locator('#loc-tag-input').fill('new-tag');
    await page.locator('#loc-tag-input').press('Enter');
    await page.locator('#save-loc-btn').click();
    await expect(page.locator('#edit-modal')).not.toHaveClass(/open/, { timeout: 5_000 });

    await page.locator('.leaflet-marker-icon').first().click();
    await expect(page.locator('.leaflet-popup-content')).toContainText('new-tag', { timeout: 5_000 });
  });
});
