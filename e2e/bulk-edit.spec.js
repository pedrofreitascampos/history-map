// Bulk Edit: seed 5 locations, select a subset via checkboxes, apply a
// category change and confirm only the selected ones changed server-side.
// Then exercise the delete-confirm path: dismiss must delete nothing, confirm
// must delete exactly the selected count.

const { test, expect } = require('@playwright/test');
const { loginAs, authHeaders } = require('./helpers');

async function sweepLocations(request, headers) {
  const existing = await (await request.get('/api/locations', { headers })).json();
  for (const l of existing) {
    await request.delete('/api/locations/' + (l._id || l.id), { headers });
  }
}

test.describe('bulk edit', () => {
  // Leave the store exactly as this file found it (empty) — downstream specs
  // in file order (e.g. delete-popup, edit-modal) don't sweep and assume a
  // clean location store.
  test.afterEach(async ({ request }) => {
    const token = await loginAs(request);
    const headers = authHeaders(token);
    await sweepLocations(request, headers);
  });

  test('select 3 of 5, apply category change, only those 3 change', async ({ page, request }) => {
    const token = await loginAs(request);
    const headers = authHeaders(token);
    await sweepLocations(request, headers);

    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });

    const seedNames = ['BE-1', 'BE-2', 'BE-3', 'BE-4', 'BE-5'];
    const ids = [];
    for (const name of seedNames) {
      const res = await request.post('/api/locations', {
        headers,
        data: { name, lat: 38.7 + ids.length * 0.01, lng: -9.1, category: 'restaurant', status: 'been' },
      });
      expect(res.status()).toBe(200);
      const body = await res.json();
      ids.push(body._id || body.id);
    }

    await page.goto('/');
    await expect(page.locator('#login-screen')).toHaveClass(/hidden/);

    await page.locator('.nav-tab[data-arg0="bulk-view"]').click();
    await expect(page.locator('#bulk-view')).toHaveClass(/active/);

    await expect(page.locator('.bulk-cb')).toHaveCount(5, { timeout: 5_000 });

    const toChange = ids.slice(0, 3);
    for (const id of toChange) {
      await page.locator(`.bulk-cb[value="${id}"]`).check();
    }
    await expect(page.locator('#bulk-selected-count')).toHaveText('3 selected');

    await page.locator('#bulk-category').selectOption('museum');
    await page.locator('button[data-arg0="applyBulkEdit"]').click();

    await expect(page.locator('.toast', { hasText: 'Updated 3 locations' })).toBeVisible({ timeout: 5_000 });

    const list = await (await request.get('/api/locations', { headers })).json();
    for (const id of toChange) {
      const loc = list.find(l => (l._id || l.id) === id);
      expect(loc.category, `${id} should have changed to museum`).toBe('museum');
    }
    const untouched = ids.slice(3);
    for (const id of untouched) {
      const loc = list.find(l => (l._id || l.id) === id);
      expect(loc.category, `${id} should NOT have changed`).toBe('restaurant');
    }

    const realErrors = errors.filter(t => !/favicon|net::ERR_|Failed to load resource/i.test(t));
    expect(realErrors, realErrors.join('\n')).toEqual([]);
  });

  test('select all, dismiss delete confirm deletes nothing, confirming deletes exactly the selection', async ({ page, request }) => {
    const token = await loginAs(request);
    const headers = authHeaders(token);
    await sweepLocations(request, headers);

    const seedNames = ['BD-1', 'BD-2', 'BD-3', 'BD-4', 'BD-5'];
    const ids = [];
    for (const name of seedNames) {
      const res = await request.post('/api/locations', {
        headers,
        data: { name, lat: 38.7 + ids.length * 0.01, lng: -9.2, category: 'restaurant', status: 'been' },
      });
      expect(res.status()).toBe(200);
      const body = await res.json();
      ids.push(body._id || body.id);
    }

    await page.goto('/');
    await expect(page.locator('#login-screen')).toHaveClass(/hidden/);
    await page.locator('.nav-tab[data-arg0="bulk-view"]').click();
    await expect(page.locator('#bulk-view')).toHaveClass(/active/);
    await expect(page.locator('.bulk-cb')).toHaveCount(5, { timeout: 5_000 });

    await page.locator('button[data-click="selectAllBulk"]').click();
    await expect(page.locator('#bulk-selected-count')).toHaveText('5 selected');

    await page.locator('button[aria-label="Delete selected locations"]').click();
    const confirmOverlay = page.locator('.confirm-overlay');
    await expect(confirmOverlay).toBeVisible();

    // Dismiss — nothing must be deleted.
    await confirmOverlay.locator('.confirm-cancel').click();
    await expect(confirmOverlay).toHaveCount(0);
    let list = await (await request.get('/api/locations', { headers })).json();
    expect(list.length).toBe(5);

    // Clear selection, select exactly 2, delete and confirm.
    await page.locator('button[data-click="clearBulkSelection"]').click();
    await expect(page.locator('#bulk-selected-count')).toHaveText('0 selected');

    const toDelete = ids.slice(0, 2);
    for (const id of toDelete) {
      await page.locator(`.bulk-cb[value="${id}"]`).check();
    }
    await expect(page.locator('#bulk-selected-count')).toHaveText('2 selected');

    await page.locator('button[aria-label="Delete selected locations"]').click();
    const confirmOverlay2 = page.locator('.confirm-overlay');
    await expect(confirmOverlay2).toBeVisible();
    await confirmOverlay2.locator('.confirm-danger').click();

    await expect(page.locator('.toast', { hasText: '2 locations deleted' })).toBeVisible({ timeout: 5_000 });

    list = await (await request.get('/api/locations', { headers })).json();
    expect(list.length).toBe(3);
    for (const id of toDelete) {
      expect(list.find(l => (l._id || l.id) === id)).toBeUndefined();
    }
  });
});
