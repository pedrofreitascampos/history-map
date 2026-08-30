// Guards a just-fixed data-loss bug: pressing Ctrl+K while the edit modal is
// open used to stack the quick-add modal on top. Picking a quick-add result
// routes through openAddModal(), which reuses the SAME #edit-modal element and
// would silently wipe unsaved edits with no warning. The fix is a guard in the
// keydown handler: if any `.modal-overlay.open` exists, Ctrl+K is a no-op.

const { test, expect } = require('@playwright/test');
const { loginAs, authHeaders } = require('./helpers');

async function sweepLocations(request, headers) {
  const existing = await (await request.get('/api/locations', { headers })).json();
  for (const l of existing) {
    await request.delete('/api/locations/' + (l._id || l.id), { headers });
  }
}

test.describe('Ctrl+K modal guard', () => {
  // Leave the store exactly as this file found it (empty) — downstream specs
  // in file order (e.g. delete-popup, edit-modal) don't sweep and assume a
  // clean location store.
  test.afterEach(async ({ request }) => {
    const token = await loginAs(request);
    const headers = authHeaders(token);
    await sweepLocations(request, headers);
  });

  test('Ctrl+K does not stack quick-add over an open, dirty edit modal', async ({ page, request }) => {
    const token = await loginAs(request);
    const headers = authHeaders(token);
    const existing = await (await request.get('/api/locations', { headers })).json();
    for (const l of existing) {
      await request.delete('/api/locations/' + (l._id || l.id), { headers });
    }

    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });

    const seedRes = await request.post('/api/locations', {
      headers,
      data: { name: 'E2E CtrlK Guard Target', lat: 38.71, lng: -9.14, category: 'restaurant', status: 'been' },
    });
    expect(seedRes.status()).toBe(200);
    const seeded = await seedRes.json();
    const locId = seeded._id || seeded.id;

    await page.goto('/');
    await expect(page.locator('#login-screen')).toHaveClass(/hidden/);

    await page.evaluate((id) => window.openEditModal(id), locId);
    await expect(page.locator('#edit-modal')).toHaveClass(/open/);

    const typedValue = 'UNSAVED-EDIT-IN-PROGRESS';
    await page.locator('#loc-name').fill(typedValue);

    await page.keyboard.press('Control+k');

    // Quick-add must NOT open on top.
    await expect(page.locator('#quick-add-modal')).not.toHaveClass(/open/);
    // Edit modal must still be open, with the typed value intact.
    await expect(page.locator('#edit-modal')).toHaveClass(/open/);
    await expect(page.locator('#loc-name')).toHaveValue(typedValue);

    const realErrors = errors.filter(t => !/favicon|net::ERR_|Failed to load resource/i.test(t));
    expect(realErrors, realErrors.join('\n')).toEqual([]);
  });

  test('Ctrl+K opens quick-add with no modal open, and closes it on a second press', async ({ page, request }) => {
    const token = await loginAs(request);
    const headers = authHeaders(token);

    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });

    await page.goto('/');
    await expect(page.locator('#login-screen')).toHaveClass(/hidden/);
    await expect(page.locator('.modal-overlay.open')).toHaveCount(0);

    await page.keyboard.press('Control+k');
    await expect(page.locator('#quick-add-modal')).toHaveClass(/open/, { timeout: 3_000 });

    await page.keyboard.press('Control+k');
    await expect(page.locator('#quick-add-modal')).not.toHaveClass(/open/, { timeout: 3_000 });

    const realErrors = errors.filter(t => !/favicon|net::ERR_|Failed to load resource/i.test(t));
    expect(realErrors, realErrors.join('\n')).toEqual([]);
  });
});
