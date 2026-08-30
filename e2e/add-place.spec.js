// Add-place is the single most-used feature in the app; before this spec it had
// zero E2E coverage. Covers: FAB open, auto-geocode success, auto-geocode
// failure (manual-coords fallback), map right-click context menu prefill, and
// the unsaved-changes discard path on Cancel.

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

test.describe('add place', () => {
  // Leave the store exactly as this file found it (empty), regardless of
  // which test ran or failed — several specs after this one in file order
  // do NOT sweep and assume a clean location store.
  test.afterEach(async ({ request }) => {
    const token = await loginAs(request);
    const headers = authHeaders(token);
    await sweepLocations(request, headers);
  });

  test('FAB → auto-geocode success → save creates a location and marker', async ({ page, request }) => {
    const token = await loginAs(request);
    const headers = authHeaders(token);
    await sweepLocations(request, headers);

    const errors = attachErrorCollectors(page);

    await page.goto('/');
    await expect(page.locator('#login-screen')).toHaveClass(/hidden/);
    await expect(page.locator('#map')).toBeVisible();

    await page.locator('#add-place-fab').click();
    await expect(page.locator('#edit-modal')).toHaveClass(/open/);

    await page.locator('#loc-name').fill('Eiffel Tower');
    // Trigger the focusout-bound auto-geocode.
    await page.locator('#loc-name').press('Tab');

    await expect.poll(async () => {
      const v = await page.locator('#loc-lat').inputValue();
      return v !== '';
    }, { timeout: 15_000 }).toBe(true);
    await expect.poll(async () => {
      const v = await page.locator('#loc-lng').inputValue();
      return v !== '';
    }, { timeout: 15_000 }).toBe(true);

    await page.locator('#modal-categories .category-option[data-cat="monument"]').click();
    await page.locator('#save-loc-btn').click();

    await expect(page.locator('#edit-modal')).not.toHaveClass(/open/, { timeout: 5_000 });
    await expect(page.locator('.leaflet-marker-icon')).toHaveCount(1, { timeout: 5_000 });

    const list = await (await request.get('/api/locations', { headers })).json();
    expect(list.length).toBe(1);
    expect(list[0].name).toBe('Eiffel Tower');
    expect(list[0].category).toBe('monument');

    expect(realErrors(errors), realErrors(errors).join('\n')).toEqual([]);
  });

  test('unresolvable name falls back to manual coords row, then saves once entered', async ({ page, request }) => {
    const token = await loginAs(request);
    const headers = authHeaders(token);
    await sweepLocations(request, headers);

    const errors = attachErrorCollectors(page);

    await page.goto('/');
    await expect(page.locator('#login-screen')).toHaveClass(/hidden/);

    await page.locator('#add-place-fab').click();
    await expect(page.locator('#edit-modal')).toHaveClass(/open/);

    // Coords row starts hidden.
    await expect(page.locator('#loc-coords-row')).toBeHidden();

    await page.locator('#loc-name').fill('zzzqqq nonexistent place 12345');
    await page.locator('#loc-name').press('Tab');
    // Give the (failing) auto-geocode fetch a moment to resolve before Save.
    await page.waitForTimeout(1500);

    await page.locator('#save-loc-btn').click();

    // Coords row must become visible and a warning toast must appear.
    await expect(page.locator('#loc-coords-row')).toBeVisible({ timeout: 5_000 });
    await expect(page.locator('.toast.warn')).toBeVisible({ timeout: 5_000 });

    // No location was created server-side.
    let list = await (await request.get('/api/locations', { headers })).json();
    expect(list.length).toBe(0);

    // Now fill in valid coords manually and save successfully.
    await page.locator('#loc-lat').fill('38.7223');
    await page.locator('#loc-lng').fill('-9.1393');
    await page.locator('#save-loc-btn').click();

    await expect(page.locator('#edit-modal')).not.toHaveClass(/open/, { timeout: 5_000 });
    list = await (await request.get('/api/locations', { headers })).json();
    expect(list.length).toBe(1);
    expect(list[0].name).toBe('zzzqqq nonexistent place 12345');
    expect(list[0].lat).toBeCloseTo(38.7223, 3);
    expect(list[0].lng).toBeCloseTo(-9.1393, 3);

    expect(realErrors(errors), realErrors(errors).join('\n')).toEqual([]);
  });

  test('map right-click context menu pre-fills coordinates on the add form', async ({ page, request }) => {
    const token = await loginAs(request);
    const headers = authHeaders(token);
    await sweepLocations(request, headers);

    const errors = attachErrorCollectors(page);

    await page.goto('/');
    await expect(page.locator('#login-screen')).toHaveClass(/hidden/);
    const map = page.locator('#map');
    await expect(map).toBeVisible();

    const box = await map.boundingBox();
    const x = box.x + box.width / 2;
    const y = box.y + box.height / 2;
    await page.mouse.click(x, y, { button: 'right' });

    const contextMenu = page.locator('#context-menu');
    await expect(contextMenu).toHaveClass(/open/);
    await page.locator('.context-menu-item', { hasText: 'Add location here' }).click();

    await expect(page.locator('#edit-modal')).toHaveClass(/open/);
    // Coords row must already be visible with non-empty pre-filled values.
    await expect(page.locator('#loc-coords-row')).toBeVisible();
    const lat = await page.locator('#loc-lat').inputValue();
    const lng = await page.locator('#loc-lng').inputValue();
    expect(lat).not.toBe('');
    expect(lng).not.toBe('');
    expect(Number.isNaN(parseFloat(lat))).toBe(false);
    expect(Number.isNaN(parseFloat(lng))).toBe(false);

    expect(realErrors(errors), realErrors(errors).join('\n')).toEqual([]);
  });

  // GENUINE BUG CHECK: the add-modal's Cancel/close routes through the same
  // closeModal() as the edit-modal, which is supposed to guard unsaved changes
  // with a "Discard unsaved changes?" confirm (showConfirm). If this assertion
  // fails, it proves openAddModal() never seeds `_editSnapshot` (it explicitly
  // nulls it), so closeModal()'s dirty check is a no-op for the Add flow and
  // typed-but-unsaved add-form data is silently discarded with no warning.
  test('cancel after typing unsaved changes prompts a discard confirm, and dismissing it keeps no location', async ({ page, request }) => {
    const token = await loginAs(request);
    const headers = authHeaders(token);
    await sweepLocations(request, headers);

    const errors = attachErrorCollectors(page);

    await page.goto('/');
    await expect(page.locator('#login-screen')).toHaveClass(/hidden/);

    await page.locator('#add-place-fab').click();
    await expect(page.locator('#edit-modal')).toHaveClass(/open/);

    await page.locator('#loc-name').fill('E2E Unsaved Add Cancel Target');
    await page.locator('#loc-notes').fill('some notes that should not be silently discarded');

    await page.locator('#edit-modal .modal-footer button.btn-secondary', { hasText: 'Cancel' }).click();

    const confirmOverlay = page.locator('.confirm-overlay');
    await expect(confirmOverlay, 'expected a discard-unsaved-changes confirm to appear on Cancel with dirty add-form fields').toBeVisible({ timeout: 3_000 });

    // Dismiss (Cancel the confirm) — modal must stay open, no location created.
    await confirmOverlay.locator('.confirm-cancel').click();
    await expect(page.locator('#edit-modal')).toHaveClass(/open/);

    const list = await (await request.get('/api/locations', { headers })).json();
    expect(list.length).toBe(0);

    expect(realErrors(errors), realErrors(errors).join('\n')).toEqual([]);
  });
});
