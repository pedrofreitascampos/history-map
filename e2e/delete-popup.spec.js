// T2: Deleting a location from its map popup actually removes it from the
// server. Guards the showConfirm-callback-vs-promise regression class — the
// popup ✕ button awaits showConfirm, so a silent revert would skip the DELETE.

const { test, expect } = require('@playwright/test');
const { loginAs, authHeaders } = require('./helpers');

test('delete from popup removes the location from server state', async ({ page, request }) => {
  const token = await loginAs(request);
  const headers = authHeaders(token);

  // Seed a single location at known coords.
  const seedRes = await request.post('/api/locations', {
    headers,
    data: {
      name: 'E2E Popup Delete Target',
      lat: 38.7223,
      lng: -9.1393,
      category: 'restaurant',
      status: 'been',
    },
  });
  expect(seedRes.status()).toBe(200);
  const seeded = await seedRes.json();
  const locId = seeded._id || seeded.id;
  expect(locId).toBeTruthy();

  await page.goto('/');
  await expect(page.locator('#login-screen')).toHaveClass(/hidden/);
  await expect(page.locator('#map')).toBeVisible();

  // Wait for the seeded marker to render. There's only one location in this
  // user's account for this spec — locate it by its category emoji class.
  const marker = page.locator('.leaflet-marker-icon').first();
  await expect(marker).toBeVisible({ timeout: 10_000 });
  await marker.click();

  // Popup opens with the ✕ Remove location button.
  // Leaflet's own .leaflet-popup-close-button sits at top-right and overlaps
  // the popup delete × (also top-right). Hide it for the duration of the test
  // so the real click path reaches deleteFromPopup → showConfirm.
  await page.addStyleTag({ content: '.leaflet-popup-close-button{display:none!important;}' });
  const removeBtn = page.locator('button[aria-label="Remove location"]');
  await expect(removeBtn).toBeVisible();
  await removeBtn.click();

  // Confirm modal is dynamically appended; click the danger button.
  const confirmDanger = page.locator('.confirm-overlay .confirm-danger');
  await expect(confirmDanger).toBeVisible();
  await confirmDanger.click();

  // Wait for the success toast as a positive signal the DELETE completed.
  await expect(page.locator('.toast', { hasText: 'Location deleted' })).toBeVisible({ timeout: 5_000 });

  // Authoritative check: the server no longer has the row.
  const listRes = await request.get('/api/locations', { headers });
  expect(listRes.status()).toBe(200);
  const list = await listRes.json();
  const stillThere = list.find(l => (l._id || l.id) === locId);
  expect(stillThere, 'Location was not deleted server-side').toBeUndefined();
});
