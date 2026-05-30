// T7 (post-onclick-refactor): popup "✏️ Edit" routes through the dispatcher
// and opens the edit modal pre-populated. Guards the popup-button conversion.

const { test, expect } = require('@playwright/test');
const { loginAs, authHeaders } = require('./helpers');

test('popup ✏️ Edit opens the edit modal with the location prefilled', async ({ page, request }) => {
  const token = await loginAs(request);
  const headers = authHeaders(token);

  const seedRes = await request.post('/api/locations', {
    headers,
    data: { name: 'E2E Edit Target', lat: 38.71, lng: -9.14, category: 'restaurant', status: 'been', notes: 'seeded by e2e' },
  });
  expect(seedRes.status()).toBe(200);

  await page.goto('/');
  await expect(page.locator('#login-screen')).toHaveClass(/hidden/);
  await expect(page.locator('#map')).toBeVisible();

  // Click the marker to open the popup, then ✏️ Edit.
  await page.locator('.leaflet-marker-icon').first().click();
  // Hide Leaflet's own close × so it doesn't overlap our Edit button at top-right.
  await page.addStyleTag({ content: '.leaflet-popup-close-button{display:none!important;}' });
  const editBtn = page.locator('.popup-btn', { hasText: 'Edit' }).first();
  await expect(editBtn).toBeVisible();
  await editBtn.click();

  // The edit modal must open with the seeded name and notes prefilled.
  await expect(page.locator('#edit-modal')).toHaveClass(/open/, { timeout: 3_000 });
  await expect(page.locator('#loc-name')).toHaveValue('E2E Edit Target');
  await expect(page.locator('#loc-notes')).toHaveValue('seeded by e2e');
});
