// T3: Deleting a trip from the trips-manager modal actually removes it from
// the server. Guards the second showConfirm class — deleteTrip was previously
// duplicated with one definition broken (await-style) shadowing the working
// callback-style one; this test would have failed against that bug.

const { test, expect } = require('@playwright/test');
const { loginAs, authHeaders } = require('./helpers');

test('delete trip removes it from server state', async ({ page, request }) => {
  const token = await loginAs(request);
  const headers = authHeaders(token);

  const seedRes = await request.post('/api/trips', {
    headers,
    data: { name: 'E2E Delete Target Trip', startDate: '2026-01-01', endDate: '2026-01-05' },
  });
  expect(seedRes.status()).toBe(200);
  const seeded = await seedRes.json();
  const tripId = seeded._id || seeded.id;
  expect(tripId).toBeTruthy();

  await page.goto('/');
  await expect(page.locator('#login-screen')).toHaveClass(/hidden/);

  // Open the trips manager modal directly (it's the same entry that
  // renderTripManager populates, including the delete button for each row).
  await page.evaluate(() => window.openTripManager());

  const deleteBtn = page.locator(`#trips-manager-list button[onclick="deleteTrip('${tripId}')"]`);
  await expect(deleteBtn).toBeVisible({ timeout: 5_000 });
  await deleteBtn.click();

  const confirmDanger = page.locator('.confirm-overlay .confirm-danger');
  await expect(confirmDanger).toBeVisible();
  await confirmDanger.click();

  // Wait for the row to disappear (renderTripManager re-runs after the awaited
  // DELETE resolves). If showConfirm regressed back to fire-and-forget, the
  // button would remain.
  await expect(deleteBtn).toHaveCount(0, { timeout: 5_000 });

  const listRes = await request.get('/api/trips', { headers });
  expect(listRes.status()).toBe(200);
  const list = await listRes.json();
  const stillThere = list.find(t => (t._id || t.id) === tripId);
  expect(stillThere, 'Trip was not deleted server-side').toBeUndefined();
});
