// Seen feature end-to-end: a seeded visit with seen[] shows up in the Seen view,
// and the edit-modal "+ seen" control persists a new entry through Save.

const { test, expect } = require('@playwright/test');
const { loginAs, authHeaders } = require('./helpers');

test('Seen view lists seeded entries; edit modal can add a seen entry that persists', async ({ page, request }) => {
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));

  const token = await loginAs(request);
  const headers = authHeaders(token);
  const seed = await request.post('/api/locations', {
    headers,
    data: {
      name: 'E2E Seen Arena', lat: 38.77, lng: -9.09, category: 'stadium', status: 'been',
      visits: [{ date: '2024-07-12', notes: '', seen: [{ type: 'artist', name: 'E2E Band' }] }],
    },
  });
  expect(seed.status()).toBe(200);
  const seeded = await seed.json();

  await page.goto('/');
  await expect(page.locator('#login-screen')).toHaveClass(/hidden/);

  // Seen view
  await page.locator('.nav-tab[data-arg0="seen-view"]').click();
  await expect(page.locator('#seen-view')).toHaveClass(/active/);
  const row = page.locator('.seen-row', { hasText: 'E2E Band' });
  await expect(row).toBeVisible();
  await expect(row).toContainText('×1');
  await expect(row.locator('.seen-place')).toHaveText('E2E Seen Arena');

  // Edit modal: expand visits, + seen, add an animal with a count
  await page.evaluate((id) => openEditModal(id), seeded._id);
  await expect(page.locator('#edit-modal')).toHaveClass(/open/);
  await page.locator('#loc-visits-summary').click();
  await expect(page.locator('.seen-chip', { hasText: 'E2E Band' })).toBeVisible();
  await page.locator('.seen-toggle').click();
  await page.locator('.seen-add-form .seen-type').selectOption('animal');
  await page.locator('.seen-add-form .seen-name').fill('E2E Elephant');
  await page.locator('.seen-add-form .seen-count').fill('3');
  await page.locator('.seen-add-form .seen-name').press('Enter');
  await expect(page.locator('.seen-chip', { hasText: 'E2E Elephant ×3' })).toBeVisible();

  await page.locator('#save-loc-btn').click();
  await expect(page.locator('#edit-modal')).not.toHaveClass(/open/, { timeout: 5_000 });

  const list = await (await request.get('/api/locations', { headers })).json();
  const stored = list.find(l => l._id === seeded._id);
  expect(stored.visits[0].seen).toEqual([
    { type: 'artist', name: 'E2E Band' },
    { type: 'animal', name: 'E2E Elephant', count: 3 },
  ]);

  expect(errors, errors.join('\n')).toEqual([]);
});
