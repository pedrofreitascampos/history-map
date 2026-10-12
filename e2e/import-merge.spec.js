// Import a JSON array of Oikumene-shaped locations: a brand-new place is added
// and a duplicate of an existing place merges its visits (+ seen) instead of
// being dropped.

const { test, expect } = require('@playwright/test');
const { loginAs, authHeaders } = require('./helpers');

test('JSON import adds new places and merges visits/seen into an existing duplicate', async ({ page, request }) => {
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  const token = await loginAs(request);
  const headers = authHeaders(token);

  const seed = await request.post('/api/locations', {
    headers,
    data: {
      name: 'E2E Merge Arena', lat: 41.38, lng: 2.12, category: 'stadium', status: 'been', tags: ['venue'],
      visits: [{ date: '2019-06-01', notes: 'mine', seen: [{ type: 'artist', name: 'Existing Act' }] }],
    },
  });
  expect(seed.status()).toBe(200);
  const seeded = await seed.json();

  const payload = [
    {
      name: 'E2E Merge Arena', address: 'Barcelona, Spain', lat: 41.38, lng: 2.12, category: 'stadium', status: 'been',
      tags: ['concert'], notes: '',
      visits: [
        { date: '2019-06-01', notes: 'theirs', seen: [{ type: 'artist', name: ' existing  act ' }, { type: 'artist', name: 'Added Act' }] },
        { date: '2022-08-09', notes: '', seen: [{ type: 'artist', name: 'Second Night Act' }] },
      ],
    },
    {
      name: 'E2E Brand New Hall', address: 'Madrid, Spain', lat: 40.41, lng: -3.70, category: 'show', status: 'been',
      tags: [], notes: 'new',
      visits: [{ date: '2023-03-03', notes: '', seen: [{ type: 'comedian', name: 'E2E Comic' }] }],
    },
  ];

  await page.goto('/');
  await expect(page.locator('#login-screen')).toHaveClass(/hidden/);
  await page.locator('.nav-tab[data-arg0="import-view"]').click();
  await page.locator('#file-input').setInputFiles({ name: 'concerts.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(payload)) });

  const mergeRow = page.locator('#import-diff-body tr', { hasText: 'merge 2 visits into existing' });
  await expect(mergeRow).toBeVisible({ timeout: 10_000 });
  await expect(mergeRow).toContainText('E2E Merge Arena');
  await expect(mergeRow.locator('input.import-update-cb')).toBeChecked();
  await expect(page.locator('#import-diff-body')).toContainText('E2E Brand New Hall');

  await page.locator('#import-confirm-btn').click();
  await expect(page.locator('#import-preview')).not.toHaveClass(/active/, { timeout: 10_000 });

  await expect.poll(async () => {
    const list = await (await request.get('/api/locations', { headers })).json();
    const merged = list.find(l => l._id === seeded._id);
    const added = list.find(l => l.name === 'E2E Brand New Hall');
    return JSON.stringify({
      visits: merged.visits.map(v => [v.date, v.notes, (v.seen || []).map(s => s.name)]),
      tags: merged.tags,
      added: added ? added.visits[0].seen : null,
    });
  }, { timeout: 8_000 }).toBe(JSON.stringify({
    visits: [['2019-06-01', 'mine\ntheirs', ['Existing Act', 'Added Act']], ['2022-08-09', '', ['Second Night Act']]],
    tags: ['venue', 'concert'],
    added: [{ type: 'comedian', name: 'E2E Comic' }],
  }));

  expect(errors, errors.join('\n')).toEqual([]);
});
