// Guards the ≤480px first-load heuristic in init(): with no saved sidebar
// preference in localStorage, a mobile viewport should default the sidebar to
// collapsed (otherwise it covers the entire map on first load). Also checks
// there's no horizontal overflow, and that the add-place modal's Save button
// stays reachable at this width.

const { test, expect } = require('@playwright/test');
const { loginAs, authHeaders } = require('./helpers');

test.use({ viewport: { width: 390, height: 844 } });

test.describe('mobile viewport (390x844)', () => {
  test.afterEach(async ({ request }) => {
    const token = await loginAs(request);
    const headers = authHeaders(token);
    const existing = await (await request.get('/api/locations', { headers })).json();
    for (const l of existing) {
      await request.delete('/api/locations/' + (l._id || l.id), { headers });
    }
  });

  test('sidebar auto-collapses, map is visible, no horizontal scroll', async ({ page, request }) => {
    const token = await loginAs(request);
    const headers = authHeaders(token);
    const existing = await (await request.get('/api/locations', { headers })).json();
    for (const l of existing) {
      await request.delete('/api/locations/' + (l._id || l.id), { headers });
    }

    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });

    await page.goto('/');
    await expect(page.locator('#login-screen')).toHaveClass(/hidden/);
    await expect(page.locator('#map')).toBeVisible();

    // Mobile first-load heuristic: with no localStorage 'hm_sidebar' preference
    // and matchMedia('(max-width: 480px)') true, init() collapses the sidebar.
    await expect(page.locator('#sidebar')).toHaveClass(/collapsed/, { timeout: 5_000 });
    await expect(page.locator('#sidebar-toggle')).toHaveText('▶');

    const overflow = await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth);
    expect(overflow, 'page has horizontal overflow at 390px width').toBe(true);

    // Open the add-place modal and confirm the Save button is reachable.
    // The modal body is long (tags, visits, photos, ...) and scrolls internally
    // at this width, so the Save button isn't necessarily within the initial
    // viewport — "reachable" means scrollIntoView + click works, not that it's
    // visible without any scrolling.
    await page.locator('#add-place-fab').click();
    await expect(page.locator('#edit-modal')).toHaveClass(/open/);
    const saveBtn = page.locator('#save-loc-btn');
    await expect(saveBtn).toBeVisible();
    await saveBtn.scrollIntoViewIfNeeded();
    const box = await saveBtn.boundingBox();
    expect(box).toBeTruthy();
    expect(box.x).toBeGreaterThanOrEqual(0);
    expect(box.x + box.width).toBeLessThanOrEqual(390 + 1);
    expect(box.y).toBeGreaterThanOrEqual(0);
    expect(box.y + box.height).toBeLessThanOrEqual(844 + 1);
    // And it must actually be clickable at that scroll position (not covered
    // by another element / clipped by an ancestor's overflow).
    await expect(saveBtn).toBeInViewport();

    const realErrors = errors.filter(t => !/favicon|net::ERR_|Failed to load resource/i.test(t));
    expect(realErrors, realErrors.join('\n')).toEqual([]);
  });
});
