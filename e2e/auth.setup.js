// Setup project: register the e2e user against the running server and persist
// a storageState with the HttpOnly hm_token cookie. After the H-2 migration
// (2026-05-30) the token is no longer readable from JS — Playwright's request
// context captures the Set-Cookie header from /auth/register automatically
// and request.storageState() serializes it. Subsequent specs open a browser
// context with that cookie already attached, so checkAuth() → /auth/me →
// 200 → startApp() runs without a login round-trip.

const path = require('path');
const { test, expect } = require('@playwright/test');

const STORAGE_STATE = path.join(__dirname, '.auth', 'state.json');
const E2E_USER = { username: 'e2euser', password: 'e2epass123' };

test('register e2e user and save storageState', async ({ request }) => {
  const res = await request.post('/api/auth/register', { data: E2E_USER });
  expect(res.status()).toBe(200);
  const body = await res.json();
  // /auth/register still returns the token in body (CLI / supertest path).
  // Browsers don't need it — the hm_token cookie is set by Set-Cookie.
  expect(body.token).toBeTruthy();

  // Persist cookies from the request context. The hm_token cookie set by
  // /auth/register lands here; the browser context in subsequent specs picks
  // it up via storageState in playwright.config.js.
  const state = await request.storageState({ path: STORAGE_STATE });
  const hmCookie = (state.cookies || []).find(c => c.name === 'hm_token');
  expect(hmCookie, 'hm_token cookie must be set by /auth/register').toBeTruthy();
  expect(hmCookie.httpOnly, 'hm_token must be HttpOnly').toBe(true);
});
