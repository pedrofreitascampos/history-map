// Setup project: register the e2e user against the running server and persist
// a storageState with hm_token in localStorage so subsequent specs land
// post-login (DOMContentLoaded → checkAuth() → startApp()).

const path = require('path');
const { test, expect } = require('@playwright/test');

const STORAGE_STATE = path.join(__dirname, '.auth', 'state.json');
const E2E_USER = { username: 'e2euser', password: 'e2epass123' };

test('register e2e user and save storageState', async ({ request, baseURL }) => {
  const res = await request.post('/api/auth/register', { data: E2E_USER });
  expect(res.status()).toBe(200);
  const body = await res.json();
  expect(body.token).toBeTruthy();

  const origin = new URL(baseURL).origin;
  const fs = require('fs');
  fs.writeFileSync(STORAGE_STATE, JSON.stringify({
    cookies: [],
    origins: [{
      origin,
      localStorage: [{ name: 'hm_token', value: body.token }],
    }],
  }, null, 2));
});
