// Shared helpers for e2e specs.

const E2E_USER = { username: 'e2euser', password: 'e2epass123' };

async function loginAs(request, user = E2E_USER) {
  const res = await request.post('/api/auth/login', { data: user });
  if (res.status() !== 200) throw new Error('Login failed: ' + res.status());
  const body = await res.json();
  return body.token;
}

function authHeaders(token) {
  return { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' };
}

module.exports = { E2E_USER, loginAs, authHeaders };
