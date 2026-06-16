// Audit 2026-06-16 "this week" security batch:
//   - username case-normalization (register/login)
//   - durable JWT revocation (NeDB-backed, survives restart)
//   - bulk-sync rate limit registered
//   - share.html Leaflet SRI

const path = require('path');
const fs = require('fs');

const testDataDir = path.join(__dirname, '..', 'data-test-sec16');
if (!fs.existsSync(testDataDir)) fs.mkdirSync(testDataDir);
process.env.DATA_DIR = testDataDir;
process.env.JWT_SECRET = 'test-secret-sec16';
process.env.ALLOWED_EMAILS = '';

const request = require('supertest');
const app = require('../server/index');
const db = require('../server/db');

beforeAll(async () => {
  await db.users.remove({}, { multi: true });
  await db.revokedTokens.remove({}, { multi: true });
});

afterAll(async () => {
  // Let any fire-and-forget NeDB writes (e.g. the revoke upsert) flush before
  // we yank the directory, then clean up defensively.
  await new Promise(r => setTimeout(r, 200));
  try {
    for (const f of fs.readdirSync(testDataDir)) fs.unlinkSync(path.join(testDataDir, f));
    fs.rmdirSync(testDataDir);
  } catch (_) { /* best-effort cleanup */ }
});

async function pollFor(fn, timeoutMs = 1500, stepMs = 25) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const v = await fn();
    if (v) return v;
    await new Promise(r => setTimeout(r, stepMs));
  }
  return null;
}

describe('Username case-normalization', () => {
  test('registration stores username lowercased', async () => {
    const res = await request(app).post('/api/auth/register')
      .send({ username: 'PEDRO@Example.com', password: 'password123' });
    expect(res.status).toBe(200);
    expect(res.body.username).toBe('pedro@example.com');
  });

  test('a case-variant of an existing user is rejected as taken (no duplicate silo)', async () => {
    const res = await request(app).post('/api/auth/register')
      .send({ username: 'pedro@EXAMPLE.COM', password: 'password123' });
    expect(res.status).toBe(409);
  });

  test('login works regardless of the case typed', async () => {
    const res = await request(app).post('/api/auth/login')
      .send({ username: '  Pedro@Example.COM  ', password: 'password123' });
    expect(res.status).toBe(200);
    expect(res.body.token).toBeDefined();
  });

  test('exactly one account exists for the normalized username', async () => {
    const matches = await db.users.find({ username: 'pedro@example.com' });
    expect(matches).toHaveLength(1);
  });
});

describe('Durable JWT revocation', () => {
  let token;
  beforeAll(async () => {
    const res = await request(app).post('/api/auth/login')
      .send({ username: 'pedro@example.com', password: 'password123' });
    token = res.body.token;
  });

  test('token is valid before logout', async () => {
    const res = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
  });

  test('logout revokes the token (subsequent request 401)', async () => {
    const out = await request(app).post('/api/auth/logout').set('Authorization', `Bearer ${token}`);
    expect(out.status).toBe(200);
    const res = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(401);
  });

  test('revocation is persisted to NeDB (survives a restart)', async () => {
    const persisted = await pollFor(async () => {
      const rows = await db.revokedTokens.find({});
      return rows.length >= 1 ? rows : null;
    });
    expect(persisted).not.toBeNull();
    expect(persisted[0].jti).toBeTruthy();
    expect(typeof persisted[0].exp).toBe('number');
  });
});

describe('Health endpoint', () => {
  test('GET /healthz → 200 { ok: true, uptime }', async () => {
    const res = await request(app).get('/healthz');
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(typeof res.body.uptime).toBe('number');
  });
});

describe('Source invariants', () => {
  const serverSrc = fs.readFileSync(path.join(__dirname, '..', 'server', 'index.js'), 'utf-8');
  const dbSrc = fs.readFileSync(path.join(__dirname, '..', 'server', 'db.js'), 'utf-8');
  const shareSrc = fs.readFileSync(path.join(__dirname, '..', 'public', 'share.html'), 'utf-8');

  test('bulk-sync has a dedicated rate limiter', () => {
    expect(serverSrc).toMatch(/app\.use\(\s*['"]\/api\/places\/bulk-sync['"]\s*,\s*rateLimit/);
  });

  test('revokeJti persists to db.revokedTokens', () => {
    expect(serverSrc).toMatch(/db\.revokedTokens\.update\([^)]*upsert/);
  });

  test('revoked jtis are loaded on startup', () => {
    expect(serverSrc).toContain('loadRevokedJtis');
    expect(serverSrc).toMatch(/loadRevokedJtis\(\)\s*;/);
  });

  test('db exports revokedTokens collection with a jti index', () => {
    expect(dbSrc).toContain('revokedTokens');
    expect(dbSrc).toMatch(/revokedTokens\.ensureIndex\(\{\s*fieldName:\s*['"]jti['"]/);
  });

  test('share.html Leaflet script carries SRI integrity', () => {
    expect(shareSrc).toMatch(/leaflet@1\.9\.4\/dist\/leaflet\.js"\s+integrity="sha384-/);
  });
});
