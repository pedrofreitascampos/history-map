const path = require('path');
const fs = require('fs');

// Isolate this test's data dir so it doesn't collide with api.test.js / places.test.js.
const testDataDir = path.join(__dirname, '..', 'data-test-admin');
if (!fs.existsSync(testDataDir)) fs.mkdirSync(testDataDir, { recursive: true });
process.env.DATA_DIR = testDataDir;
process.env.JWT_SECRET = 'admin-test-secret';
// First email in ALLOWED_EMAILS is the admin. Both test users must be in the allowlist
// so registration succeeds (server enforces this when ALLOWED_EMAILS is non-empty).
process.env.ALLOWED_EMAILS = 'admin@e2e.test,user@e2e.test';

const request = require('supertest');
const app = require('../server/index');
const db = require('../server/db');

const ADMIN = { username: 'admin@e2e.test', password: 'adminpass123' };
const USER = { username: 'user@e2e.test', password: 'userpass123' };

let adminToken;
let userToken;
let userId;

beforeAll(async () => {
  await db.users.remove({}, { multi: true });
  await db.locations.remove({}, { multi: true });
  await db.trips.remove({}, { multi: true });
  await db.collections.remove({}, { multi: true });
  await db.transits.remove({}, { multi: true });
  await db.auditLog.remove({}, { multi: true });

  const reg1 = await request(app).post('/api/auth/register').send(ADMIN);
  adminToken = reg1.body.token;
  const reg2 = await request(app).post('/api/auth/register').send(USER);
  userToken = reg2.body.token;
  const u = await db.users.findOne({ username: USER.username });
  userId = u._id;
});

afterAll(() => {
  const wipe = (dir) => {
    if (!fs.existsSync(dir)) return;
    for (const f of fs.readdirSync(dir)) {
      const p = path.join(dir, f);
      const stat = fs.statSync(p);
      if (stat.isDirectory()) {
        wipe(p);
        fs.rmdirSync(p);
      } else {
        fs.unlinkSync(p);
      }
    }
  };
  wipe(testDataDir);
  if (fs.existsSync(testDataDir)) fs.rmdirSync(testDataDir);
});

describe('Admin happy-path — list users / audit', () => {
  test('GET /api/admin/users → 200, returns both users', async () => {
    const res = await request(app).get('/api/admin/users').set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    const usernames = res.body.map(u => u.username).sort();
    expect(usernames).toEqual([ADMIN.username, USER.username].sort());
    // Must NOT leak password / hash
    res.body.forEach(u => {
      expect(u.password).toBeUndefined();
      expect(u.googlePlacesKey).toBeUndefined();
    });
  });

  test('GET /api/audit → 200, returns array (registrations were audited)', async () => {
    const res = await request(app).get('/api/audit').set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBeGreaterThan(0);
    // Must contain a register_success event (audit() stores under `event`, not `action`)
    const events = res.body.map(e => e.event);
    expect(events).toEqual(expect.arrayContaining(['register_success']));
  });

  test('GET /api/audit?limit=1 → at most 1 entry', async () => {
    const res = await request(app).get('/api/audit?limit=1').set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.length).toBeLessThanOrEqual(1);
  });
});

describe('Admin happy-path — reset password', () => {
  test('POST /api/admin/reset-password → 200, user can log in with new password', async () => {
    const newPassword = 'rotatedPass456';
    const res = await request(app).post('/api/admin/reset-password')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ username: USER.username, newPassword });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);

    // Old password no longer works
    const oldLogin = await request(app).post('/api/auth/login').send(USER);
    expect(oldLogin.status).toBe(401);

    // New password works
    const newLogin = await request(app).post('/api/auth/login')
      .send({ username: USER.username, password: newPassword });
    expect(newLogin.status).toBe(200);
    expect(newLogin.body.token).toBeTruthy();
    userToken = newLogin.body.token;
    USER.password = newPassword;
  });

  test('POST /api/admin/reset-password → 404 unknown user', async () => {
    const res = await request(app).post('/api/admin/reset-password')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ username: 'nobody@nowhere', newPassword: 'whatever123' });
    expect(res.status).toBe(404);
  });

  test('POST /api/admin/reset-password → 400 missing fields', async () => {
    const res = await request(app).post('/api/admin/reset-password')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ username: USER.username });
    expect(res.status).toBe(400);
  });

  test('reset-password emits audit entry', async () => {
    const res = await request(app).get('/api/audit').set('Authorization', `Bearer ${adminToken}`);
    const events = res.body.map(e => e.event);
    expect(events).toContain('password_reset');
  });
});

describe('Admin happy-path — merge accounts', () => {
  beforeAll(async () => {
    // Seed data on the non-admin user before merge
    await db.locations.insert({ userId, name: 'A', lat: 1, lng: 2 });
    await db.locations.insert({ userId, name: 'B', lat: 3, lng: 4 });
    await db.trips.insert({ userId, name: 'T1' });
    await db.collections.insert({ userId, name: 'C1' });
    await db.transits.insert({ userId, fromLat: 1, fromLng: 2, toLat: 3, toLng: 4 });
  });

  test('POST /api/admin/merge-accounts → 200, all data moves to target, source removed', async () => {
    const res = await request(app).post('/api/admin/merge-accounts')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ fromUsername: USER.username, toUsername: ADMIN.username });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.merged.locations).toBe(2);
    expect(res.body.merged.trips).toBe(1);
    expect(res.body.merged.collections).toBe(1);
    expect(res.body.merged.transits).toBe(1);

    // Source user is gone
    const gone = await db.users.findOne({ username: USER.username });
    expect(gone).toBeNull();

    // Target user owns the merged rows
    const adminUser = await db.users.findOne({ username: ADMIN.username });
    const adminLocs = await db.locations.find({ userId: adminUser._id });
    expect(adminLocs.length).toBe(2);
  });

  test('POST /api/admin/merge-accounts → 404 unknown source', async () => {
    const res = await request(app).post('/api/admin/merge-accounts')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ fromUsername: 'ghost@nowhere', toUsername: ADMIN.username });
    expect(res.status).toBe(404);
  });

  test('POST /api/admin/merge-accounts → 400 missing fields', async () => {
    const res = await request(app).post('/api/admin/merge-accounts')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ fromUsername: ADMIN.username });
    expect(res.status).toBe(400);
  });

  test('merge emits account_merge audit entry', async () => {
    const res = await request(app).get('/api/audit').set('Authorization', `Bearer ${adminToken}`);
    const events = res.body.map(e => e.event);
    expect(events).toContain('account_merge');
  });
});

describe('Admin happy-path — backups list + download', () => {
  const BACKUP_DIR = path.join(testDataDir, 'backups');
  const fixtureName = 'admin@e2e.test_2026-01-01.json';

  beforeAll(() => {
    if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });
    fs.writeFileSync(
      path.join(BACKUP_DIR, fixtureName),
      JSON.stringify({ exportDate: '2026-01-01', username: ADMIN.username, locations: [], trips: [], collections: [], transits: [] })
    );
  });

  test('GET /api/admin/backups → 200, lists the seeded backup', async () => {
    const res = await request(app).get('/api/admin/backups').set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    const found = res.body.find(b => b.name === fixtureName);
    expect(found).toBeDefined();
    expect(found.date).toBe('2026-01-01');
    expect(found.size).toBeGreaterThan(0);
  });

  test('GET /api/admin/backups/:filename → 200 downloads file content', async () => {
    const res = await request(app).get('/api/admin/backups/' + fixtureName).set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    const body = JSON.parse(res.text);
    expect(body.username).toBe(ADMIN.username);
  });

  test('GET /api/admin/backups/:filename → 404 unknown file', async () => {
    const res = await request(app).get('/api/admin/backups/does-not-exist.json').set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(404);
  });

  test('GET /api/admin/backups/:filename path traversal → 404 (path.basename strips)', async () => {
    const res = await request(app)
      .get('/api/admin/backups/' + encodeURIComponent('../../etc/passwd'))
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(404);
  });
});

describe('Admin guards — non-admin user is rejected', () => {
  // userToken was rotated by reset-password, so re-login the merged-away user is impossible.
  // Register a fresh non-admin (still in allowlist? user@e2e.test was deleted by merge).
  // Use a token issued before the merge instead — login as admin a second time and forge a non-admin via DB direct.
  let freshUserToken;
  beforeAll(async () => {
    // Re-create the non-admin user (allowlist permits it)
    const reg = await request(app).post('/api/auth/register').send({ username: USER.username, password: 'freshpass789' });
    freshUserToken = reg.body.token;
  });

  test('non-admin GET /api/admin/users → 403', async () => {
    const res = await request(app).get('/api/admin/users').set('Authorization', `Bearer ${freshUserToken}`);
    expect(res.status).toBe(403);
  });

  test('non-admin POST /api/admin/merge-accounts → 403', async () => {
    const res = await request(app).post('/api/admin/merge-accounts')
      .set('Authorization', `Bearer ${freshUserToken}`)
      .send({ fromUsername: 'a', toUsername: 'b' });
    expect(res.status).toBe(403);
  });
});
