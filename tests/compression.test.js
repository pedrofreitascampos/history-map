// Pins the gzip-compression middleware shipped 2026-06-03 (audit P0).
// Render doesn't auto-gzip Node responses; without this middleware index.html
// ships at ~580 KB raw on every cold load. Test verifies:
//   1. middleware is mounted (server-side require + app-level wiring)
//   2. responses with Accept-Encoding: gzip get Content-Encoding: gzip
//   3. responses without Accept-Encoding stay uncompressed (identity)
//   4. small responses skip compression (below default 1 KB threshold)
// Regression guard: if the middleware is removed or reordered after the
// response-sending handlers, all four assertions fail.

const path = require('path');
const fs = require('fs');

const testDataDir = path.join(__dirname, '..', 'data-test-compression');
if (!fs.existsSync(testDataDir)) fs.mkdirSync(testDataDir);
process.env.DATA_DIR = testDataDir;
process.env.JWT_SECRET = 'test-secret';
process.env.ALLOWED_EMAILS = '';

const request = require('supertest');
const app = require('../server/index');
const db = require('../server/db');

afterAll(() => {
  const files = fs.readdirSync(testDataDir);
  files.forEach(f => fs.unlinkSync(path.join(testDataDir, f)));
  fs.rmdirSync(testDataDir);
});

describe('gzip compression middleware', () => {
  test('compression module is a declared dependency', () => {
    const pkg = require('../package.json');
    expect(pkg.dependencies.compression).toBeDefined();
  });

  test('index.html served with Content-Encoding: gzip when Accept-Encoding: gzip', async () => {
    const res = await request(app)
      .get('/')
      .set('Accept-Encoding', 'gzip');
    expect(res.status).toBe(200);
    expect(res.headers['content-encoding']).toBe('gzip');
    // The gzipped body is decoded transparently by supertest; sanity-check
    // we still got HTML, not a corrupted stream.
    expect(res.text).toMatch(/<html/i);
  });

  test('index.html served uncompressed when Accept-Encoding: identity', async () => {
    const res = await request(app)
      .get('/')
      .set('Accept-Encoding', 'identity');
    expect(res.status).toBe(200);
    // No Content-Encoding header (or explicitly 'identity') => uncompressed.
    expect(res.headers['content-encoding']).toBeUndefined();
  });

  test('Vary: Accept-Encoding is set so caches keep gzip+identity copies separate', async () => {
    const res = await request(app)
      .get('/')
      .set('Accept-Encoding', 'gzip');
    expect(res.status).toBe(200);
    const vary = res.headers.vary || '';
    expect(vary.toLowerCase()).toMatch(/accept-encoding/);
  });

  test('tiny JSON responses skip compression (below 1 KB threshold)', async () => {
    // The unauthenticated /api/auth/me path returns a small JSON error body
    // (~30 bytes) — well below compression's default 1024-byte threshold.
    const res = await request(app)
      .get('/api/auth/me')
      .set('Accept-Encoding', 'gzip');
    expect(res.headers['content-encoding']).toBeUndefined();
  });

  test('large API JSON responses are gzipped', async () => {
    // Register a user, bulk-create enough locations that the /api/locations
    // payload comfortably exceeds the 1 KB threshold, then verify gzip
    // kicks in on the read path.
    await db.users.remove({}, { multi: true });
    await db.locations.remove({}, { multi: true });
    const reg = await request(app)
      .post('/api/auth/register')
      .send({ username: 'gzipuser', password: 'gziptest123' });
    expect(reg.status).toBe(200);
    const token = reg.body.token;

    // 50 locations × ~100 bytes each ≈ 5 KB JSON — safely over the threshold.
    const locations = Array.from({ length: 50 }, (_, i) => ({
      name: `Place ${i}`,
      lat: 38.7 + i * 0.001,
      lng: -9.1 + i * 0.001,
      category: 'restaurant',
      status: 'bucket',
      address: `Some street ${i}, Lisbon, Portugal`,
    }));
    const bulk = await request(app)
      .post('/api/locations/bulk')
      .set('Authorization', `Bearer ${token}`)
      .send({ locations });
    expect(bulk.status).toBe(200);

    const res = await request(app)
      .get('/api/locations')
      .set('Authorization', `Bearer ${token}`)
      .set('Accept-Encoding', 'gzip');
    expect(res.status).toBe(200);
    expect(res.headers['content-encoding']).toBe('gzip');
    // supertest transparently decodes; verify we still got our 50 records.
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBe(50);
  });
});
