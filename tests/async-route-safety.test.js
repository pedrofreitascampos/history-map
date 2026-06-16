// Async-route safety: Express 4 doesn't forward async rejections to error
// middleware automatically. A one-time method patch (before first route) wraps
// every handler so next(err) is called on rejection → 500, not a silent hang
// or unhandledRejection crash.

const path = require('path');
const fs = require('fs');

const testDataDir = path.join(__dirname, '..', 'data-test-async-route');
if (!fs.existsSync(testDataDir)) fs.mkdirSync(testDataDir);
process.env.DATA_DIR = testDataDir;
process.env.JWT_SECRET = 'test-secret-async-route';
process.env.ALLOWED_EMAILS = '';

const request = require('supertest');
const app = require('../server/index');
const db = require('../server/db');

let token;

beforeAll(async () => {
  await db.users.remove({}, { multi: true });
  await db.locations.remove({}, { multi: true });
  const res = await request(app).post('/api/auth/register')
    .send({ username: 'routetest', password: 'routepass123' });
  token = res.body.token;
});

afterAll(async () => {
  await new Promise(r => setTimeout(r, 100));
  try {
    for (const f of fs.readdirSync(testDataDir)) fs.unlinkSync(path.join(testDataDir, f));
    fs.rmdirSync(testDataDir);
  } catch (_) {}
});

const serverSrc = fs.readFileSync(path.join(__dirname, '..', 'server', 'index.js'), 'utf-8');

describe('Async-route patch — source invariants', () => {
  test('patch is present in server/index.js', () => {
    expect(serverSrc).toMatch(/\['get',\s*'post',\s*'put',\s*'delete',\s*'patch'\]\.forEach/);
  });

  test('patch wraps handlers so rejections call next(err)', () => {
    expect(serverSrc).toMatch(/r\?\.catch.*next/);
  });

  test('patch is registered before the first auth route', () => {
    const patchIdx = serverSrc.indexOf("['get', 'post', 'put', 'delete', 'patch'].forEach");
    const firstRouteIdx = serverSrc.indexOf("app.post('/api/auth/register'");
    expect(patchIdx).toBeGreaterThan(-1);
    expect(firstRouteIdx).toBeGreaterThan(-1);
    expect(patchIdx).toBeLessThan(firstRouteIdx);
  });
});

describe('Async-route patch — previously-unprotected routes respond correctly', () => {
  test('GET /api/locations returns 200 array (not a crash/hang)', async () => {
    const res = await request(app).get('/api/locations')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });

  test('GET /api/trips returns 200 array', async () => {
    const res = await request(app).get('/api/trips')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });

  test('GET /api/collections returns 200 array', async () => {
    const res = await request(app).get('/api/collections')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });

  test('GET /api/transits returns 200 array', async () => {
    const res = await request(app).get('/api/transits')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });

  test('GET /api/settings returns 200', async () => {
    const res = await request(app).get('/api/settings')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
  });

  test('PUT /api/locations/:id with unknown id returns 404 not a crash', async () => {
    const res = await request(app).put('/api/locations/nonexistent-id-xyz')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: 'Test', lat: 10, lng: 10 });
    expect(res.status).toBe(404);
  });
});
