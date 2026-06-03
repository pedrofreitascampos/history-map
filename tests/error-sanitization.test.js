// Regression: 500 responses must NOT leak `err.message` to clients.
// Audit 2026-06-02 HIGH-SEC closed 2026-06-03 — 7 catch blocks sanitised:
//   GET  /api/my-backups            (1160)
//   GET  /api/my-backup             (1174)
//   POST /api/places/search         (1356, mapped to GET in route)
//   POST /api/places/autocomplete   (1415)
//   POST /api/places/sync           (1445)
//   POST /api/places/bulk-sync      (1497)
//   POST /api/places/discover       (1574)
// Each catch is expected to: log('error', '<endpoint>_failed', ...) and respond
// `{error: 'Internal error'}` — never echo upstream / filesystem error strings.

const path = require('path');
const fs = require('fs');

const testDataDir = path.join(__dirname, '..', 'data-test-error-leak');
if (!fs.existsSync(testDataDir)) fs.mkdirSync(testDataDir, { recursive: true });
process.env.DATA_DIR = testDataDir;
process.env.JWT_SECRET = 'errleak-test-secret';
process.env.ALLOWED_EMAILS = '';
process.env.GOOGLE_PLACES_KEY = 'errleak-fake-key';

const request = require('supertest');
const app = require('../server/index');
const db = require('../server/db');

const USER = { username: 'errleakuser', password: 'errleakpass123' };
const SECRET = 'UPSTREAM_INTERNAL_TRACE_DO_NOT_LEAK_xyz';
let token;
let fetchSpy;

beforeAll(async () => {
  await db.users.remove({}, { multi: true });
  await db.locations.remove({}, { multi: true });
  await db.auditLog.remove({}, { multi: true });
  const reg = await request(app).post('/api/auth/register').send(USER);
  token = reg.body.token;
});

afterAll(() => {
  const wipe = (dir) => {
    if (!fs.existsSync(dir)) return;
    for (const f of fs.readdirSync(dir)) {
      const p = path.join(dir, f);
      const stat = fs.statSync(p);
      if (stat.isDirectory()) { wipe(p); fs.rmdirSync(p); }
      else fs.unlinkSync(p);
    }
  };
  wipe(testDataDir);
  if (fs.existsSync(testDataDir)) fs.rmdirSync(testDataDir);
});

beforeEach(() => {
  fetchSpy = jest.spyOn(global, 'fetch');
});
afterEach(() => {
  fetchSpy.mockRestore();
  jest.restoreAllMocks();
});

function assertSanitized(res) {
  expect(res.status).toBe(500);
  expect(res.body).toEqual({ error: 'Internal error' });
  expect(JSON.stringify(res.body)).not.toContain(SECRET);
  expect(JSON.stringify(res.body)).not.toContain('errleak-fake-key');
}

describe('500-response sanitization (HIGH-SEC audit 2026-06-02)', () => {
  test('GET /api/places/search swallows upstream throw', async () => {
    fetchSpy.mockImplementation(() => { throw new Error(SECRET); });
    const res = await request(app)
      .get('/api/places/search?q=anything')
      .set('Authorization', `Bearer ${token}`);
    assertSanitized(res);
  });

  test('POST /api/places/autocomplete swallows upstream throw', async () => {
    fetchSpy.mockImplementation(() => { throw new Error(SECRET); });
    const res = await request(app)
      .post('/api/places/autocomplete')
      .set('Authorization', `Bearer ${token}`)
      .send({ input: 'cafe' });
    assertSanitized(res);
  });

  test('POST /api/places/sync swallows upstream throw', async () => {
    fetchSpy.mockImplementation(() => { throw new Error(SECRET); });
    const res = await request(app)
      .post('/api/places/sync')
      .set('Authorization', `Bearer ${token}`)
      .send({ placeId: 'ChIJ_anything' });
    assertSanitized(res);
  });

  test('POST /api/places/bulk-sync per-item errors never reach client body', async () => {
    // bulk-sync's outer catch is guarded by the static pin below. The
    // interesting live path is per-item: a fetch throw must not surface
    // its message in the `results` array either.
    fetchSpy.mockImplementation(() => { throw new Error(SECRET); });
    const res = await request(app)
      .post('/api/places/bulk-sync')
      .set('Authorization', `Bearer ${token}`)
      .send({ locations: [{ id: 'x', name: 'X', lat: 0, lng: 0 }] });
    expect(res.status).toBe(200);
    expect(JSON.stringify(res.body)).not.toContain(SECRET);
  });

  test('POST /api/places/discover swallows upstream throw', async () => {
    fetchSpy.mockImplementation(() => { throw new Error(SECRET); });
    const res = await request(app)
      .post('/api/places/discover')
      .set('Authorization', `Bearer ${token}`)
      .send({ lat: 38.71, lng: -9.14, category: 'restaurant', radius: 1000, minRatings: 100 });
    assertSanitized(res);
  });

  test('GET /api/my-backups swallows fs throw', async () => {
    // Force fs.readdirSync to throw with the secret. Use spyOn so it auto-restores.
    jest.spyOn(fs, 'readdirSync').mockImplementation(() => { throw new Error(SECRET); });
    // BACKUP_DIR must exist for the catch path (else early `if (!fs.existsSync)` returns [])
    jest.spyOn(fs, 'existsSync').mockReturnValue(true);
    const res = await request(app)
      .get('/api/my-backups')
      .set('Authorization', `Bearer ${token}`);
    assertSanitized(res);
  });

  test('GET /api/my-backup swallows fs throw', async () => {
    jest.spyOn(fs, 'readdirSync').mockImplementation(() => { throw new Error(SECRET); });
    jest.spyOn(fs, 'existsSync').mockReturnValue(true);
    const res = await request(app)
      .get('/api/my-backup')
      .set('Authorization', `Bearer ${token}`);
    assertSanitized(res);
  });

  test('static pin: no `err.message` reaches a 500 JSON response in server/index.js', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'server', 'index.js'), 'utf8');
    // Cybersec invariant: no `res.status(500).json({ error: err.message })` patterns.
    // (Inside log() calls is fine — that's server-side only.)
    expect(src).not.toMatch(/res\.status\(500\)\.json\(\{\s*error:\s*err\.message/);
  });
});
