// Behavioral acceptance tests for input validation, applied consistently
// across the single-item and bulk write paths. Real HTTP calls via
// supertest against the real Express app — no source-text regex pins.

const path = require('path');
const fs = require('fs');

const testDataDir = path.join(__dirname, '..', 'data-test-acceptance-validation');
if (!fs.existsSync(testDataDir)) fs.mkdirSync(testDataDir, { recursive: true });
process.env.DATA_DIR = testDataDir;
process.env.JWT_SECRET = 'acceptance-validation-secret';
process.env.ALLOWED_EMAILS = '';

const request = require('supertest');
const app = require('../server/index');
const db = require('../server/db');

let token;

beforeAll(async () => {
  await db.users.remove({}, { multi: true });
  await db.locations.remove({}, { multi: true });
  await db.trips.remove({}, { multi: true });
  await db.collections.remove({}, { multi: true });
  await db.transits.remove({}, { multi: true });
  await db.auditLog.remove({}, { multi: true });

  const reg = await request(app).post('/api/auth/register').send({ username: 'validationuser', password: 'validation123' });
  expect(reg.status).toBe(200);
  token = reg.body.token;
});

afterAll(() => {
  // Best-effort cleanup. NeDB keeps file handles open for the life of the
  // process and Windows refuses to unlink a locked file, so a failed sweep of
  // a temp dir must not fail the suite — the tests themselves already passed.
  const wipe = (dir) => {
    if (!fs.existsSync(dir)) return;
    for (const f of fs.readdirSync(dir)) {
      const p = path.join(dir, f);
      try {
        if (fs.statSync(p).isDirectory()) { wipe(p); fs.rmdirSync(p); } else { fs.unlinkSync(p); }
      } catch { /* locked or already gone */ }
    }
  };
  try {
    wipe(testDataDir);
    if (fs.existsSync(testDataDir)) fs.rmdirSync(testDataDir);
  } catch { /* leave the temp dir behind rather than failing the run */ }
});

function auth(req) { return req.set('Authorization', `Bearer ${token}`); }

// ─── lat/lng bounds — single item ────────────────────────────────────────
describe('POST /api/locations lat/lng bounds', () => {
  test.each([
    ['lat=91', { name: 'X', lat: 91, lng: 0 }],
    ['lat=-91', { name: 'X', lat: -91, lng: 0 }],
    ['lng=181', { name: 'X', lat: 0, lng: 181 }],
    ['lng=-181', { name: 'X', lat: 0, lng: -181 }],
    ['lat="abc"', { name: 'X', lat: 'abc', lng: 0 }],
    ['lat=null', { name: 'X', lat: null, lng: 0 }],
  ])('%s -> 400', async (_label, body) => {
    const res = await auth(request(app).post('/api/locations')).send(body);
    expect(res.status).toBe(400);
  });

  test('lat=NaN (malformed JSON body) -> 400', async () => {
    // NaN has no JSON representation, so we send the raw invalid-JSON token
    // directly to exercise the server's rejection of an unparseable body.
    const res = await auth(request(app).post('/api/locations'))
      .set('Content-Type', 'application/json')
      .send('{"name":"X","lat":NaN,"lng":0}');
    expect(res.status).toBe(400);
  });
});

// ─── lat/lng bounds — bulk path must match the single-item path ─────────
describe('POST /api/locations/bulk lat/lng bounds (parity with single-item validation)', () => {
  // This was a real bug: bulk only checked `typeof === 'number'`, so an
  // out-of-range lat/lng persisted via bulk while POST correctly rejected it.
  test.each([
    ['lat=999', { name: 'BulkBad', lat: 999, lng: 0, category: 'bar' }],
    ['lat=-999', { name: 'BulkBad', lat: -999, lng: 0, category: 'bar' }],
    ['lng=999', { name: 'BulkBad', lat: 0, lng: 999, category: 'bar' }],
    ['lng=-999', { name: 'BulkBad', lat: 0, lng: -999, category: 'bar' }],
    ['lat="abc"', { name: 'BulkBad', lat: 'abc', lng: 0, category: 'bar' }],
  ])('single out-of-range item (%s) -> 400 "No valid locations"', async (_label, item) => {
    const res = await auth(request(app).post('/api/locations/bulk')).send({ locations: [item] });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/No valid locations/i);
  });

  test('mixed payload: one valid + one out-of-range persists ONLY the valid one', async () => {
    const res = await auth(request(app).post('/api/locations/bulk')).send({
      locations: [
        { name: 'BulkValid', lat: 10, lng: 10, category: 'bar' },
        { name: 'BulkInvalid', lat: 999, lng: 999, category: 'bar' },
      ],
    });
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(1);
    expect(res.body[0].name).toBe('BulkValid');

    const list = await auth(request(app).get('/api/locations'));
    const names = list.body.map(l => l.name);
    expect(names).toContain('BulkValid');
    expect(names).not.toContain('BulkInvalid');
  });
});

// ─── name validation ──────────────────────────────────────────────────────
describe('Location name validation', () => {
  test('empty name -> 400', async () => {
    const res = await auth(request(app).post('/api/locations')).send({ name: '', lat: 1, lng: 1 });
    expect(res.status).toBe(400);
  });

  // validateLocation used to check only `!name` (falsy), so a whitespace-only
  // string was truthy and sailed through — then sanitizeShortText trimmed it to
  // '' and stored a nameless location. It now rejects anything that sanitizes
  // to empty.
  test('whitespace-only name -> 400', async () => {
    const res = await auth(request(app).post('/api/locations')).send({ name: '   ', lat: 1, lng: 1 });
    expect(res.status).toBe(400);
  });

  test('very long name (100,000 chars) is rejected or truncated to <= 300 stored chars', async () => {
    const longName = 'A'.repeat(100000);
    const res = await auth(request(app).post('/api/locations')).send({ name: longName, lat: 1, lng: 1 });
    if (res.status === 200) {
      expect(res.body.name.length).toBeLessThanOrEqual(300);
    } else {
      expect(res.status).toBe(400);
    }
  });

  test('<script> tag and its body are stripped from a name, surrounding text kept', async () => {
    const res = await auth(request(app).post('/api/locations'))
      .send({ name: 'Joe<script>alert(1)</script>s Bar', lat: 1, lng: 1 });
    expect(res.status).toBe(200);
    expect(res.body.name).not.toMatch(/<script/i);
    expect(res.body.name).not.toMatch(/alert\(1\)/); // tag AND body removed, not just the tag
    expect(res.body.name).toBe('Joes Bar');
  });

  test('a name consisting only of a <script> tag is rejected', async () => {
    // Sanitizes to '' → validateLocation must reject rather than store a
    // nameless location.
    const res = await auth(request(app).post('/api/locations'))
      .send({ name: '<script>alert(1)</script>', lat: 1, lng: 1 });
    expect(res.status).toBe(400);
  });

  // name/address go through sanitizeShortText(), NOT the notes denylist.
  // sanitizeNotes only knows about <script>/<iframe>/javascript:, which leaves
  // <img onerror>/<svg onload> intact. A denylist is the wrong shape for a
  // field that never legitimately carries markup, so short text has every tag
  // stripped outright. CSP script-src-attr:'none' is the second layer, not the
  // only one — don't regress this to relying on CSP alone.
  test.each([
    ['<img src=x onerror=alert(1)>Cafe', 'Cafe'],
    ['<svg onload=alert(1)>Bar', 'Bar'],
    ['<b>Bold</b> Bistro', 'Bold Bistro'],
  ])('event-handler markup stripped from name: %s', async (payload, expected) => {
    const res = await auth(request(app).post('/api/locations')).send({ name: payload, lat: 1, lng: 1 });
    expect(res.status).toBe(200);
    expect(res.body.name).toBe(expected);
    expect(res.body.name).not.toMatch(/onerror|onload|<|>/i);
  });

  test('a name that is ONLY markup is rejected, not stored empty', async () => {
    // sanitizeShortText would reduce these to '', so validateLocation has to
    // reject them up front rather than persisting a nameless location.
    for (const payload of ['<img src=x onerror=alert(1)>', '<b></b>', '   ']) {
      const res = await auth(request(app).post('/api/locations')).send({ name: payload, lat: 1, lng: 1 });
      expect(res.status).toBe(400);
    }
  });

  test('legitimate unicode and punctuation in names survive intact', async () => {
    const name = 'Café Ñoño 東京 — Bar & Grill';
    const res = await auth(request(app).post('/api/locations')).send({ name, lat: 1, lng: 1 });
    expect(res.status).toBe(200);
    expect(res.body.name).toBe(name);
  });

  test('notes with a javascript: URI has the scheme stripped', async () => {
    const res = await auth(request(app).post('/api/locations')).send({ name: 'JsUriTest', lat: 1, lng: 1, notes: 'click javascript:alert(1) now' });
    expect(res.status).toBe(200);
    expect(res.body.notes).not.toMatch(/javascript:/i);
  });
});

// ─── bucketStrength clamp ─────────────────────────────────────────────────
describe('bucketStrength is clamped to 0..5', () => {
  test('bucketStrength=-5 clamps to 0', async () => {
    const res = await auth(request(app).post('/api/locations')).send({ name: 'BS-neg', lat: 1, lng: 1, bucketStrength: -5 });
    expect(res.status).toBe(200);
    expect(res.body.bucketStrength).toBe(0);
  });

  test('bucketStrength=99 clamps to 5', async () => {
    const res = await auth(request(app).post('/api/locations')).send({ name: 'BS-huge', lat: 1, lng: 1, bucketStrength: 99 });
    expect(res.status).toBe(200);
    expect(res.body.bucketStrength).toBe(5);
  });
});

// ─── media[] cap + per-entry validation ──────────────────────────────────
describe('media[] is capped at 100 entries; invalid per-entry lat is dropped', () => {
  test('150 media entries -> capped at 100, out-of-range lat on first entry is dropped', async () => {
    const media = [];
    for (let i = 0; i < 150; i++) {
      media.push({ source: 'manual', filename: `photo-${i}.jpg`, lat: i === 0 ? 999 : 10, lon: 10 });
    }
    const res = await auth(request(app).post('/api/locations')).send({ name: 'MediaCap', lat: 1, lng: 1, media });
    expect(res.status).toBe(200);
    expect(res.body.media).toHaveLength(100);
    expect(res.body.media[0].filename).toBe('photo-0.jpg');
    expect(res.body.media[0].lat).toBeUndefined(); // out-of-range lat dropped, entry itself kept
    expect(res.body.media[1].lat).toBe(10); // valid entries keep their lat
  });
});

// ─── cost bounds ──────────────────────────────────────────────────────────
describe('Location cost validation', () => {
  test('negative cost is dropped (not persisted)', async () => {
    const res = await auth(request(app).post('/api/locations')).send({ name: 'CostNeg', lat: 1, lng: 1, cost: -10 });
    expect(res.status).toBe(200);
    expect(res.body.cost).toBeUndefined();
  });

  test('non-numeric cost string is dropped', async () => {
    const res = await auth(request(app).post('/api/locations')).send({ name: 'CostStr', lat: 1, lng: 1, cost: 'abc' });
    expect(res.status).toBe(200);
    expect(res.body.cost).toBeUndefined();
  });

  test('cost over the 1e9 cap is dropped', async () => {
    const res = await auth(request(app).post('/api/locations')).send({ name: 'CostHuge', lat: 1, lng: 1, cost: 1e12 });
    expect(res.status).toBe(200);
    expect(res.body.cost).toBeUndefined();
  });
});

// ─── bulk size cap ────────────────────────────────────────────────────────
describe('Bulk import size cap', () => {
  test('POST /api/locations/bulk over 10000 items -> 400', async () => {
    const locations = new Array(10001).fill(0).map((_, i) => ({ name: `Over-${i}`, lat: 1, lng: 1 }));
    const res = await auth(request(app).post('/api/locations/bulk')).send({ locations });
    expect(res.status).toBe(400);
  }, 20000);
});
