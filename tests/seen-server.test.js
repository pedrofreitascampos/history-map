// Per-visit "seen" (artists, comedians, animals, celebrities, sport): server-side
// sanitisation, API round trip, bulk import, and the public-share no-leak guarantee.

const path = require('path');
const fs = require('fs');

const testDataDir = path.join(__dirname, '..', 'data-test-seen');
if (!fs.existsSync(testDataDir)) fs.mkdirSync(testDataDir, { recursive: true });
process.env.DATA_DIR = testDataDir;
process.env.JWT_SECRET = 'seen-test-secret';
process.env.ALLOWED_EMAILS = '';

const request = require('supertest');
const app = require('../server/index');
const db = require('../server/db');

const { sanitizeSeenList, sanitizeVisitsSeen } = app.locals;

let token;
beforeAll(async () => {
  await db.users.remove({}, { multi: true });
  await db.locations.remove({}, { multi: true });
  await db.trips.remove({}, { multi: true });
  const reg = await request(app).post('/api/auth/register').send({ username: 'seenuser', password: 'seenpass123' });
  expect(reg.status).toBe(200);
  token = reg.body.token;
});
afterAll(() => {
  const wipe = (dir) => {
    if (!fs.existsSync(dir)) return;
    for (const f of fs.readdirSync(dir)) {
      const p = path.join(dir, f);
      try { if (fs.statSync(p).isDirectory()) { wipe(p); fs.rmdirSync(p); } else fs.unlinkSync(p); } catch { /* locked */ }
    }
  };
  try { wipe(testDataDir); fs.rmdirSync(testDataDir); } catch { /* leave it */ }
});
const auth = (req) => req.set('Authorization', `Bearer ${token}`);
const base = (extra) => ({ name: 'Venue', lat: 38.7, lng: -9.1, category: 'stadium', status: 'been', ...extra });

describe('sanitizeSeenList', () => {
  test('keeps valid entries with every field', () => {
    const r = sanitizeSeenList([{ type: 'animal', name: 'African elephant', note: 'herd of 12', count: 12, wild: true }]);
    expect(r).toEqual([{ type: 'animal', name: 'African elephant', note: 'herd of 12', count: 12, wild: true }]);
  });
  test('trims names and drops entries without a name', () => {
    const r = sanitizeSeenList([{ type: 'artist', name: '  Foo Fighters  ' }, { type: 'artist', name: '   ' }, { type: 'artist' }, { type: 'artist', name: 42 }]);
    expect(r).toEqual([{ type: 'artist', name: 'Foo Fighters' }]);
  });
  test('unknown or missing type becomes "other"', () => {
    const r = sanitizeSeenList([{ type: 'wizard', name: 'A' }, { name: 'B' }, { type: '__proto__', name: 'C' }]);
    expect(r.map(e => e.type)).toEqual(['other', 'other', 'other']);
  });
  test('clamps name to 120 and note to 200 chars', () => {
    const r = sanitizeSeenList([{ type: 'artist', name: 'x'.repeat(500), note: 'n'.repeat(500) }]);
    expect(r[0].name).toHaveLength(120);
    expect(r[0].note).toHaveLength(200);
  });
  test('count must be an integer 1..100000, otherwise dropped; coerced from numeric strings', () => {
    const r = sanitizeSeenList([
      { type: 'animal', name: 'a', count: 0 },
      { type: 'animal', name: 'b', count: -3 },
      { type: 'animal', name: 'c', count: 100001 },
      { type: 'animal', name: 'd', count: '7' },
      { type: 'animal', name: 'e', count: 2.9 },
      { type: 'animal', name: 'f', count: 'lots' },
      { type: 'animal', name: 'g', count: true },
    ]);
    expect(r.map(e => e.count)).toEqual([undefined, undefined, undefined, 7, 2, undefined, undefined]);
  });
  test('wild is coerced to a boolean or omitted', () => {
    const r = sanitizeSeenList([
      { type: 'animal', name: 'a', wild: true }, { type: 'animal', name: 'b', wild: false },
      { type: 'animal', name: 'c', wild: 'true' }, { type: 'animal', name: 'd', wild: 'yes' }, { type: 'animal', name: 'e', wild: 1 },
    ]);
    expect(r.map(e => e.wild)).toEqual([true, false, true, undefined, undefined]);
  });
  test('non-array input yields an empty list; junk entries are skipped', () => {
    expect(sanitizeSeenList('nope')).toEqual([]);
    expect(sanitizeSeenList({ type: 'artist', name: 'x' })).toEqual([]);
    expect(sanitizeSeenList(null)).toEqual([]);
    expect(sanitizeSeenList([null, 5, 'str', [], { type: 'artist', name: 'ok' }])).toEqual([{ type: 'artist', name: 'ok' }]);
  });
  test('caps at 300 entries per visit', () => {
    const many = Array.from({ length: 450 }, (_, i) => ({ type: 'artist', name: 'Act ' + i }));
    expect(sanitizeSeenList(many)).toHaveLength(300);
  });
  test('markup / script / javascript: strings are stored as inert plain text', () => {
    const r = sanitizeSeenList([
      { type: 'artist', name: '<img src=x onerror=alert(1)>Band' },
      { type: 'artist', name: '<script>alert(1)</script>Evil', note: '<svg onload=alert(1)>hi' },
      { type: 'celebrity', name: 'javascript:alert(1)' },
      { type: 'artist', name: '<b></b>' },
    ]);
    const raw = JSON.stringify(r);
    expect(raw).not.toMatch(/[<>]/);
    expect(raw).not.toMatch(/javascript:/i);
    expect(r[0].name).toBe('Band');
    expect(r[1]).toEqual({ type: 'artist', name: 'Evil', note: 'hi' });
    expect(r).toHaveLength(3); // the markup-only name is dropped
  });
  test('output never carries unknown keys from the input', () => {
    const r = sanitizeSeenList([{ type: 'artist', name: 'A', evil: 'x' }]);
    expect(Object.keys(r[0])).toEqual(['type', 'name']);
  });
});

describe('sanitizeVisitsSeen', () => {
  test('leaves visits without seen untouched and drops a non-array / empty seen', () => {
    const v = sanitizeVisitsSeen([{ date: '2024-01-01', notes: 'x' }, { date: '2024-01-02', seen: 'bad' }, { date: '2024-01-03', seen: [] }]);
    expect(v[0]).toEqual({ date: '2024-01-01', notes: 'x' });
    expect(v[1]).toEqual({ date: '2024-01-02' });
    expect(v[2]).toEqual({ date: '2024-01-03' });
  });
  test('non-array visits pass through (existing behaviour)', () => {
    expect(sanitizeVisitsSeen(undefined)).toBeUndefined();
  });
});

describe('seen over the API', () => {
  const visits = [{
    date: '2024-07-12', notes: 'Rock in Rio',
    seen: [{ type: 'artist', name: 'Foo Fighters' }, { type: 'artist', name: 'Queens of the Stone Age', note: 'opener' }],
  }, {
    date: '2023-05-01', notes: '', seen: [{ type: 'sport', name: 'Benfica 2-1 Porto' }],
  }];

  test('POST -> GET round trip keeps seen; PUT replaces and sanitises it', async () => {
    const created = await auth(request(app).post('/api/locations')).send(base({ visits }));
    expect(created.status).toBe(200);
    const list = await auth(request(app).get('/api/locations'));
    const got = list.body.find(l => l._id === created.body._id);
    expect(got.visits[0].seen).toEqual(visits[0].seen);
    expect(got.visits[1].seen).toEqual(visits[1].seen);

    const put = await auth(request(app).put(`/api/locations/${created.body._id}`)).send({
      visits: [{ date: '2024-07-12', notes: '', seen: [{ type: 'ufo', name: '<b>Elephant</b>', count: '3', wild: 'true' }] }],
    });
    expect(put.status).toBe(200);
    expect(put.body.visits[0].seen).toEqual([{ type: 'other', name: 'Elephant', count: 3, wild: true }]);
  });

  test('PUT without visits does not touch stored seen', async () => {
    const created = await auth(request(app).post('/api/locations')).send(base({ name: 'Keep', visits }));
    await auth(request(app).put(`/api/locations/${created.body._id}`)).send({ notes: 'changed' });
    const list = await auth(request(app).get('/api/locations'));
    expect(list.body.find(l => l._id === created.body._id).visits[0].seen).toHaveLength(2);
  });

  test('hostile payload is stored inert', async () => {
    const res = await auth(request(app).post('/api/locations')).send(base({
      name: 'Hostile', visits: [{ date: '2024-01-01', seen: [{ type: 'artist', name: '<img src=x onerror=alert(1)>Safe', note: 'javascript:alert(1)' }] }],
    }));
    expect(res.status).toBe(200);
    expect(res.body.visits[0].seen).toEqual([{ type: 'artist', name: 'Safe', note: 'alert(1)' }]);
  });

  test('bulk import keeps and sanitises seen', async () => {
    const res = await auth(request(app).post('/api/locations/bulk')).send({ locations: [
      base({ name: 'Bulk A', visits }),
      base({ name: 'Bulk B', visits: [{ date: '2022-02-02', seen: [{ type: 'bogus', name: 'X' }, { name: '' }] }] }),
    ] });
    expect(res.status).toBe(200);
    const a = res.body.find(l => l.name === 'Bulk A');
    const b = res.body.find(l => l.name === 'Bulk B');
    expect(a.visits[0].seen).toEqual(visits[0].seen);
    expect(b.visits[0].seen).toEqual([{ type: 'other', name: 'X' }]);
  });

  test('public share route never leaks seen (or visit notes)', async () => {
    const trip = (await auth(request(app).post('/api/trips')).send({ name: 'SeenShare' })).body;
    const loc = await auth(request(app).post('/api/locations')).send(base({
      name: 'SharedStadium', tripId: trip._id, tripOrder: 0,
      visits: [{ date: '2024-07-12', notes: 'PRIVATE-NOTE', seen: [{ type: 'celebrity', name: 'SECRET-CELEB' }] }],
    }));
    expect(loc.status).toBe(200);
    const share = await auth(request(app).post(`/api/trips/${trip._id}/share`));
    expect(share.status).toBe(200);
    const pub = await request(app).get(`/api/share/${share.body.shareToken}`);
    expect(pub.status).toBe(200);
    expect(pub.body.locations[0].visits).toEqual([{ date: '2024-07-12' }]);
    const raw = JSON.stringify(pub.body);
    expect(raw).not.toMatch(/SECRET-CELEB/);
    expect(raw).not.toMatch(/PRIVATE-NOTE/);
    expect(raw).not.toMatch(/"seen"/);
  });
});
