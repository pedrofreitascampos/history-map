// Behavioral acceptance tests: every field the UI collects must survive a
// full write -> read round trip over real HTTP, via supertest against the
// real Express app + real NeDB files. No source-text regex assertions here.
//
// Context: `cost` was silently dropped from the location/transit write
// allowlist for months because nothing ever exercised POST->GET with that
// field populated. These tests exist to make that class of bug loud.

const path = require('path');
const fs = require('fs');

const testDataDir = path.join(__dirname, '..', 'data-test-acceptance-crud');
if (!fs.existsSync(testDataDir)) fs.mkdirSync(testDataDir, { recursive: true });
process.env.DATA_DIR = testDataDir;
process.env.JWT_SECRET = 'acceptance-crud-secret';
process.env.ALLOWED_EMAILS = '';

const request = require('supertest');
const app = require('../server/index');
const db = require('../server/db');

let token, userId;

beforeAll(async () => {
  await db.users.remove({}, { multi: true });
  await db.locations.remove({}, { multi: true });
  await db.trips.remove({}, { multi: true });
  await db.collections.remove({}, { multi: true });
  await db.transits.remove({}, { multi: true });
  await db.auditLog.remove({}, { multi: true });

  const reg = await request(app).post('/api/auth/register').send({ username: 'crudroundtrip', password: 'roundtrip123' });
  expect(reg.status).toBe(200);
  token = reg.body.token;
  const u = await db.users.findOne({ username: 'crudroundtrip' });
  userId = u._id;
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

async function getLocation(id) {
  const res = await auth(request(app).get('/api/locations'));
  expect(res.status).toBe(200);
  return res.body.find(l => l._id === id);
}
async function getTransit(id) {
  const res = await auth(request(app).get('/api/transits'));
  expect(res.status).toBe(200);
  return res.body.find(t => t._id === id);
}
async function getTrip(id) {
  const res = await auth(request(app).get('/api/trips'));
  expect(res.status).toBe(200);
  return res.body.find(t => t._id === id);
}
async function getCollection(id) {
  const res = await auth(request(app).get('/api/collections'));
  expect(res.status).toBe(200);
  return res.body.find(c => c._id === id);
}

// ─── Locations: full-field round trip ───────────────────────────────────
describe('Location field round trip (POST -> GET)', () => {
  const full = {
    name: 'Full Fixture Place',
    lat: 38.7169,
    lng: -9.1399,
    address: 'Rua Augusta 1, Lisbon',
    category: 'restaurant',
    status: 'visited',
    myRating: 4,
    googleRating: 4.6,
    priceLevel: 2,
    tripId: 'trip-fixture-1',
    tripOrder: 2,
    collections: ['col-a', 'col-b'],
    people: ['Alice', 'Bob'],
    tags: ['foodie', 'tapas'],
    notes: 'Great tapas, go back',
    visits: [{ date: '2024-05-01' }, { date: '2025-01-10' }],
    bucketStrength: 3,
    iata: 'LIS',
    cost: 45.5,
  };
  let id;

  test('POST /api/locations persists every field', async () => {
    const res = await auth(request(app).post('/api/locations')).send(full);
    expect(res.status).toBe(200);
    id = res.body._id;
    expect(id).toBeDefined();
  });

  test('GET /api/locations round-trips every field written on POST', async () => {
    const got = await getLocation(id);
    expect(got).toBeDefined();
    expect(got.name).toBe(full.name);
    expect(got.lat).toBe(full.lat);
    expect(got.lng).toBe(full.lng);
    expect(got.address).toBe(full.address);
    expect(got.category).toBe(full.category);
    expect(got.status).toBe(full.status);
    expect(got.myRating).toBe(full.myRating);
    expect(got.googleRating).toBe(full.googleRating);
    expect(got.priceLevel).toBe(full.priceLevel);
    expect(got.tripId).toBe(full.tripId);
    expect(got.tripOrder).toBe(full.tripOrder);
    expect(got.collections).toEqual(full.collections);
    expect(got.people).toEqual(full.people);
    expect(got.tags).toEqual(full.tags);
    expect(got.notes).toBe(full.notes);
    expect(got.visits).toEqual(full.visits);
    expect(got.bucketStrength).toBe(full.bucketStrength);
    expect(got.iata).toBe(full.iata);
    expect(got.cost).toBe(full.cost);
  });
});

describe('Location field round trip (PUT -> GET) on an existing record', () => {
  let id;
  const updated = {
    name: 'Renamed Fixture Place',
    lat: 41.1579,
    lng: -8.6291,
    address: 'Rua de Santa Catarina 1, Porto',
    category: 'museum',
    status: 'bucket',
    myRating: 5,
    googleRating: 4.2,
    priceLevel: 1,
    tripId: 'trip-fixture-2',
    tripOrder: 7,
    collections: ['col-c'],
    people: ['Carla'],
    tags: ['art'],
    notes: 'Update round trip',
    visits: [{ date: '2023-09-09' }],
    bucketStrength: 1,
    iata: 'OPO',
    cost: 12.25,
  };

  beforeAll(async () => {
    const res = await auth(request(app).post('/api/locations')).send({ name: 'Seed', lat: 0, lng: 0 });
    id = res.body._id;
  });

  test('PUT updates every writable field', async () => {
    const res = await auth(request(app).put(`/api/locations/${id}`)).send(updated);
    expect(res.status).toBe(200);
  });

  test('GET reflects every field written on PUT', async () => {
    const got = await getLocation(id);
    expect(got.name).toBe(updated.name);
    expect(got.lat).toBe(updated.lat);
    expect(got.lng).toBe(updated.lng);
    expect(got.address).toBe(updated.address);
    expect(got.category).toBe(updated.category);
    expect(got.status).toBe(updated.status);
    expect(got.myRating).toBe(updated.myRating);
    expect(got.googleRating).toBe(updated.googleRating);
    expect(got.priceLevel).toBe(updated.priceLevel);
    expect(got.tripId).toBe(updated.tripId);
    expect(got.tripOrder).toBe(updated.tripOrder);
    expect(got.collections).toEqual(updated.collections);
    expect(got.people).toEqual(updated.people);
    expect(got.tags).toEqual(updated.tags);
    expect(got.notes).toBe(updated.notes);
    expect(got.visits).toEqual(updated.visits);
    expect(got.bucketStrength).toBe(updated.bucketStrength);
    expect(got.iata).toBe(updated.iata);
    expect(got.cost).toBe(updated.cost);
  });
});

describe('Location cost field — the specific regression', () => {
  let id;

  test('POST cost: 45.5 -> GET returns 45.5', async () => {
    const res = await auth(request(app).post('/api/locations')).send({ name: 'CostPlace', lat: 1, lng: 1, cost: 45.5 });
    expect(res.status).toBe(200);
    id = res.body._id;
    const got = await getLocation(id);
    expect(got.cost).toBe(45.5);
  });

  test('PUT cost: 0 -> GET returns 0 (not null/undefined — 0 is meaningful)', async () => {
    const res = await auth(request(app).put(`/api/locations/${id}`)).send({ cost: 0 });
    expect(res.status).toBe(200);
    const got = await getLocation(id);
    expect(got.cost).toBe(0);
    expect(got.cost).not.toBeNull();
    expect(got.cost).not.toBeUndefined();
  });

  test('PUT cost: null -> clears it', async () => {
    // First set a real value so we can prove it actually clears rather than never having been set.
    await auth(request(app).put(`/api/locations/${id}`)).send({ cost: 99 });
    const before = await getLocation(id);
    expect(before.cost).toBe(99);

    const res = await auth(request(app).put(`/api/locations/${id}`)).send({ cost: null });
    expect(res.status).toBe(200);
    const got = await getLocation(id);
    expect(got.cost).toBeNull();
  });
});

// ─── Transits: full-field round trip + cost ─────────────────────────────
describe('Transit field round trip (POST/PUT -> GET)', () => {
  const full = {
    mode: 'flight',
    date: '2025-06-01',
    fromName: 'Lisbon Airport',
    fromLocationId: 'loc-from-1',
    fromIata: 'LIS',
    fromLat: 38.77,
    fromLng: -9.13,
    toName: 'Porto Airport',
    toLocationId: 'loc-to-1',
    toIata: 'OPO',
    toLat: 41.24,
    toLng: -8.68,
    flightNumber: 'TP1234',
    airline: 'TAP',
    aircraft: 'A320',
    seat: '14C',
    tripId: 'trip-transit-1',
    notes: 'On time',
    distanceKm: 280.5,
    durationMin: 55,
    cost: 65.9,
  };
  let id;

  test('POST persists every writable transit field', async () => {
    const res = await auth(request(app).post('/api/transits')).send(full);
    expect(res.status).toBe(200);
    id = res.body._id;
  });

  test('GET round-trips every field', async () => {
    const got = await getTransit(id);
    expect(got).toBeDefined();
    for (const k of Object.keys(full)) {
      expect(got[k]).toBe(full[k]);
    }
  });

  test('PUT round-trips a fresh set of values', async () => {
    const updated = { ...full, fromName: 'Faro Airport', fromIata: 'FAO', cost: 12.75, notes: 'Delayed' };
    const putRes = await auth(request(app).put(`/api/transits/${id}`)).send(updated);
    expect(putRes.status).toBe(200);
    const got = await getTransit(id);
    expect(got.fromName).toBe('Faro Airport');
    expect(got.fromIata).toBe('FAO');
    expect(got.cost).toBe(12.75);
    expect(got.notes).toBe('Delayed');
  });

  test('transit cost: 0 round-trips as 0, null clears it', async () => {
    const zero = await auth(request(app).put(`/api/transits/${id}`)).send({ cost: 0 });
    expect(zero.status).toBe(200);
    let got = await getTransit(id);
    expect(got.cost).toBe(0);

    await auth(request(app).put(`/api/transits/${id}`)).send({ cost: 33 });
    got = await getTransit(id);
    expect(got.cost).toBe(33);

    const cleared = await auth(request(app).put(`/api/transits/${id}`)).send({ cost: null });
    expect(cleared.status).toBe(200);
    got = await getTransit(id);
    expect(got.cost).toBeNull();
  });
});

// ─── Trips: field round trip ─────────────────────────────────────────────
describe('Trip field round trip (POST/PUT -> GET)', () => {
  let id;
  const full = { name: 'Iberia Loop', color: '#3388ff', startDate: '2025-06-01', endDate: '2025-06-10', notes: 'Road trip notes' };

  test('POST persists name/color/startDate/endDate/notes', async () => {
    const res = await auth(request(app).post('/api/trips')).send(full);
    expect(res.status).toBe(200);
    id = res.body._id;
    const got = await getTrip(id);
    expect(got.name).toBe(full.name);
    expect(got.color).toBe(full.color);
    expect(got.startDate).toBe(full.startDate);
    expect(got.endDate).toBe(full.endDate);
    expect(got.notes).toBe(full.notes);
  });

  test('PUT updates all trip fields', async () => {
    const updated = { name: 'Iberia Loop v2', color: 'crimson', startDate: '2025-07-01', endDate: '2025-07-15', notes: 'Updated notes' };
    const res = await auth(request(app).put(`/api/trips/${id}`)).send(updated);
    expect(res.status).toBe(200);
    const got = await getTrip(id);
    expect(got.name).toBe(updated.name);
    expect(got.color).toBe(updated.color);
    expect(got.startDate).toBe(updated.startDate);
    expect(got.endDate).toBe(updated.endDate);
    expect(got.notes).toBe(updated.notes);
  });
});

// ─── Collections: field round trip ───────────────────────────────────────
describe('Collection field round trip (POST/PUT -> GET)', () => {
  let id;
  const full = { name: 'Best Ramen', emoji: '🍜', description: 'Ramen spots worth a detour', totalItems: 12 };

  test('POST persists name/emoji/description/totalItems', async () => {
    const res = await auth(request(app).post('/api/collections')).send(full);
    expect(res.status).toBe(200);
    id = res.body._id;
    const got = await getCollection(id);
    expect(got.name).toBe(full.name);
    expect(got.emoji).toBe(full.emoji);
    expect(got.description).toBe(full.description);
    expect(got.totalItems).toBe(full.totalItems);
  });

  test('PUT updates all collection fields', async () => {
    const updated = { name: 'Best Ramen v2', emoji: '🍥', description: 'Updated', totalItems: 20 };
    const res = await auth(request(app).put(`/api/collections/${id}`)).send(updated);
    expect(res.status).toBe(200);
    const got = await getCollection(id);
    expect(got.name).toBe(updated.name);
    expect(got.emoji).toBe(updated.emoji);
    expect(got.description).toBe(updated.description);
    expect(got.totalItems).toBe(updated.totalItems);
  });
});

// ─── Hostile keys must never be persisted ────────────────────────────────
describe('Hostile / forged keys are stripped, not persisted', () => {
  test('POST with userId/_id/isAdmin/__proto__ overrides is defended', async () => {
    const res = await auth(request(app).post('/api/locations')).send({
      name: 'Hostile',
      lat: 10,
      lng: 10,
      userId: 'someone-else',
      _id: 'forged',
      isAdmin: true,
      __proto__: { x: 1 },
    });
    expect(res.status).toBe(200);
    expect(res.body.userId).toBe(userId);
    expect(res.body.userId).not.toBe('someone-else');
    expect(res.body._id).not.toBe('forged');
    expect(res.body.isAdmin).toBeUndefined();
    // Global prototype must not have been polluted.
    expect(({}).x).toBeUndefined();

    const got = await getLocation(res.body._id);
    expect(got.userId).toBe(userId);
    expect(got.isAdmin).toBeUndefined();
  });
});
