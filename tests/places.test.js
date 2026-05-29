const path = require('path');
const fs = require('fs');

const testDataDir = path.join(__dirname, '..', 'data-test-places');
if (!fs.existsSync(testDataDir)) fs.mkdirSync(testDataDir, { recursive: true });
process.env.DATA_DIR = testDataDir;
process.env.JWT_SECRET = 'places-test-secret';
process.env.ALLOWED_EMAILS = '';
process.env.GOOGLE_PLACES_KEY = 'test-fake-key-do-not-leak';

const request = require('supertest');
const app = require('../server/index');
const db = require('../server/db');

const USER = { username: 'placesuser', password: 'placespass123' };
let token;
let fetchSpy;

function mockResponse(json, ok = true) {
  return Promise.resolve({
    ok,
    status: ok ? 200 : 500,
    json: () => Promise.resolve(json),
    text: () => Promise.resolve(JSON.stringify(json)),
  });
}

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
});

describe('GET /api/places/status', () => {
  test('returns enabled:true when GOOGLE_PLACES_KEY env is set', async () => {
    const res = await request(app).get('/api/places/status').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.enabled).toBe(true);
    // Never leak the key itself
    expect(JSON.stringify(res.body)).not.toContain('test-fake-key');
  });
});

describe('GET /api/places/search', () => {
  test('happy path: returns mapped result array, never exposes key', async () => {
    fetchSpy.mockReturnValue(mockResponse({
      status: 'OK',
      results: [
        {
          name: 'Bairro Alto',
          formatted_address: 'Lisbon, Portugal',
          geometry: { location: { lat: 38.71, lng: -9.14 } },
          rating: 4.5,
          price_level: 2,
          place_id: 'ChIJ_test_1',
          types: ['neighborhood'],
          user_ratings_total: 1234,
        },
      ],
    }));

    const res = await request(app)
      .get('/api/places/search?q=bairro+alto')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body).toHaveLength(1);
    expect(res.body[0]).toMatchObject({
      name: 'Bairro Alto',
      address: 'Lisbon, Portugal',
      lat: 38.71,
      lng: -9.14,
      googleRating: 4.5,
      placeId: 'ChIJ_test_1',
    });
    // Key never returned to client
    expect(JSON.stringify(res.body)).not.toContain('test-fake-key');

    // Outbound call carried the key as a query param (not exposed to client, but verifies plumbing)
    const calledUrl = fetchSpy.mock.calls[0][0];
    expect(calledUrl).toContain('textsearch/json');
    expect(calledUrl).toContain('key=test-fake-key');
    expect(calledUrl).toContain('query=bairro%20alto');
  });

  test('ZERO_RESULTS → 200 with empty array', async () => {
    fetchSpy.mockReturnValue(mockResponse({ status: 'ZERO_RESULTS', results: [] }));
    const res = await request(app)
      .get('/api/places/search?q=nowhere')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body).toEqual([]);
  });

  test('REQUEST_DENIED → 502 with sanitized error', async () => {
    fetchSpy.mockReturnValue(mockResponse({ status: 'REQUEST_DENIED', error_message: 'bad key' }));
    const res = await request(app)
      .get('/api/places/search?q=anything')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(502);
    expect(res.body.error).toBe('Places API: REQUEST_DENIED');
    // Google's error_message must NOT leak to the client
    expect(JSON.stringify(res.body)).not.toContain('bad key');
  });

  test('missing q → 400', async () => {
    const res = await request(app)
      .get('/api/places/search')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(400);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  test('invalid coords → 400, no upstream call', async () => {
    const res = await request(app)
      .get('/api/places/search?q=x&lat=999&lng=999')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(400);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  test('valid lat/lng → upstream URL includes location bias', async () => {
    fetchSpy.mockReturnValue(mockResponse({ status: 'OK', results: [] }));
    await request(app)
      .get('/api/places/search?q=cafe&lat=38.71&lng=-9.14')
      .set('Authorization', `Bearer ${token}`);
    const calledUrl = fetchSpy.mock.calls[0][0];
    expect(calledUrl).toContain('location=38.71,-9.14');
    expect(calledUrl).toContain('radius=50000');
  });

  test('caps results at 10 even if Google returns more', async () => {
    const many = Array.from({ length: 20 }, (_, i) => ({
      name: `R${i}`,
      formatted_address: `addr ${i}`,
      geometry: { location: { lat: 0, lng: 0 } },
      rating: 1,
      place_id: `id_${i}`,
      types: [],
    }));
    fetchSpy.mockReturnValue(mockResponse({ status: 'OK', results: many }));
    const res = await request(app)
      .get('/api/places/search?q=many')
      .set('Authorization', `Bearer ${token}`);
    expect(res.body).toHaveLength(10);
  });
});

describe('POST /api/places/sync', () => {
  test('happy path with placeId → uses details endpoint, returns enriched fields', async () => {
    fetchSpy.mockReturnValue(mockResponse({
      status: 'OK',
      result: {
        name: 'Eiffel Tower',
        rating: 4.6,
        price_level: null,
        formatted_address: 'Champ de Mars, Paris',
        place_id: 'ChIJ_eiffel',
        geometry: { location: { lat: 48.8584, lng: 2.2945 } },
        user_ratings_total: 5000,
      },
    }));
    const res = await request(app)
      .post('/api/places/sync')
      .set('Authorization', `Bearer ${token}`)
      .send({ placeId: 'ChIJ_eiffel' });
    expect(res.status).toBe(200);
    expect(res.body.found).toBe(true);
    expect(res.body.googleRating).toBe(4.6);
    expect(res.body.placeId).toBe('ChIJ_eiffel');
    expect(res.body.address).toBe('Champ de Mars, Paris');
    const calledUrl = fetchSpy.mock.calls[0][0];
    expect(calledUrl).toContain('place/details/json');
    expect(calledUrl).toContain('place_id=ChIJ_eiffel');
  });

  test('happy path without placeId → falls back to findplace, returns found:false on no candidates', async () => {
    fetchSpy.mockReturnValue(mockResponse({ status: 'ZERO_RESULTS', candidates: [] }));
    const res = await request(app)
      .post('/api/places/sync')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: 'Nonexistent Cafe', lat: 0, lng: 0 });
    expect(res.status).toBe(200);
    expect(res.body.found).toBe(false);
    expect(fetchSpy.mock.calls[0][0]).toContain('findplacefromtext/json');
  });

  test('400 when neither name nor placeId given', async () => {
    const res = await request(app)
      .post('/api/places/sync')
      .set('Authorization', `Bearer ${token}`)
      .send({});
    expect(res.status).toBe(400);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe('POST /api/places/bulk-sync', () => {
  test('happy path: mixed placeId / text fallback, DB updated, response totals correct', async () => {
    // 2 locations: first has placeId (details path), second has only name (findplace path)
    const loc1 = await db.locations.insert({ userId: (await db.users.findOne({ username: USER.username }))._id, name: 'Spot1', lat: 1, lng: 2 });
    const loc2 = await db.locations.insert({ userId: (await db.users.findOne({ username: USER.username }))._id, name: 'Spot2', lat: 3, lng: 4 });

    fetchSpy
      .mockReturnValueOnce(mockResponse({
        status: 'OK',
        result: { rating: 4.2, price_level: 2, formatted_address: 'A1', place_id: 'pid1', user_ratings_total: 100 },
      }))
      .mockReturnValueOnce(mockResponse({
        status: 'OK',
        candidates: [{ rating: 3.9, price_level: 1, formatted_address: 'A2', place_id: 'pid2', user_ratings_total: 50 }],
      }));

    const res = await request(app)
      .post('/api/places/bulk-sync')
      .set('Authorization', `Bearer ${token}`)
      .send({ locations: [
        { id: loc1._id, name: 'Spot1', placeId: 'pid_seed_1' },
        { id: loc2._id, name: 'Spot2', lat: 3, lng: 4 },
      ]});

    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(2);
    expect(res.body[0].found).toBe(true);
    expect(res.body[1].found).toBe(true);

    // Both upstream calls used correct endpoints
    expect(fetchSpy.mock.calls[0][0]).toContain('place/details/json');
    expect(fetchSpy.mock.calls[1][0]).toContain('findplacefromtext/json');

    // DB persisted the enrichment
    const updated1 = await db.locations.findOne({ _id: loc1._id });
    expect(updated1.googleRating).toBe(4.2);
    expect(updated1._googleSyncedAt).toBeTruthy();
    const updated2 = await db.locations.findOne({ _id: loc2._id });
    expect(updated2.googleRating).toBe(3.9);
  });

  test('cap at 50 per request — only first 50 are processed', async () => {
    const userId = (await db.users.findOne({ username: USER.username }))._id;
    const inputs = [];
    for (let i = 0; i < 60; i++) {
      const l = await db.locations.insert({ userId, name: `Bulk${i}`, lat: i, lng: i });
      inputs.push({ id: l._id, name: l.name, lat: i, lng: i });
    }
    fetchSpy.mockReturnValue(mockResponse({ status: 'ZERO_RESULTS', candidates: [] }));
    const res = await request(app)
      .post('/api/places/bulk-sync')
      .set('Authorization', `Bearer ${token}`)
      .send({ locations: inputs });
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(50);
    expect(fetchSpy).toHaveBeenCalledTimes(50);
  });

  test('400 when locations is not an array', async () => {
    const res = await request(app)
      .post('/api/places/bulk-sync')
      .set('Authorization', `Bearer ${token}`)
      .send({ locations: 'oops' });
    expect(res.status).toBe(400);
  });
});

describe('GOOGLE_PLACES_KEY never leaks', () => {
  test('search response body does not contain the key', async () => {
    fetchSpy.mockReturnValue(mockResponse({
      status: 'OK',
      results: [{ name: 'X', formatted_address: 'Y', geometry: { location: { lat: 0, lng: 0 } }, place_id: 'p', types: [] }],
    }));
    const res = await request(app).get('/api/places/search?q=z').set('Authorization', `Bearer ${token}`);
    expect(JSON.stringify(res.body)).not.toContain('test-fake-key');
  });

  test('sync response body does not contain the key', async () => {
    fetchSpy.mockReturnValue(mockResponse({
      status: 'OK',
      result: { rating: 1, place_id: 'p', geometry: { location: { lat: 0, lng: 0 } } },
    }));
    const res = await request(app)
      .post('/api/places/sync')
      .set('Authorization', `Bearer ${token}`)
      .send({ placeId: 'p' });
    expect(JSON.stringify(res.body)).not.toContain('test-fake-key');
  });
});
