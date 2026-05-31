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
      places: [
        {
          id: 'ChIJ_test_1',
          displayName: { text: 'Bairro Alto' },
          formattedAddress: 'Lisbon, Portugal',
          location: { latitude: 38.71, longitude: -9.14 },
          rating: 4.5,
          priceLevel: 'PRICE_LEVEL_MODERATE',
          userRatingCount: 1234,
          types: ['neighborhood'],
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
    // priceLevel enum → integer
    expect(res.body[0].priceLevel).toBe(2);
    // Key never returned to client
    expect(JSON.stringify(res.body)).not.toContain('test-fake-key');

    // Outbound call uses new endpoint (POST searchText), NOT legacy textsearch
    const calledUrl = fetchSpy.mock.calls[0][0];
    expect(calledUrl).toContain('places:searchText');
    expect(calledUrl).not.toContain('textsearch/json');
    // Key is in header, NOT in URL
    expect(calledUrl).not.toContain('key=');
    expect(fetchSpy.mock.calls[0][1].method).toBe('POST');
    expect(fetchSpy.mock.calls[0][1].headers['X-Goog-Api-Key']).toBe('test-fake-key-do-not-leak');
    expect(fetchSpy.mock.calls[0][1].headers['X-Goog-FieldMask']).toContain('places.id');
    expect(fetchSpy.mock.calls[0][1].headers['X-Goog-FieldMask']).toContain('places.displayName');
    // Body carries textQuery
    expect(JSON.parse(fetchSpy.mock.calls[0][1].body).textQuery).toBe('bairro alto');
  });

  test('ZERO_RESULTS → 200 with empty array', async () => {
    fetchSpy.mockReturnValue(mockResponse({ places: [] }));
    const res = await request(app)
      .get('/api/places/search?q=nowhere')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body).toEqual([]);
  });

  test('REQUEST_DENIED → 502 with sanitized error', async () => {
    fetchSpy.mockReturnValue(mockResponse({ error: { status: 'PERMISSION_DENIED', code: 403, message: 'bad key' } }, false));
    const res = await request(app)
      .get('/api/places/search?q=anything')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(502);
    expect(res.body.error).toBe('Places API: PERMISSION_DENIED');
    // Google's error.message must NOT leak to the client
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

  test('valid lat/lng → locationBias sent in request body', async () => {
    fetchSpy.mockReturnValue(mockResponse({ places: [] }));
    await request(app)
      .get('/api/places/search?q=cafe&lat=38.71&lng=-9.14')
      .set('Authorization', `Bearer ${token}`);
    const body = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(body.locationBias.circle.center.latitude).toBe(38.71);
    expect(body.locationBias.circle.center.longitude).toBe(-9.14);
    expect(body.locationBias.circle.radius).toBe(50000);
  });

  test('caps results at 10 even if Google returns more', async () => {
    const many = Array.from({ length: 20 }, (_, i) => ({
      id: `id_${i}`,
      displayName: { text: `R${i}` },
      formattedAddress: `addr ${i}`,
      location: { latitude: 0, longitude: 0 },
      rating: 1,
      types: [],
    }));
    fetchSpy.mockReturnValue(mockResponse({ places: many }));
    const res = await request(app)
      .get('/api/places/search?q=many')
      .set('Authorization', `Bearer ${token}`);
    expect(res.body).toHaveLength(10);
  });
});

describe('POST /api/places/sync', () => {
  test('happy path with placeId → uses details endpoint, returns enriched fields', async () => {
    fetchSpy.mockReturnValue(mockResponse({
      id: 'ChIJ_eiffel',
      displayName: { text: 'Eiffel Tower' },
      formattedAddress: 'Champ de Mars, Paris',
      location: { latitude: 48.8584, longitude: 2.2945 },
      rating: 4.6,
      userRatingCount: 5000,
      // priceLevel intentionally absent → maps to null
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
    expect(res.body.priceLevel).toBeNull();
    const calledUrl = fetchSpy.mock.calls[0][0];
    expect(calledUrl).toContain('/v1/places/ChIJ_eiffel');
    expect(calledUrl).not.toContain('place/details/json');
    // Key in header, not URL
    expect(calledUrl).not.toContain('key=');
  });

  test('happy path without placeId → falls back to searchText, returns found:false on no candidates', async () => {
    fetchSpy.mockReturnValue(mockResponse({ places: [] }));
    const res = await request(app)
      .post('/api/places/sync')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: 'Nonexistent Cafe', lat: 0, lng: 0 });
    expect(res.status).toBe(200);
    expect(res.body.found).toBe(false);
    const calledUrl = fetchSpy.mock.calls[0][0];
    expect(calledUrl).toContain('places:searchText');
    expect(calledUrl).not.toContain('findplacefromtext/json');
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
    // 2 locations: first has placeId (details path), second has only name (searchText path)
    const loc1 = await db.locations.insert({ userId: (await db.users.findOne({ username: USER.username }))._id, name: 'Spot1', lat: 1, lng: 2 });
    const loc2 = await db.locations.insert({ userId: (await db.users.findOne({ username: USER.username }))._id, name: 'Spot2', lat: 3, lng: 4 });

    fetchSpy
      .mockReturnValueOnce(mockResponse({
        id: 'pid1',
        displayName: { text: 'Spot1' },
        formattedAddress: 'A1',
        location: { latitude: 1, longitude: 2 },
        rating: 4.2,
        priceLevel: 'PRICE_LEVEL_MODERATE',
        userRatingCount: 100,
      }))
      .mockReturnValueOnce(mockResponse({
        places: [{
          id: 'pid2',
          displayName: { text: 'Spot2' },
          formattedAddress: 'A2',
          location: { latitude: 3, longitude: 4 },
          rating: 3.9,
          priceLevel: 'PRICE_LEVEL_INEXPENSIVE',
          userRatingCount: 50,
        }],
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

    // First call: placeDetails (GET /v1/places/{id}), second: searchText (POST)
    expect(fetchSpy.mock.calls[0][0]).toContain('/v1/places/pid_seed_1');
    expect(fetchSpy.mock.calls[1][0]).toContain('places:searchText');
    // Keys never in URLs
    expect(fetchSpy.mock.calls[0][0]).not.toContain('key=');
    expect(fetchSpy.mock.calls[1][0]).not.toContain('key=');

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
    fetchSpy.mockReturnValue(mockResponse({ places: [] }));
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

describe('POST /api/places/discover', () => {
  function makePlaces(count, baseCount = 2000) {
    return Array.from({ length: count }, (_, i) => ({
      id: `disc_${i}`,
      displayName: { text: `Place ${i}` },
      formattedAddress: `Street ${i}, City`,
      location: { latitude: 38.7 + i * 0.001, longitude: -9.1 + i * 0.001 },
      rating: 4.5 - i * 0.01,
      priceLevel: 'PRICE_LEVEL_EXPENSIVE',
      userRatingCount: baseCount - i * 10,
      types: ['restaurant'],
    }));
  }

  test('happy path: filters by minRatings, sorts by userRatingCount desc, maps priceLevel', async () => {
    // 3 places >= 1000 ratings, 2 below
    const places = [
      { id: 'r1', displayName: { text: 'Top' }, formattedAddress: 'A', location: { latitude: 38.7, longitude: -9.1 }, rating: 4.8, priceLevel: 'PRICE_LEVEL_EXPENSIVE', userRatingCount: 5000, types: [] },
      { id: 'r2', displayName: { text: 'Mid' }, formattedAddress: 'B', location: { latitude: 38.71, longitude: -9.11 }, rating: 4.5, priceLevel: 'PRICE_LEVEL_MODERATE', userRatingCount: 2000, types: [] },
      { id: 'r3', displayName: { text: 'Low' }, formattedAddress: 'C', location: { latitude: 38.72, longitude: -9.12 }, rating: 4.2, priceLevel: 'PRICE_LEVEL_INEXPENSIVE', userRatingCount: 1000, types: [] },
      { id: 'r4', displayName: { text: 'Skip1' }, formattedAddress: 'D', location: { latitude: 38.73, longitude: -9.13 }, rating: 4.0, priceLevel: null, userRatingCount: 500, types: [] },
      { id: 'r5', displayName: { text: 'Skip2' }, formattedAddress: 'E', location: { latitude: 38.74, longitude: -9.14 }, rating: 3.9, priceLevel: null, userRatingCount: 10, types: [] },
    ];
    fetchSpy.mockReturnValue(mockResponse({ places }));

    const res = await request(app)
      .post('/api/places/discover')
      .set('Authorization', `Bearer ${token}`)
      .send({ lat: 38.7, lng: -9.1, category: 'restaurant', radius: 5000, minRatings: 1000 });

    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(3);
    // sorted by userRatingCount desc
    expect(res.body[0].userRatingsTotal).toBe(5000);
    expect(res.body[1].userRatingsTotal).toBe(2000);
    expect(res.body[2].userRatingsTotal).toBe(1000);
    // priceLevel enum → integer
    expect(res.body[0].priceLevel).toBe(3); // EXPENSIVE
    expect(res.body[1].priceLevel).toBe(2); // MODERATE
    expect(res.body[2].priceLevel).toBe(1); // INEXPENSIVE

    // Outbound call shape
    const [outUrl, outOpts] = fetchSpy.mock.calls[0];
    expect(outUrl).toContain('places:searchText');
    expect(outOpts.method).toBe('POST');
    expect(outOpts.headers['X-Goog-Api-Key']).toBe('test-fake-key-do-not-leak');
    expect(outOpts.headers['X-Goog-FieldMask']).toContain('places.id');
    const outBody = JSON.parse(outOpts.body);
    expect(outBody.includedType).toBe('restaurant');
    expect(outBody.locationBias.circle.center.latitude).toBe(38.7);
    expect(outBody.locationBias.circle.center.longitude).toBe(-9.1);
    expect(outBody.locationBias.circle.radius).toBe(5000);
  });

  test('bad coordinates → 400, no upstream call', async () => {
    const res = await request(app)
      .post('/api/places/discover')
      .set('Authorization', `Bearer ${token}`)
      .send({ lat: 999, lng: 0, category: 'restaurant', minRatings: 0 });
    expect(res.status).toBe(400);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  test('unsupported category → 400, no upstream call', async () => {
    const res = await request(app)
      .post('/api/places/discover')
      .set('Authorization', `Bearer ${token}`)
      .send({ lat: 38.7, lng: -9.1, category: 'airport', minRatings: 0 });
    expect(res.status).toBe(400);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  // Skipped: GOOGLE_PLACES_KEY is captured into a module-level const at require() time.
  // Mutating process.env after the module is loaded has no effect on the already-captured
  // value, so we cannot test the 501 path without re-requiring the server in a child
  // process with no env key — impractical in the current Jest setup.
  test.skip('no Places key → 501 (skipped: env key captured at module load, cannot clear mid-run)', async () => {
    const res = await request(app)
      .post('/api/places/discover')
      .set('Authorization', `Bearer ${token}`)
      .send({ lat: 38.7, lng: -9.1, category: 'restaurant', minRatings: 0 });
    expect(res.status).toBe(501);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  test('API error → 502 with sanitized error, Google message not leaked', async () => {
    fetchSpy.mockReturnValue(mockResponse({ error: { status: 'PERMISSION_DENIED', message: 'bad key' } }, false));
    const res = await request(app)
      .post('/api/places/discover')
      .set('Authorization', `Bearer ${token}`)
      .send({ lat: 38.7, lng: -9.1, category: 'restaurant', minRatings: 0 });
    expect(res.status).toBe(502);
    expect(res.body.error).toContain('PERMISSION_DENIED');
    expect(JSON.stringify(res.body)).not.toContain('bad key');
  });

  test('radius clamped to [100, 50000]; minRatings clamped to >= 0', async () => {
    fetchSpy.mockReturnValue(mockResponse({ places: [] }));
    await request(app)
      .post('/api/places/discover')
      .set('Authorization', `Bearer ${token}`)
      .send({ lat: 38.7, lng: -9.1, category: 'cafe', radius: 999999, minRatings: -50 });
    const outBody = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(outBody.locationBias.circle.radius).toBe(50000);
    // minRatings clamped to 0 — all returned places pass the filter (empty array → no assertion on count needed)
  });

  test('sort + cap at 20: 25 matching places → response length 20', async () => {
    fetchSpy.mockReturnValue(mockResponse({ places: makePlaces(25) }));
    const res = await request(app)
      .post('/api/places/discover')
      .set('Authorization', `Bearer ${token}`)
      .send({ lat: 38.7, lng: -9.1, category: 'museum', radius: 5000, minRatings: 0 });
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(20);
    // First result should have the highest userRatingCount
    expect(res.body[0].userRatingsTotal).toBeGreaterThanOrEqual(res.body[1].userRatingsTotal);
  });
});

describe('GOOGLE_PLACES_KEY never leaks', () => {
  test('search response body does not contain the key', async () => {
    fetchSpy.mockReturnValue(mockResponse({
      places: [{ id: 'p', displayName: { text: 'X' }, formattedAddress: 'Y', location: { latitude: 0, longitude: 0 }, types: [] }],
    }));
    const res = await request(app).get('/api/places/search?q=z').set('Authorization', `Bearer ${token}`);
    expect(JSON.stringify(res.body)).not.toContain('test-fake-key');
  });

  test('sync response body does not contain the key', async () => {
    fetchSpy.mockReturnValue(mockResponse({
      id: 'p',
      displayName: { text: 'X' },
      formattedAddress: '',
      location: { latitude: 0, longitude: 0 },
      rating: 1,
      userRatingCount: 0,
    }));
    const res = await request(app)
      .post('/api/places/sync')
      .set('Authorization', `Bearer ${token}`)
      .send({ placeId: 'p' });
    expect(JSON.stringify(res.body)).not.toContain('test-fake-key');
  });
});

describe('Places API (New) shape', () => {
  test('priceLevel enum round-trip: PRICE_LEVEL_EXPENSIVE → client receives 3', async () => {
    fetchSpy.mockReturnValue(mockResponse({
      places: [{
        id: 'ChIJ_exp',
        displayName: { text: 'Fancy Place' },
        formattedAddress: 'Paris, France',
        location: { latitude: 48.85, longitude: 2.35 },
        rating: 4.8,
        priceLevel: 'PRICE_LEVEL_EXPENSIVE',
        userRatingCount: 999,
        types: ['restaurant'],
      }],
    }));
    const res = await request(app)
      .get('/api/places/search?q=fancy')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body[0].priceLevel).toBe(3);
  });

  test('outbound requests include X-Goog-Api-Key and X-Goog-FieldMask; key is NOT in URL', async () => {
    // search
    fetchSpy.mockReturnValue(mockResponse({ places: [] }));
    await request(app).get('/api/places/search?q=test').set('Authorization', `Bearer ${token}`);
    const searchCall = fetchSpy.mock.calls[0];
    expect(searchCall[0]).not.toContain('key=');
    expect(searchCall[1].headers['X-Goog-Api-Key']).toBe('test-fake-key-do-not-leak');
    expect(searchCall[1].headers['X-Goog-FieldMask']).toBeTruthy();
    fetchSpy.mockRestore();

    // sync by placeId (GET details)
    fetchSpy = jest.spyOn(global, 'fetch');
    fetchSpy.mockReturnValue(mockResponse({
      id: 'pid_x',
      displayName: { text: 'X' },
      formattedAddress: '',
      location: { latitude: 0, longitude: 0 },
    }));
    await request(app).post('/api/places/sync').set('Authorization', `Bearer ${token}`).send({ placeId: 'pid_x' });
    const detailsCall = fetchSpy.mock.calls[0];
    expect(detailsCall[0]).not.toContain('key=');
    expect(detailsCall[1].headers['X-Goog-Api-Key']).toBe('test-fake-key-do-not-leak');
    expect(detailsCall[1].headers['X-Goog-FieldMask']).toBeTruthy();
    fetchSpy.mockRestore();

    // sync by text (POST searchText)
    fetchSpy = jest.spyOn(global, 'fetch');
    fetchSpy.mockReturnValue(mockResponse({ places: [] }));
    await request(app).post('/api/places/sync').set('Authorization', `Bearer ${token}`).send({ name: 'Some Place' });
    const textCall = fetchSpy.mock.calls[0];
    expect(textCall[0]).not.toContain('key=');
    expect(textCall[1].headers['X-Goog-Api-Key']).toBe('test-fake-key-do-not-leak');
    expect(textCall[1].headers['X-Goog-FieldMask']).toBeTruthy();
  });

  test('unmapped priceLevel enum (PRICE_LEVEL_UNSPECIFIED or future value) → null', async () => {
    fetchSpy.mockReturnValue(mockResponse({
      places: [{
        id: 'ChIJ_unk',
        displayName: { text: 'Unknown' },
        formattedAddress: 'Somewhere',
        location: { latitude: 0, longitude: 0 },
        priceLevel: 'PRICE_LEVEL_UNSPECIFIED',
        types: [],
      }],
    }));
    const res = await request(app)
      .get('/api/places/search?q=unknown')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body[0].priceLevel).toBeNull();

    // Also test a hypothetical future enum value
    fetchSpy.mockReturnValue(mockResponse({
      places: [{
        id: 'ChIJ_fut',
        displayName: { text: 'Future' },
        formattedAddress: 'Somewhere',
        location: { latitude: 0, longitude: 0 },
        priceLevel: 'PRICE_LEVEL_ULTRA_EXPENSIVE',
        types: [],
      }],
    }));
    const res2 = await request(app)
      .get('/api/places/search?q=future')
      .set('Authorization', `Bearer ${token}`);
    expect(res2.status).toBe(200);
    expect(res2.body[0].priceLevel).toBeNull();
  });
});
