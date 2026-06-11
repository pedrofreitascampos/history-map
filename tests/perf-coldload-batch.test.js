// S2 perf cold-load batch (2026-06-04). Pins three first-paint wins:
//   1. /api/locations sets Cache-Control: no-cache + Express's auto ETag, so
//      the browser revalidates with If-None-Match and gets a 304 on a clean
//      repeat refresh. Saves ~140 KB gzip + the JSON.stringify round-trip
//      per refresh once the on-disk cache is warm.
//   2. startApp() now calls initMap() BEFORE awaiting loadFromServer(), so
//      Leaflet tile requests run in parallel with /api/locations.
//   3. Chart.js / TopoJSON / JSZip / exifr CDN <script> tags carry `defer`
//      so they don't block HTML parsing (~300 KB off the critical path).
//      Leaflet / MarkerCluster / Heat stay blocking — initMap() needs them.

const path = require('path');
const fs = require('fs');

const testDataDir = path.join(__dirname, '..', 'data-test-perf-coldload');
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

describe('S2 perf cold-load batch', () => {
  let token;

  beforeAll(async () => {
    await db.users.remove({}, { multi: true });
    await db.locations.remove({}, { multi: true });
    const reg = await request(app)
      .post('/api/auth/register')
      .send({ username: 'perfuser', password: 'perfpass123' });
    expect(reg.status).toBe(200);
    token = reg.body.token;
  });

  // ── 1. ETag + Cache-Control on /api/locations ──
  describe('GET /api/locations — ETag + Cache-Control 304 path', () => {
    test('sets Cache-Control: no-cache to drive browser revalidation', async () => {
      const res = await request(app)
        .get('/api/locations')
        .set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(200);
      const cc = res.headers['cache-control'] || '';
      expect(cc).toMatch(/no-cache/);
    });

    test('sets an ETag header (Express auto, weak hash of body)', async () => {
      const res = await request(app)
        .get('/api/locations')
        .set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(200);
      expect(res.headers.etag).toBeTruthy();
      // Weak ETags begin with W/"…". Express defaults to weak.
      expect(res.headers.etag).toMatch(/^(W\/)?"[^"]+"$/);
    });

    test('If-None-Match matching the live ETag returns 304 with no body', async () => {
      const first = await request(app)
        .get('/api/locations')
        .set('Authorization', `Bearer ${token}`);
      expect(first.status).toBe(200);
      const etag = first.headers.etag;
      expect(etag).toBeTruthy();

      const second = await request(app)
        .get('/api/locations')
        .set('Authorization', `Bearer ${token}`)
        .set('If-None-Match', etag);
      expect(second.status).toBe(304);
      // 304 carries no body. supertest gives an empty object for parsed JSON.
      expect(second.text === '' || second.text === undefined).toBe(true);
    });

    test('inserting a location invalidates the ETag', async () => {
      const before = await request(app)
        .get('/api/locations')
        .set('Authorization', `Bearer ${token}`);
      const etagBefore = before.headers.etag;

      await request(app)
        .post('/api/locations')
        .set('Authorization', `Bearer ${token}`)
        .send({ name: 'EtagTrigger', lat: 10, lng: 10, status: 'bucket' });

      const after = await request(app)
        .get('/api/locations')
        .set('Authorization', `Bearer ${token}`);
      expect(after.status).toBe(200);
      expect(after.headers.etag).toBeTruthy();
      expect(after.headers.etag).not.toBe(etagBefore);
    });

    test('a stale If-None-Match falls through to a full 200 with new ETag', async () => {
      const res = await request(app)
        .get('/api/locations')
        .set('Authorization', `Bearer ${token}`)
        .set('If-None-Match', 'W/"deadbeef-stale-etag-from-yesterday"');
      expect(res.status).toBe(200);
      expect(res.headers.etag).toBeTruthy();
      expect(res.headers.etag).not.toBe('W/"deadbeef-stale-etag-from-yesterday"');
      expect(Array.isArray(res.body)).toBe(true);
    });
  });

  // ── 2. initMap() before awaiting loadFromServer() ──
  describe('startApp() — initMap before await loadFromServer', () => {
    const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');

    test('startApp() calls initMap() before awaiting loadFromServer()', () => {
      // Locate the startApp body and assert order. We use the call-site sentinels
      // rather than line numbers so the assertion survives unrelated refactors.
      const startIdx = html.indexOf('async function startApp(');
      expect(startIdx).toBeGreaterThan(-1);
      // Find the function's closing brace via the next top-level `function`/`async function`.
      const nextFnIdx = html.indexOf('\nasync function ', startIdx + 1);
      const fnBody = html.slice(startIdx, nextFnIdx > 0 ? nextFnIdx : startIdx + 5000);
      const initMapPos = fnBody.indexOf('if (!map) initMap()');
      const loadPos = fnBody.indexOf('await loadFromServer()');
      expect(initMapPos).toBeGreaterThan(-1);
      expect(loadPos).toBeGreaterThan(-1);
      expect(initMapPos).toBeLessThan(loadPos);
    });

    test('startApp() re-renders markers after loadFromServer() so data lands', () => {
      // The order-swap leaves initMap's renderMarkers() call rendering empty
      // state; an explicit renderMarkers() after the await populates with
      // loaded data. Static pin: renderMarkers() appears AFTER the await.
      const startIdx = html.indexOf('async function startApp(');
      const fnBody = html.slice(startIdx, startIdx + 5000);
      const loadPos = fnBody.indexOf('await loadFromServer()');
      // Find a renderMarkers() call after loadFromServer (skip the one inside
      // initMap's body which we don't see here — we see the call in startApp).
      const renderPos = fnBody.indexOf('renderMarkers()', loadPos);
      expect(renderPos).toBeGreaterThan(loadPos);
    });
  });

  // ── 3. Lazy CDN defers ──
  describe('non-critical CDN <script> tags carry defer', () => {
    const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');

    const optionalCdn = [
      'cdn.jsdelivr.net/npm/chart.js',
      // topojson-client removed — had zero call sites (S2 perf round 2)
      'cdn.jsdelivr.net/npm/jszip',
      'cdn.jsdelivr.net/npm/exifr',
    ];

    optionalCdn.forEach(host => {
      test(`<script src="…${host.split('/').pop()}…"> has defer`, () => {
        // Capture the full <script ...> tag containing this host.
        const re = new RegExp(`<script[^>]*${host.replace(/[.\/]/g, '\\$&')}[^>]*></script>`);
        const m = html.match(re);
        expect(m).toBeTruthy();
        expect(m[0]).toContain('defer');
      });
    });

    const criticalCdn = [
      'unpkg.com/leaflet@1.9.4',
      'unpkg.com/leaflet.markercluster',
      'unpkg.com/leaflet.heat',
    ];

    criticalCdn.forEach(host => {
      test(`<script src="…${host.split('/').pop()}…"> stays blocking (no defer)`, () => {
        const re = new RegExp(`<script[^>]*${host.replace(/[.\/@]/g, '\\$&')}[^>]*></script>`);
        const m = html.match(re);
        expect(m).toBeTruthy();
        // Leaflet + plugins must be available synchronously when initMap()
        // runs at startup. Asserting no `defer` here protects against
        // accidental "let's defer everything" regressions.
        expect(m[0]).not.toContain('defer');
      });
    });
  });
});
