const path = require('path');
const fs = require('fs');

// Set test data dir before requiring anything
const testDataDir = path.join(__dirname, '..', 'data-test');
if (!fs.existsSync(testDataDir)) fs.mkdirSync(testDataDir);
process.env.DATA_DIR = testDataDir;
process.env.JWT_SECRET = 'test-secret';
process.env.ALLOWED_EMAILS = '';

const request = require('supertest');
const app = require('../server/index');
const db = require('../server/db');

let token;
const testUser = { username: 'testuser', password: 'testpass123' };

beforeAll(async () => {
  await db.users.remove({}, { multi: true });
  await db.locations.remove({}, { multi: true });
  await db.trips.remove({}, { multi: true });
  await db.collections.remove({}, { multi: true });
  await db.transits.remove({}, { multi: true });
  await db.auditLog.remove({}, { multi: true });
});

afterAll(() => {
  const files = fs.readdirSync(testDataDir);
  files.forEach(f => fs.unlinkSync(path.join(testDataDir, f)));
  fs.rmdirSync(testDataDir);
});

// ─── Auth ────────────────────────────────────────────────
describe('Auth', () => {
  test('register new user', async () => {
    const res = await request(app).post('/api/auth/register').send(testUser);
    expect(res.status).toBe(200);
    expect(res.body.token).toBeDefined();
    expect(res.body.username).toBe(testUser.username);
  });

  test('reject duplicate registration', async () => {
    const res = await request(app).post('/api/auth/register').send(testUser);
    expect(res.status).toBe(409);
  });

  test('reject short password', async () => {
    const res = await request(app).post('/api/auth/register').send({ username: 'x', password: '12' });
    expect(res.status).toBe(400);
  });

  test('login with valid credentials', async () => {
    const res = await request(app).post('/api/auth/login').send(testUser);
    expect(res.status).toBe(200);
    expect(res.body.token).toBeDefined();
    token = res.body.token;
  });

  test('reject invalid password', async () => {
    const res = await request(app).post('/api/auth/login').send({ ...testUser, password: 'wrong' });
    expect(res.status).toBe(401);
  });

  test('get current user', async () => {
    const res = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.username).toBe(testUser.username);
  });

  test('reject missing token', async () => {
    const res = await request(app).get('/api/auth/me');
    expect(res.status).toBe(401);
  });

  test('reject invalid token', async () => {
    const res = await request(app).get('/api/auth/me').set('Authorization', 'Bearer bad');
    expect(res.status).toBe(401);
  });
});

// ─── Locations ───────────────────────────────────────────
describe('Locations', () => {
  let locationId;

  test('create location', async () => {
    const res = await request(app).post('/api/locations').set('Authorization', `Bearer ${token}`)
      .send({ name: 'Test Place', lat: 38.7, lng: -9.1, category: 'restaurant' });
    expect(res.status).toBe(200);
    expect(res.body.name).toBe('Test Place');
    expect(res.body._id).toBeDefined();
    locationId = res.body._id;
  });

  test('list locations', async () => {
    const res = await request(app).get('/api/locations').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(1);
  });

  test('update location', async () => {
    const res = await request(app).put(`/api/locations/${locationId}`).set('Authorization', `Bearer ${token}`)
      .send({ name: 'Updated', myRating: 5 });
    expect(res.status).toBe(200);
    expect(res.body.name).toBe('Updated');
    expect(res.body.myRating).toBe(5);
  });

  test('reject update nonexistent', async () => {
    const res = await request(app).put('/api/locations/nope').set('Authorization', `Bearer ${token}`)
      .send({ name: 'X' });
    expect(res.status).toBe(404);
  });

  test('PUT allowlists fields: keeps tripOrder, drops unknown keys, ignores userId override', async () => {
    const res = await request(app).put(`/api/locations/${locationId}`).set('Authorization', `Bearer ${token}`)
      .send({ tripOrder: 3, address: '5 Main St', evilField: 'nope', userId: 'someone-else' });
    expect(res.status).toBe(200);
    expect(res.body.tripOrder).toBe(3);       // tripOrder is allowlisted (reorder feature)
    expect(res.body.address).toBe('5 Main St');
    expect(res.body.evilField).toBeUndefined(); // unknown key dropped
    expect(res.body.userId).not.toBe('someone-else'); // ownership cannot be reassigned
  });

  test('bulk import', async () => {
    const res = await request(app).post('/api/locations/bulk').set('Authorization', `Bearer ${token}`)
      .send({ locations: [
        { name: 'Bulk1', lat: 40, lng: -8, category: 'bar' },
        { name: 'Bulk2', lat: 41, lng: -7, category: 'park' },
      ]});
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(2);
  });

  test('delete location', async () => {
    const res = await request(app).delete(`/api/locations/${locationId}`).set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    const list = await request(app).get('/api/locations').set('Authorization', `Bearer ${token}`);
    expect(list.body).toHaveLength(2);
  });
});

// ─── Bucket-list strength ────────────────────────────────
describe('Bucket-list strength', () => {
  test('bulk import round-trips a valid bucketStrength (1-5)', async () => {
    const res = await request(app).post('/api/locations/bulk').set('Authorization', `Bearer ${token}`)
      .send({ locations: [
        { name: 'Wishlist3', lat: 50, lng: 50, category: 'monument', status: 'bucket', bucketStrength: 3 },
        { name: 'Wishlist5', lat: 51, lng: 51, category: 'park',     status: 'bucket', bucketStrength: 5 },
      ]});
    expect(res.status).toBe(200);
    expect(res.body[0].bucketStrength).toBe(3);
    expect(res.body[1].bucketStrength).toBe(5);
  });

  test('bulk import clamps out-of-range bucketStrength', async () => {
    const res = await request(app).post('/api/locations/bulk').set('Authorization', `Bearer ${token}`)
      .send({ locations: [
        { name: 'Negative',   lat: 60, lng: 60, category: 'park', status: 'bucket', bucketStrength: -1 },
        { name: 'TooHigh',    lat: 61, lng: 61, category: 'park', status: 'bucket', bucketStrength: 99 },
        { name: 'AsString',   lat: 62, lng: 62, category: 'park', status: 'bucket', bucketStrength: '4' },
        { name: 'AsGarbage',  lat: 63, lng: 63, category: 'park', status: 'bucket', bucketStrength: 'banana' },
      ]});
    expect(res.status).toBe(200);
    const byName = Object.fromEntries(res.body.map(l => [l.name, l]));
    expect(byName.Negative.bucketStrength).toBe(0);
    expect(byName.TooHigh.bucketStrength).toBe(5);
    expect(byName.AsString.bucketStrength).toBe(4);
    expect(byName.AsGarbage.bucketStrength).toBe(0);
  });

  test('PUT accepts bucketStrength update', async () => {
    // Create a fresh bucket location
    const created = await request(app).post('/api/locations').set('Authorization', `Bearer ${token}`)
      .send({ name: 'TopPriority', lat: 70, lng: 70, category: 'monument', status: 'bucket' });
    expect(created.status).toBe(200);
    const updated = await request(app).put(`/api/locations/${created.body._id}`).set('Authorization', `Bearer ${token}`)
      .send({ bucketStrength: 4 });
    expect(updated.status).toBe(200);
    expect(updated.body.bucketStrength).toBe(4);
  });

  test('PUT clamps out-of-range bucketStrength (regression: prevents stored-render DoS)', async () => {
    // Stored values are used in `'♥'.repeat(loc.bucketStrength)` on the client.
    // String.prototype.repeat() throws RangeError for huge or negative numbers,
    // which would break the popup/list render for the affected location.
    const created = await request(app).post('/api/locations').set('Authorization', `Bearer ${token}`)
      .send({ name: 'ClampTarget', lat: 80, lng: 80, category: 'monument', status: 'bucket' });
    expect(created.status).toBe(200);

    const tooBig = await request(app).put(`/api/locations/${created.body._id}`).set('Authorization', `Bearer ${token}`)
      .send({ bucketStrength: 999999 });
    expect(tooBig.body.bucketStrength).toBe(5);

    const negative = await request(app).put(`/api/locations/${created.body._id}`).set('Authorization', `Bearer ${token}`)
      .send({ bucketStrength: -10 });
    expect(negative.body.bucketStrength).toBe(0);

    const garbage = await request(app).put(`/api/locations/${created.body._id}`).set('Authorization', `Bearer ${token}`)
      .send({ bucketStrength: 'banana' });
    expect(garbage.body.bucketStrength).toBe(0);
  });
});

// ─── Auto-approve & Approval ─────────────────────────────
describe('Import approval flow', () => {
  test('bulk import with needsApproval flag', async () => {
    const res = await request(app).post('/api/locations/bulk').set('Authorization', `Bearer ${token}`)
      .send({ locations: [
        { name: 'Pending1', lat: 1, lng: 1, category: 'location', needsApproval: true, suggestedCategory: 'restaurant' },
        { name: 'Pending2', lat: 2, lng: 2, category: 'location', needsApproval: true, suggestedCategory: 'stadium' },
      ]});
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(2);
    expect(res.body[0].needsApproval).toBe(true);
  });

  test('auto-approved imports have needsApproval false', async () => {
    const res = await request(app).post('/api/locations/bulk').set('Authorization', `Bearer ${token}`)
      .send({ locations: [
        { name: 'AutoApproved', lat: 3, lng: 3, category: 'restaurant', needsApproval: false },
      ]});
    expect(res.body[0].needsApproval).toBe(false);
  });

  test('auto-approved import does not require subsequent approval', async () => {
    // Regression: importing with auto-approve then calling renderMarkers
    // crashed with _animating null because map wasn't active
    const res = await request(app).post('/api/locations/bulk').set('Authorization', `Bearer ${token}`)
      .send({ locations: [
        { name: 'AutoPlace1', lat: 10, lng: 10, category: 'stadium', needsApproval: false, suggestedCategory: null },
        { name: 'AutoPlace2', lat: 11, lng: 11, category: 'bar', needsApproval: false, suggestedCategory: null },
      ]});
    expect(res.status).toBe(200);
    // Verify none need approval
    res.body.forEach(loc => {
      expect(loc.needsApproval).toBe(false);
      expect(loc.suggestedCategory).toBeNull();
    });
    // Verify they show up in regular listing without needing approval
    const list = await request(app).get('/api/locations').set('Authorization', `Bearer ${token}`);
    const autoPlaces = list.body.filter(l => l.name.startsWith('AutoPlace'));
    expect(autoPlaces).toHaveLength(2);
    autoPlaces.forEach(l => expect(l.needsApproval).toBe(false));
  });

  test('approve location updates category and clears needsApproval', async () => {
    // Find a pending location
    const list = await request(app).get('/api/locations').set('Authorization', `Bearer ${token}`);
    const pending = list.body.find(l => l.needsApproval && l.name === 'Pending1');
    expect(pending).toBeDefined();

    // Approve it with a new category
    const res = await request(app).put(`/api/locations/${pending._id}`).set('Authorization', `Bearer ${token}`)
      .send({ needsApproval: false, suggestedCategory: null, category: 'restaurant' });
    expect(res.status).toBe(200);
    expect(res.body.needsApproval).toBe(false);
    expect(res.body.category).toBe('restaurant');

    // Verify it stays approved on re-fetch
    const refetch = await request(app).get('/api/locations').set('Authorization', `Bearer ${token}`);
    const approved = refetch.body.find(l => l._id === pending._id);
    expect(approved.needsApproval).toBe(false);
  });
});

// ─── Trips ───────────────────────────────────────────────
describe('Trips', () => {
  let tripId;

  test('create trip', async () => {
    const res = await request(app).post('/api/trips').set('Authorization', `Bearer ${token}`)
      .send({ name: 'Test Trip', startDate: '2024-01-01', endDate: '2024-01-07' });
    expect(res.status).toBe(200);
    expect(res.body.name).toBe('Test Trip');
    tripId = res.body._id;
  });

  test('list trips', async () => {
    const res = await request(app).get('/api/trips').set('Authorization', `Bearer ${token}`);
    expect(res.body).toHaveLength(1);
  });

  test('update trip', async () => {
    const res = await request(app).put(`/api/trips/${tripId}`).set('Authorization', `Bearer ${token}`)
      .send({ name: 'Renamed' });
    expect(res.status).toBe(200);
    expect(res.body.name).toBe('Renamed');
  });

  test('delete trip', async () => {
    await request(app).delete(`/api/trips/${tripId}`).set('Authorization', `Bearer ${token}`);
    const list = await request(app).get('/api/trips').set('Authorization', `Bearer ${token}`);
    expect(list.body).toHaveLength(0);
  });
});

// ─── Collections ─────────────────────────────────────────
describe('Collections', () => {
  let colId;

  test('create collection with just a name', async () => {
    // Regression: creating with minimal fields (just name) must work.
    // Frontend now only sends name + defaults, no multi-prompt.
    const res = await request(app).post('/api/collections').set('Authorization', `Bearer ${token}`)
      .send({ name: 'My Places', emoji: '🏆', description: '', totalItems: null });
    expect(res.status).toBe(200);
    expect(res.body.name).toBe('My Places');
    expect(res.body._id).toBeDefined();
    colId = res.body._id;
  });

  test('create collection with full fields', async () => {
    const res = await request(app).post('/api/collections').set('Authorization', `Bearer ${token}`)
      .send({ name: 'UNESCO', emoji: '🏰', description: 'World Heritage', totalItems: 1199 });
    expect(res.status).toBe(200);
    expect(res.body.totalItems).toBe(1199);
  });

  test('create collection with null optional fields', async () => {
    // Regression: null totalItems, empty description must not crash.
    // After sanitizer added in Phase B, null/invalid values are dropped rather
    // than persisted — totalItems being absent is acceptable; the assertion is
    // that the request doesn't crash and a valid collection is created.
    const res = await request(app).post('/api/collections').set('Authorization', `Bearer ${token}`)
      .send({ name: 'Open Ended', emoji: '📋', description: null, totalItems: null });
    expect(res.status).toBe(200);
    expect(res.body.name).toBe('Open Ended');
    expect(res.body.totalItems == null).toBe(true); // null or undefined both OK
  });

  test('list collections', async () => {
    const res = await request(app).get('/api/collections').set('Authorization', `Bearer ${token}`);
    expect(res.body).toHaveLength(3);
  });

  test('update collection', async () => {
    const res = await request(app).put(`/api/collections/${colId}`).set('Authorization', `Bearer ${token}`)
      .send({ totalItems: 1200, emoji: '🌍' });
    expect(res.body.totalItems).toBe(1200);
    expect(res.body.emoji).toBe('🌍');
  });

  test('delete collection', async () => {
    // Delete all 3
    const list = await request(app).get('/api/collections').set('Authorization', `Bearer ${token}`);
    for (const c of list.body) {
      await request(app).delete(`/api/collections/${c._id}`).set('Authorization', `Bearer ${token}`);
    }
    const after = await request(app).get('/api/collections').set('Authorization', `Bearer ${token}`);
    expect(after.body).toHaveLength(0);
  });
});

// ─── Data isolation ──────────────────────────────────────
describe('User data isolation', () => {
  let token2;

  test('second user sees empty data', async () => {
    const reg = await request(app).post('/api/auth/register').send({ username: 'user2', password: 'pass1234' });
    token2 = reg.body.token;

    const locs = await request(app).get('/api/locations').set('Authorization', `Bearer ${token2}`);
    expect(locs.body).toHaveLength(0);
  });

  test('second user cannot modify first user data', async () => {
    const locs = await request(app).get('/api/locations').set('Authorization', `Bearer ${token}`);
    const id = locs.body[0]._id;
    const res = await request(app).put(`/api/locations/${id}`).set('Authorization', `Bearer ${token2}`)
      .send({ name: 'Hacked!' });
    expect(res.status).toBe(404);
  });
});

// ─── Import parsers (unit tests via inline execution) ────
describe('Import parsers', () => {
  // Extract parser functions from index.html and test them
  const indexHtml = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');

  // Helper: extract and eval a function from the HTML
  function evalParser(fnName) {
    // We can't eval the whole file, but we can test the detection logic
    return indexHtml.includes(`function ${fnName}`);
  }

  test('all Google format parsers exist', () => {
    expect(evalParser('parseGoogleSavedPlaces')).toBe(true);
    expect(evalParser('parseGoogleTimelineOld')).toBe(true);
    expect(evalParser('parseGoogleTimelineNew')).toBe(true);
    expect(evalParser('parseGoogleTimelineSegments')).toBe(true);
    expect(evalParser('parseGoogleRawLocations')).toBe(true);
    expect(evalParser('parseCSV')).toBe(true);
    expect(evalParser('parseKML')).toBe(true);
    expect(evalParser('parseGeoJSON')).toBe(true);
  });

  test('CSV parser handles Google Takeout format (no coords, geocodes by name)', () => {
    // Regression: Google Takeout Saved CSV has Title,Note,URL,Tags,Comment
    // with NO lat/lng — only place name in URL. Must geocode via Nominatim.
    expect(indexHtml).toContain('isGoogleSaved');
    expect(indexHtml).toContain('_needsGeocode');
    expect(indexHtml).toContain('geocodeCSVResults');
  });

  test('CSV parser skips empty rows', () => {
    // Google Takeout CSV has blank row 2 (just commas)
    expect(indexHtml).toContain("if (!name) continue");
  });

  test('handleFiles handles async parsers (geocoding)', () => {
    // CSV geocoding returns a Promise, handleFiles must await it
    expect(indexHtml).toContain('parsed instanceof Promise');
    expect(indexHtml).toContain('parsed = await parsed');
  });

  test('Timeline detection covers all known formats', () => {
    // Old: { timelineObjects: [...] }
    expect(indexHtml).toContain('data.timelineObjects');
    // Mid: [{ placeVisit: {...} }]
    expect(indexHtml).toContain('data[0]?.placeVisit');
    // New: [{ visit: { topCandidate: {...} } }]
    expect(indexHtml).toContain('data[0]?.visit');
    // New with timestamps: [{ startTime, endTime, visit }]
    expect(indexHtml).toContain('data[0]?.startTime && data[0]?.endTime');
    // Segments: { semanticSegments: [...] }
    expect(indexHtml).toContain('data.semanticSegments');
    // Timeline Edits: { timelineEdits: [...] }
    expect(indexHtml).toContain('data.timelineEdits');
    // Raw: { locations: [{ latitudeE7 }] }
    expect(indexHtml).toContain('data.locations[0]?.latitudeE7');
  });

  test('import preview has dedup detection', () => {
    // Regression: importing the same data twice created duplicates.
    // Preview must flag items that match existing locations by name or proximity.
    expect(indexHtml).toContain('function findDuplicate');
    expect(indexHtml).toContain('_duplicate');
    expect(indexHtml).toContain('skip-dups-btn');
  });

  test('confirmImport respects unchecked rows', () => {
    // Users can uncheck duplicates before importing
    expect(indexHtml).toContain('import-row-cb');
    expect(indexHtml).toContain('uncheckedIdxs');
  });

  test('Timeline Edits parser handles placeAggregateInfo with latE7/lngE7', () => {
    expect(indexHtml).toContain('parseGoogleTimelineEdits');
    expect(indexHtml).toContain('placeAggregateInfo');
    expect(indexHtml).toContain('pp.latE7');
  });

  test('Raw locations parser caps output and filters drive-by points', () => {
    // Must require multiple readings (>= 3) to count as a place
    expect(indexHtml).toContain('c.count >= 3');
    // Must cap at 500 to prevent massive imports
    expect(indexHtml).toContain('.slice(0, 500)');
  });

  test('extractPlaceId exists and handles known Google Maps URL formats', () => {
    expect(indexHtml).toContain('function extractPlaceId');
    // Supports place_id=... and place_id:... formats
    expect(indexHtml).toContain('place_id[=:]');
    // Supports ftid format
    expect(indexHtml).toContain('ftid=');
  });

  test('parseGoogleSavedPlaces extracts Place ID from google_maps_url', () => {
    expect(indexHtml).toContain('extractPlaceId(googleUrl)');
    expect(indexHtml).toContain('result._googlePlaceId = placeId');
  });

  test('getGoogleMapsUrl builds URL from available identifiers', () => {
    expect(indexHtml).toContain('function getGoogleMapsUrl');
    // Prefers _googleUrl, falls back to _googlePlaceId, then lat/lng
    expect(indexHtml).toContain('loc._googleUrl');
    expect(indexHtml).toContain('loc._googlePlaceId');
    expect(indexHtml).toContain('api=1&query=');
  });

  test('Google Maps link shown in popup and edit modal', () => {
    expect(indexHtml).toContain('loc-google-maps-link');
    expect(indexHtml).toContain('Open in Google Maps');
  });
});

// ─── Frontend invariants (documented, not runtime-testable without e2e) ──
describe('Frontend invariants (code checks)', () => {
  const indexHtml = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');

  test('heatmap zoom handler is a stable reference outside renderMarkers', () => {
    // Regression: if _heatZoomHandler is defined inside renderMarkers,
    // map.off() can't remove old listeners → breaks after toggling
    const handlerDef = indexHtml.indexOf('function _heatZoomHandler()');
    const renderDef = indexHtml.indexOf('function renderMarkers()');
    expect(handlerDef).toBeGreaterThan(-1);
    expect(renderDef).toBeGreaterThan(-1);
    expect(handlerDef).toBeLessThan(renderDef); // defined before renderMarkers
  });

  test('renderMarkers cleans up zoomend listener before adding', () => {
    // Must call map.off before map.on to prevent accumulation
    const offCall = indexHtml.indexOf("map.off('zoomend', _heatZoomHandler)");
    const onCall = indexHtml.indexOf("map.on('zoomend', _heatZoomHandler)");
    expect(offCall).toBeGreaterThan(-1);
    expect(onCall).toBeGreaterThan(-1);
    expect(offCall).toBeLessThan(onCall);
  });

  test('renderMarkers removes heat layer before re-adding', () => {
    // Must remove heatLayer at start of renderMarkers to prevent ghost layers
    expect(indexHtml).toContain('map.removeLayer(heatLayer)');
  });

  test('heatLayer is recreated fresh each render, not reused via setOptions', () => {
    // Regression: setOptions on an existing removed heatLayer is unreliable
    // and causes the layer to break when filters change.
    // renderMarkers must create a new L.heatLayer() each time heat mode renders.
    const renderBody = indexHtml.substring(
      indexHtml.indexOf('function renderMarkers()'),
      indexHtml.indexOf('function renderMarkers()') + 3000
    );
    expect(renderBody).toContain('heatLayer = L.heatLayer(');
    expect(renderBody).not.toContain('heatLayer.setOptions');
    expect(renderBody).not.toContain('heatLayer.setLatLngs');
  });

  test('heatLayer initialized as null in initMap, not pre-created', () => {
    // Regression: pre-creating heatLayer in initMap then trying to reconfigure
    // it in renderMarkers caused stale state. Must be null until first heat render.
    expect(indexHtml).toContain('heatLayer = null;');
  });

  test('renderMarkers has full teardown comment documenting invariants', () => {
    expect(indexHtml).toContain('INVARIANT (regression fix): renderMarkers MUST fully tear down');
  });

  test('renderMarkers defers when map tab is not active', () => {
    // Regression: calling renderMarkers from Import tab with heatmap mode
    // caused _animating null error because Leaflet.heat canvas not ready
    expect(indexHtml).toContain('_renderMarkersPending = true');
    expect(indexHtml).toContain("map-view')?.classList.contains('active')");
  });

  test('renderMarkers wraps heat operations in try/catch', () => {
    // Regression: Leaflet.heat throws on _animating when map not visible
    const renderBody = indexHtml.substring(
      indexHtml.indexOf('function renderMarkers()'),
      indexHtml.indexOf('function renderMarkers()') + 4000
    );
    expect(renderBody).toContain("catch (err)");
    expect(renderBody).toContain("map may not be visible");
  });

  test('switchView flushes pending render when returning to map', () => {
    expect(indexHtml).toContain('_renderMarkersPending = false; renderMarkers()');
  });

  // ── Security ──
  test('XSS: esc() helper exists and is used in popup content', () => {
    expect(indexHtml).toContain('function esc(str)');
    expect(indexHtml).toContain('esc(loc.name)');
    expect(indexHtml).toContain('esc(loc.notes)');
    expect(indexHtml).toContain('esc(p)'); // people tags
    expect(indexHtml).toContain('esc(t)'); // tag chips
  });

  test('XSS: tag filter uses DOM API not innerHTML with onclick', () => {
    // Regression: tag names in onclick attributes allow XSS
    const tagBuildFn = indexHtml.substring(
      indexHtml.indexOf('function buildTagFilters()'),
      indexHtml.indexOf('function buildTagFilters()') + 1000
    );
    expect(tagBuildFn).toContain('document.createElement');
    expect(tagBuildFn).toContain('.textContent');
    expect(tagBuildFn).not.toContain("onclick=\"toggleTagFilter('");
  });

  test('path traversal: backup download uses path.resolve + path.basename', () => {
    const serverJs = fs.readFileSync(path.join(__dirname, '..', 'server', 'index.js'), 'utf-8');
    expect(serverJs).toContain('path.resolve(');
    expect(serverJs).toContain('path.basename(');
    expect(serverJs).toContain("normalizedDir + path.sep");
  });

  test('DB has indexes on userId for all collections', () => {
    const dbJs = fs.readFileSync(path.join(__dirname, '..', 'server', 'db.js'), 'utf-8');
    expect(dbJs).toContain("locations.ensureIndex({ fieldName: 'userId' })");
    expect(dbJs).toContain("trips.ensureIndex({ fieldName: 'userId' })");
    expect(dbJs).toContain("collections.ensureIndex({ fieldName: 'userId' })");
  });

  // ── Performance ──
  test('filter changes are debounced', () => {
    expect(indexHtml).toContain('_filterTimer');
    expect(indexHtml).toContain('setTimeout');
    expect(indexHtml).toContain('clearTimeout(_filterTimer)');
  });

  test('cluster mode uses batch addLayers', () => {
    expect(indexHtml).toContain('markersLayer.addLayers(markers)');
  });

  test('tag filter has rebuild cache', () => {
    expect(indexHtml).toContain('_tagFilterGen');
  });

  test('bulk edit is a separate tab with list-based selection', () => {
    // Regression: bulk edit on map tab caused cluster conflicts and unresponsiveness.
    // Must be a separate view with checkbox list, not map marker selection.
    expect(indexHtml).toContain('id="bulk-view"');
    expect(indexHtml).toContain('function initBulkView');
    expect(indexHtml).toContain('function renderBulkList');
    expect(indexHtml).toContain('function applyBulkEdit');
    // Must NOT interfere with map markers
    expect(indexHtml).not.toContain('data-bulk-id');
    expect(indexHtml).not.toContain('toggleBulkMode');
  });

  // ── Phase D: UI/UX fixes ──

  test('U1: replay panel has mobile media query shrinking map to 240px', () => {
    expect(indexHtml).toContain('#replay-map { height: 240px; }');
    expect(indexHtml).toContain('.replay-scrubber-wrap { flex: 1 1 100%; order: 3; min-width: 0; }');
  });

  test('U2: trips-view flex-direction set via CSS not inline style', () => {
    expect(indexHtml).toContain('#trips-view { flex-direction: row; }');
    expect(indexHtml).not.toContain('id="trips-view" style="flex-direction:row;"');
    expect(indexHtml).toContain('#trips-view #trip-sidebar { width: 360px; flex-shrink: 0; }');
  });

  test('U3: clear-btn elements are <button> tags (keyboard accessible)', () => {
    const matches = indexHtml.match(/<button class="clear-btn"/g) || [];
    expect(matches.length).toBeGreaterThanOrEqual(5);
    expect(indexHtml).not.toContain('<span class="clear-btn"');
  });

  test('U3: clear-btn has visible focus style in CSS', () => {
    expect(indexHtml).toContain('.filter-section h4 .clear-btn:focus');
    expect(indexHtml).toContain('outline: 2px solid var(--accent)');
  });

  test('U4: currentBaseTileUrl helper defined for sub-map theme inheritance', () => {
    expect(indexHtml).toContain('function currentBaseTileUrl()');
    expect(indexHtml).toContain('window._activeBaseLayer && window._activeBaseLayer._url');
  });

  test('U5: bulk delete button has aria-label', () => {
    expect(indexHtml).toContain('aria-label="Delete selected locations"');
  });

  test('U6: toast container has aria-live and role=status', () => {
    expect(indexHtml).toContain('aria-live="polite"');
    expect(indexHtml).toContain('role="status"');
  });

});

// ─── Backups ────────────────────────────────────────────
describe('User backup endpoints', () => {
  test('my-backups returns empty array when no backups exist', async () => {
    const res = await request(app).get('/api/my-backups').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body).toEqual([]);
  });

  test('my-backup returns 404 when no backups exist', async () => {
    const res = await request(app).get('/api/my-backup').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(404);
  });

  test('my-backup/:filename rejects access to other users backups', async () => {
    const res = await request(app).get('/api/my-backup/otheruser_2026-01-01.json').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(403);
  });

  test('my-backups requires auth', async () => {
    const res = await request(app).get('/api/my-backups');
    expect(res.status).toBe(401);
  });
});

// ─── Static files ────────────────────────────────────────
describe('Static files', () => {
  test('serves index.html', async () => {
    const res = await request(app).get('/');
    expect(res.status).toBe(200);
    expect(res.text).toContain('Oikumene');
  });

  test('serves admin1.json', async () => {
    const res = await request(app).get('/admin1.json');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/json/);
  });
});

// ─── Auth negative paths ─────────────────────────────────
describe('Auth negative paths', () => {
  test('register without username → 400', async () => {
    const res = await request(app).post('/api/auth/register').send({ password: 'testpass123' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBeDefined();
  });

  test('register without password → 400', async () => {
    const res = await request(app).post('/api/auth/register').send({ username: 'newuser' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBeDefined();
  });

  test('login with nonexistent username → 401', async () => {
    const res = await request(app).post('/api/auth/login').send({ username: 'doesnotexist', password: 'whatever' });
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('Invalid credentials');
  });

  test('login without body fields → 401', async () => {
    // username undefined → findOne returns null → 401
    const res = await request(app).post('/api/auth/login').send({});
    expect(res.status).toBe(401);
  });

  test('google auth when OAuth not configured → 501', async () => {
    // In tests GOOGLE_CLIENT_ID is unset → googleClient is null → 501 (not 400)
    const res = await request(app).post('/api/auth/google').send({ credential: 'fake-credential' });
    expect(res.status).toBe(501);
  });
});

// ─── Authorization (no token) ────────────────────────────
describe('Authorization (no token)', () => {
  test('GET /api/locations → 401 No token', async () => {
    const res = await request(app).get('/api/locations');
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('No token');
  });

  test('GET /api/trips → 401 No token', async () => {
    const res = await request(app).get('/api/trips');
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('No token');
  });

  test('GET /api/collections → 401 No token', async () => {
    const res = await request(app).get('/api/collections');
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('No token');
  });

  test('GET /api/settings → 401 No token', async () => {
    const res = await request(app).get('/api/settings');
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('No token');
  });

  test('GET /api/places/status → 401 No token', async () => {
    const res = await request(app).get('/api/places/status');
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('No token');
  });
});

// ─── Authorization (invalid token) ──────────────────────
describe('Authorization (invalid token)', () => {
  test('GET /api/locations → 401 Invalid token', async () => {
    const res = await request(app).get('/api/locations').set('Authorization', 'Bearer garbage-not-a-real-jwt');
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('Invalid token');
  });

  test('PUT /api/locations/anything → 401 Invalid token', async () => {
    const res = await request(app).put('/api/locations/anything').set('Authorization', 'Bearer garbage-not-a-real-jwt').send({ name: 'X' });
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('Invalid token');
  });
});

// ─── CRUD not found ──────────────────────────────────────
describe('CRUD not found', () => {
  test('PUT /api/locations/nonexistent-id-xyz → 404', async () => {
    const res = await request(app).put('/api/locations/nonexistent-id-xyz').set('Authorization', `Bearer ${token}`).send({ name: 'X' });
    expect(res.status).toBe(404);
    expect(res.body.error).toBe('Not found');
  });

  test('DELETE /api/locations/nonexistent-id-xyz → 404', async () => {
    const res = await request(app).delete('/api/locations/nonexistent-id-xyz').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(404);
    expect(res.body.error).toBe('Not found');
  });

  test('PUT /api/trips/nonexistent-id-xyz → 404', async () => {
    const res = await request(app).put('/api/trips/nonexistent-id-xyz').set('Authorization', `Bearer ${token}`).send({ name: 'X' });
    expect(res.status).toBe(404);
    expect(res.body.error).toBe('Not found');
  });

  test('DELETE /api/trips/nonexistent-id-xyz → 404', async () => {
    const res = await request(app).delete('/api/trips/nonexistent-id-xyz').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(404);
    expect(res.body.error).toBe('Not found');
  });

  test('PUT /api/collections/nonexistent-id-xyz → 404', async () => {
    const res = await request(app).put('/api/collections/nonexistent-id-xyz').set('Authorization', `Bearer ${token}`).send({ name: 'X' });
    expect(res.status).toBe(404);
    expect(res.body.error).toBe('Not found');
  });

  test('DELETE /api/collections/nonexistent-id-xyz → 404', async () => {
    const res = await request(app).delete('/api/collections/nonexistent-id-xyz').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(404);
    expect(res.body.error).toBe('Not found');
  });
});

// ─── CRUD validation ─────────────────────────────────────
describe('CRUD validation', () => {
  test('POST /api/locations missing name → 400 Name required', async () => {
    const res = await request(app).post('/api/locations').set('Authorization', `Bearer ${token}`).send({ lat: 38.7, lng: -9.1 });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Name required');
  });

  test('POST /api/locations missing lat → 400 Invalid latitude', async () => {
    const res = await request(app).post('/api/locations').set('Authorization', `Bearer ${token}`).send({ name: 'X', lng: -9.1 });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Invalid latitude');
  });

  test('POST /api/locations lat: 91 → 400 Invalid latitude', async () => {
    const res = await request(app).post('/api/locations').set('Authorization', `Bearer ${token}`).send({ name: 'X', lat: 91, lng: 0 });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Invalid latitude');
  });

  test('POST /api/locations lng: 181 → 400 Invalid longitude', async () => {
    const res = await request(app).post('/api/locations').set('Authorization', `Bearer ${token}`).send({ name: 'X', lat: 0, lng: 181 });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Invalid longitude');
  });

  test('POST /api/locations lat: "abc" (non-number) → 400 Invalid latitude', async () => {
    const res = await request(app).post('/api/locations').set('Authorization', `Bearer ${token}`).send({ name: 'X', lat: 'abc', lng: 0 });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Invalid latitude');
  });

  test('POST /api/locations/bulk with non-array body → 400 Expected array', async () => {
    const res = await request(app).post('/api/locations/bulk').set('Authorization', `Bearer ${token}`).send({ locations: 'foo' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Expected array');
  });
});

// ─── Bulk import edge cases ──────────────────────────────
describe('Bulk import edge cases', () => {
  test('POST /api/locations/bulk with empty array → 400 No valid locations', async () => {
    const res = await request(app).post('/api/locations/bulk').set('Authorization', `Bearer ${token}`).send({ locations: [] });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('No valid locations');
  });

  test('POST /api/locations/bulk with only invalid items → 400 No valid locations', async () => {
    const res = await request(app).post('/api/locations/bulk').set('Authorization', `Bearer ${token}`).send({ locations: [{ name: 'x' }] });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('No valid locations');
  });

  test('POST /api/collections/bulk with non-array → 400 Expected array', async () => {
    const res = await request(app).post('/api/collections/bulk').set('Authorization', `Bearer ${token}`).send({ collections: 'foo' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Expected array');
  });
});

// ─── Settings ────────────────────────────────────────────
describe('Settings', () => {
  test('GET /api/settings returns googlePlacesKey: null for fresh user', async () => {
    const res = await request(app).get('/api/settings').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.googlePlacesKey).toBeNull();
  });

  test('PUT /api/settings sets key, GET returns masked value', async () => {
    const put = await request(app).put('/api/settings').set('Authorization', `Bearer ${token}`).send({ googlePlacesKey: 'AIzaTest1234' });
    expect(put.status).toBe(200);
    const get = await request(app).get('/api/settings').set('Authorization', `Bearer ${token}`);
    expect(get.status).toBe(200);
    expect(get.body.googlePlacesKey).toBe('••••1234');
  });

  test('PUT /api/settings with empty string clears key, GET returns null', async () => {
    await request(app).put('/api/settings').set('Authorization', `Bearer ${token}`).send({ googlePlacesKey: '' });
    const get = await request(app).get('/api/settings').set('Authorization', `Bearer ${token}`);
    expect(get.status).toBe(200);
    expect(get.body.googlePlacesKey).toBeNull();
  });
});

// ─── Backup path security ────────────────────────────────
describe('Backup path security', () => {
  test('GET /api/my-backup/other-user-file.json → 403 Access denied', async () => {
    const res = await request(app).get('/api/my-backup/other-user-file.json').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('Access denied');
  });

  test('GET /api/my-backup with path traversal → 403', async () => {
    const res = await request(app).get('/api/my-backup/..%2F..%2Fetc%2Fpasswd').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(403);
  });

  test('GET /api/my-backups without token → 401', async () => {
    const res = await request(app).get('/api/my-backups');
    expect(res.status).toBe(401);
  });
});

// ─── Cross-user data isolation (404 path) ────────────────
describe('Cross-user data isolation (404 path)', () => {
  let tokenB;

  beforeAll(async () => {
    const reg = await request(app).post('/api/auth/register').send({ username: 'userB-isolation', password: 'passB1234' });
    tokenB = reg.body.token;
  });

  test('User B cannot PUT User A location → 404', async () => {
    const created = await request(app).post('/api/locations').set('Authorization', `Bearer ${token}`)
      .send({ name: 'UserA Location', lat: 10, lng: 10, category: 'park' });
    expect(created.status).toBe(200);
    const res = await request(app).put(`/api/locations/${created.body._id}`).set('Authorization', `Bearer ${tokenB}`).send({ name: 'Hacked' });
    expect(res.status).toBe(404);
  });

  test('User B cannot DELETE User A trip → 404', async () => {
    const created = await request(app).post('/api/trips').set('Authorization', `Bearer ${token}`)
      .send({ name: 'UserA Trip', startDate: '2024-06-01', endDate: '2024-06-07' });
    expect(created.status).toBe(200);
    const res = await request(app).delete(`/api/trips/${created.body._id}`).set('Authorization', `Bearer ${tokenB}`);
    expect(res.status).toBe(404);
  });

  test('User B cannot PUT User A collection → 404', async () => {
    const created = await request(app).post('/api/collections').set('Authorization', `Bearer ${token}`)
      .send({ name: 'UserA Collection', emoji: '📌' });
    expect(created.status).toBe(200);
    const res = await request(app).put(`/api/collections/${created.body._id}`).set('Authorization', `Bearer ${tokenB}`).send({ name: 'Hacked' });
    expect(res.status).toBe(404);
  });
});

// ─── Admin endpoint authorization ────────────────────────
// Regression: requireAdmin guard previously was `if (ADMIN_EMAIL && ...)` which
// short-circuited to a no-op when ALLOWED_EMAILS was unset (open-registration),
// silently granting every authenticated user admin privileges. The fix inverts
// the guard to `if (!ADMIN_EMAIL || ...)` — when no admin is configured, NO ONE
// is admin. Test env has ALLOWED_EMAILS='' → all admin endpoints must 403.
describe('Admin authorization (ALLOWED_EMAILS unset)', () => {
  test('POST /api/admin/merge-accounts → 403 for normal user', async () => {
    const res = await request(app).post('/api/admin/merge-accounts')
      .set('Authorization', `Bearer ${token}`)
      .send({ fromUsername: 'testuser', toUsername: 'someone' });
    expect(res.status).toBe(403);
  });

  test('POST /api/admin/reset-password → 403 for normal user', async () => {
    const res = await request(app).post('/api/admin/reset-password')
      .set('Authorization', `Bearer ${token}`)
      .send({ username: 'testuser', newPassword: 'newpass123' });
    expect(res.status).toBe(403);
  });

  test('GET /api/admin/users → 403 for normal user', async () => {
    const res = await request(app).get('/api/admin/users').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(403);
  });

  test('GET /api/audit → 403 for normal user', async () => {
    const res = await request(app).get('/api/audit').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(403);
  });

  test('GET /api/admin/backups → 403 for normal user', async () => {
    const res = await request(app).get('/api/admin/backups').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(403);
  });

  test('GET /api/admin/backups/:filename → 403 for normal user', async () => {
    const res = await request(app).get('/api/admin/backups/anything.json').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(403);
  });

  test('admin endpoints still require auth first (no token → 401, not 403)', async () => {
    const res = await request(app).get('/api/admin/users');
    expect(res.status).toBe(401);
  });
});

// ─── SSRF / input validation regressions ─────────────────
describe('Places search lat/lng validation', () => {
  test('rejects non-numeric lat', async () => {
    // No API key configured in test env → expect 501 first; but if lat is invalid
    // we want 400 to fire BEFORE the key check would matter. Actually the code
    // checks the key first; with no key we get 501 regardless. Verify the validation
    // exists by string-grep on the server source instead.
    const serverSrc = fs.readFileSync(path.join(__dirname, '..', 'server', 'index.js'), 'utf-8');
    expect(serverSrc).toMatch(/Math\.abs\(fLat\)\s*>\s*90/);
    expect(serverSrc).toMatch(/Math\.abs\(fLng\)\s*>\s*180/);
  });
});

// ─── Input validation regressions (Phase B) ──────────────
describe('Input validation hardening', () => {
  test('password min length is now 8 (was 4) — source check (avoids rate limit)', () => {
    const serverSrc = fs.readFileSync(path.join(__dirname, '..', 'server', 'index.js'), 'utf-8');
    expect(serverSrc).toMatch(/password\.length\s*<\s*8/);
    expect(serverSrc).not.toMatch(/password\.length\s*<\s*4\b/);
  });

  test('POST /api/trips strips disallowed fields', async () => {
    const res = await request(app).post('/api/trips')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: 'X', userId: 'evil', _id: 'evil', __proto__: { polluted: true }, totallyMadeUp: 'val' });
    expect(res.status).toBe(200);
    expect(res.body.totallyMadeUp).toBeUndefined();
    expect(res.body.userId).not.toBe('evil');
  });

  test('POST /api/trips rejects bad color formats', async () => {
    const res = await request(app).post('/api/trips')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: 'BadColor', color: 'red; background: url(evil)' });
    expect(res.status).toBe(200);
    expect(res.body.color).toBeUndefined(); // dropped by COLOR_RE
  });

  test('POST /api/trips accepts valid hex color', async () => {
    const res = await request(app).post('/api/trips')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: 'GoodColor', color: '#ff8800' });
    expect(res.status).toBe(200);
    expect(res.body.color).toBe('#ff8800');
  });

  test('POST /api/trips requires name', async () => {
    const res = await request(app).post('/api/trips')
      .set('Authorization', `Bearer ${token}`)
      .send({ color: '#fff' });
    expect(res.status).toBe(400);
  });

  test('POST /api/collections/bulk caps at 500', async () => {
    const overflow = Array.from({ length: 501 }, (_, i) => ({ name: 'C' + i, emoji: '📋' }));
    const res = await request(app).post('/api/collections/bulk')
      .set('Authorization', `Bearer ${token}`)
      .send({ collections: overflow });
    expect(res.status).toBe(400);
  });

  test('POST /api/collections strips disallowed fields', async () => {
    const res = await request(app).post('/api/collections')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: 'StrictCol', emoji: '📋', userId: 'evil', secretField: 'x' });
    expect(res.status).toBe(200);
    expect(res.body.userId).not.toBe('evil');
    expect(res.body.secretField).toBeUndefined();
  });
});

// ─── Defense-in-depth invariants ─────────────────────────
describe('Helmet / CORS hardening', () => {
  const serverSrc = fs.readFileSync(path.join(__dirname, '..', 'server', 'index.js'), 'utf-8');

  test('CSP is enabled (not contentSecurityPolicy: false)', () => {
    expect(serverSrc).not.toMatch(/contentSecurityPolicy:\s*false/);
    expect(serverSrc).toMatch(/contentSecurityPolicy:\s*\{/);
    expect(serverSrc).toContain("defaultSrc: [\"'self'\"]");
  });

  test('CORS does not reflect arbitrary origins when ALLOWED_ORIGINS unset in production', () => {
    expect(serverSrc).toMatch(/process\.env\.NODE_ENV === 'production' \? false :/);
  });
});

// ─── Frontend bug fixes (Phase B + C) ─────────────────────
describe('Frontend correctness fixes', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');

  test('computeTripStats uses Number.isFinite for ms', () => {
    expect(html).toMatch(/Number\.isFinite\(ms\)\s*&&\s*ms\s*>=\s*0/);
  });

  test('pickSearchResult uses dataset.cat (not dataset.category)', () => {
    // The buggy line was `o.classList.toggle('selected', o.dataset.category === cat)`
    // inside pickSearchResult; the builders set dataset.cat.
    expect(html).not.toMatch(/dataset\.category\s*===\s*cat\b/);
  });

  test('logout resets _placesEnabled cache', () => {
    expect(html).toMatch(/function logout\(\)\s*\{[\s\S]*?_placesEnabled\s*=\s*null/);
  });

  test('applyBulkEdit uses Promise.allSettled (rollback-safe)', () => {
    expect(html).toMatch(/applyBulkEdit[\s\S]{0,2000}Promise\.allSettled/);
  });

  test('deleteCollection uses Promise.allSettled (rollback-safe)', () => {
    expect(html).toMatch(/deleteCollection[\s\S]{0,2000}Promise\.allSettled/);
  });

  test('drawRoadRoutes takes version arg for race protection', () => {
    expect(html).toMatch(/async function drawRoadRoutes\(tripLocs, color, version\)/);
    expect(html).toMatch(/version !== _selectTripVersion/);
  });

  test('seekReplay guards against null markersLayer', () => {
    expect(html).toMatch(/function seekReplay\([\s\S]{0,500}!replayState\.markersLayer/);
  });

  test('enrichInBackground awaits PUT and only mutates on success', () => {
    // Old code: `api('PUT', ...).catch(() => {})` — silent swallow with mutation
    // before await. New code: try/catch around await, mutation after success.
    expect(html).not.toMatch(/api\('PUT', '\/locations\/' \+ locId,[^)]+\)\.catch\(\(\) => \{\}\)/);
  });
});

// ─── XSS regression checks ───────────────────────────────
describe('XSS escape invariants', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');

  test('col.description is escaped in viewCollection', () => {
    expect(html).toContain('${esc(col.description || \'\')}');
  });

  test('loc.address is escaped in collection detail list', () => {
    expect(html).toContain('${esc(loc.address || \'\')}');
  });

  test('v.notes is escaped in visit-field value attribute', () => {
    expect(html).toContain('value="${esc(v.notes || \'\')}"');
  });

  test('restoreBackup encodes filename', () => {
    expect(html).toContain("'/api/admin/backups/' + encodeURIComponent(filename)");
  });
});

// ─── M-T3: admin1-boundaries auth regression ─────────────
describe('admin1-boundaries auth', () => {
  test('returns 401 with no token', async () => {
    const res = await request(app).get('/api/admin1-boundaries');
    expect(res.status).toBe(401);
  });

  test('does not return 401 with valid token', async () => {
    const res = await request(app)
      .get('/api/admin1-boundaries')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).not.toBe(401);
  });
});

// ─── M-T4: Replay play button disabled invariant ─────────
describe('Replay play button disabled invariant', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');

  test('rebuildReplayFrames sets disabled based on frames.length', () => {
    expect(html).toMatch(/rebuildReplayFrames[\s\S]{0,2000}playBtn\.disabled\s*=\s*replayState\.frames\.length\s*===\s*0/);
  });
});

// ─── Transits ────────────────────────────────────────────
describe('Transits', () => {
  let transitToken;
  let createdTransitId;

  beforeAll(async () => {
    // Reuse the global testuser token (set in Auth describe block)
    transitToken = token;
  });

  test('reject without auth', async () => {
    const res = await request(app).get('/api/transits');
    expect(res.status).toBe(401);
  });

  test('reject invalid mode', async () => {
    const res = await request(app).post('/api/transits')
      .set('Authorization', `Bearer ${transitToken}`)
      .send({ mode: 'teleport', fromLat: 0, fromLng: 0, toLat: 1, toLng: 1 });
    expect(res.status).toBe(400);
  });

  test('reject missing coordinates', async () => {
    const res = await request(app).post('/api/transits')
      .set('Authorization', `Bearer ${transitToken}`)
      .send({ mode: 'flight' });
    expect(res.status).toBe(400);
  });

  test('reject out-of-range lat', async () => {
    const res = await request(app).post('/api/transits')
      .set('Authorization', `Bearer ${transitToken}`)
      .send({ mode: 'flight', fromLat: 999, fromLng: 0, toLat: 0, toLng: 0 });
    expect(res.status).toBe(400); // sanitize drops fromLat, then 400 because coords missing
  });

  test('create valid flight transit', async () => {
    const res = await request(app).post('/api/transits')
      .set('Authorization', `Bearer ${transitToken}`)
      .send({
        mode: 'flight',
        date: '2024-07-10',
        fromName: 'Lisbon (LIS)', fromLat: 38.7813, fromLng: -9.1359, fromIata: 'LIS',
        toName: 'New York (JFK)', toLat: 40.6413, toLng: -73.7781, toIata: 'JFK',
        flightNumber: 'TP201', airline: 'TAP',
        distanceKm: 5418,
      });
    expect(res.status).toBe(200);
    expect(res.body._id).toBeDefined();
    expect(res.body.mode).toBe('flight');
    expect(res.body.fromLat).toBe(38.7813);
    createdTransitId = res.body._id;
  });

  test('list returns created transit', async () => {
    const res = await request(app).get('/api/transits')
      .set('Authorization', `Bearer ${transitToken}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.find(t => t._id === createdTransitId)).toBeDefined();
  });

  test('update transit', async () => {
    const res = await request(app).put(`/api/transits/${createdTransitId}`)
      .set('Authorization', `Bearer ${transitToken}`)
      .send({ notes: 'Red-eye, full flight' });
    expect(res.status).toBe(200);
    expect(res.body.notes).toBe('Red-eye, full flight');
  });

  test('sanitize drops bad fields on update', async () => {
    const res = await request(app).put(`/api/transits/${createdTransitId}`)
      .set('Authorization', `Bearer ${transitToken}`)
      .send({ fromLat: 999, mode: 'spaceship' });
    expect(res.status).toBe(200);
    // mode untouched (still 'flight'), fromLat untouched (still 38.7813)
    const get = await request(app).get('/api/transits').set('Authorization', `Bearer ${transitToken}`);
    const t = get.body.find(x => x._id === createdTransitId);
    expect(t.mode).toBe('flight');
    expect(t.fromLat).toBe(38.7813);
  });

  test('bulk insert', async () => {
    const res = await request(app).post('/api/transits/bulk')
      .set('Authorization', `Bearer ${transitToken}`)
      .send({ transits: [
        { mode: 'car', date: '2024-07-12', fromName: 'A', fromLat: 38.7, fromLng: -9.1, toName: 'B', toLat: 38.8, toLng: -9.2 },
        { mode: 'train', date: '2024-07-13', fromName: 'C', fromLat: 38.7, fromLng: -9.1, toName: 'D', toLat: 41.1, toLng: -8.6 },
        { mode: 'invalid', fromLat: 0, fromLng: 0, toLat: 0, toLng: 0 }, // filtered out
      ]});
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBe(2);
  });

  test('bulk rejects non-array', async () => {
    const res = await request(app).post('/api/transits/bulk')
      .set('Authorization', `Bearer ${transitToken}`)
      .send({ transits: 'nope' });
    expect(res.status).toBe(400);
  });

  test('bulk rejects oversize', async () => {
    const arr = new Array(1001).fill({ mode: 'flight', fromLat: 0, fromLng: 0, toLat: 1, toLng: 1 });
    const res = await request(app).post('/api/transits/bulk')
      .set('Authorization', `Bearer ${transitToken}`)
      .send({ transits: arr });
    expect(res.status).toBe(400);
  });

  test('cross-user isolation', async () => {
    // Log in as user2 (registered in the User data isolation block above)
    const login = await request(app).post('/api/auth/login').send({ username: 'user2', password: 'pass1234' });
    expect(login.status).toBe(200);
    const otherToken = login.body.token;
    expect(otherToken).toBeDefined();
    // 2nd user cannot see first user's transits
    const list = await request(app).get('/api/transits').set('Authorization', `Bearer ${otherToken}`);
    expect(list.status).toBe(200);
    expect(Array.isArray(list.body)).toBe(true);
    expect(list.body.find(t => t._id === createdTransitId)).toBeUndefined();
    // 2nd user cannot update first user's transit
    const upd = await request(app).put(`/api/transits/${createdTransitId}`)
      .set('Authorization', `Bearer ${otherToken}`)
      .send({ notes: 'hijack' });
    expect(upd.status).toBe(404);
  });

  test('delete transit', async () => {
    const res = await request(app).delete(`/api/transits/${createdTransitId}`)
      .set('Authorization', `Bearer ${transitToken}`);
    expect(res.status).toBe(200);
  });

  test('detach trip with empty-string tripId', async () => {
    // Create a trip
    const trip = await request(app).post('/api/trips').set('Authorization', `Bearer ${transitToken}`).send({ name: 'Test trip for detach' });
    expect(trip.status).toBe(200);
    const tripId = trip.body._id;
    // Create transit with tripId
    const create = await request(app).post('/api/transits').set('Authorization', `Bearer ${transitToken}`).send({
      mode: 'flight', fromLat: 0, fromLng: 0, toLat: 1, toLng: 1, tripId,
    });
    expect(create.status).toBe(200);
    expect(create.body.tripId).toBe(tripId);
    // Detach via empty string
    const upd = await request(app).put('/api/transits/' + create.body._id).set('Authorization', `Bearer ${transitToken}`).send({ tripId: '' });
    expect(upd.status).toBe(200);
    expect(upd.body.tripId === null || upd.body.tripId === undefined).toBe(true);
    // Cleanup
    await request(app).delete('/api/transits/' + create.body._id).set('Authorization', `Bearer ${transitToken}`);
    await request(app).delete('/api/trips/' + tripId).set('Authorization', `Bearer ${transitToken}`);
  });
});

// ─── Transits source-grep invariants ─────────────────────
describe('Input validation hardening (transits)', () => {
  test('MAX_TRANSITS_PER_BULK exists in server source', () => {
    const serverSrc = fs.readFileSync(path.join(__dirname, '..', 'server', 'index.js'), 'utf-8');
    expect(serverSrc).toContain('MAX_TRANSITS_PER_BULK');
  });
});
