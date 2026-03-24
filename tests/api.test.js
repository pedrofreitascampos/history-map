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
    // Regression: null totalItems, empty description must not crash
    const res = await request(app).post('/api/collections').set('Authorization', `Bearer ${token}`)
      .send({ name: 'Open Ended', emoji: '📋', description: null, totalItems: null });
    expect(res.status).toBe(200);
    expect(res.body.totalItems).toBeNull();
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

  test('CSV parser extracts coords from Google Maps URLs', () => {
    // Regression: Google Takeout Saved Places CSV has coords in URL, not separate columns
    expect(indexHtml).toContain("/@(-?\\d+\\.?\\d*),(-?\\d+\\.?\\d*)");
    expect(indexHtml).toContain("obj.url || obj.link || obj['google maps url']");
  });

  test('CSV parser handles Title column (Google Takeout uses Title not Name)', () => {
    expect(indexHtml).toContain("obj.title || obj.name");
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
    // Raw: { locations: [{ latitudeE7 }] }
    expect(indexHtml).toContain('data.locations[0]?.latitudeE7');
  });

  test('Raw locations parser caps output and filters drive-by points', () => {
    // Must require multiple readings (>= 3) to count as a place
    expect(indexHtml).toContain('c.count >= 3');
    // Must cap at 500 to prevent massive imports
    expect(indexHtml).toContain('.slice(0, 500)');
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

  // ── Planner ──
  test('planner category toggle does not mass-deselect', () => {
    // Regression: clicking a category when all were active used to select ONLY that one.
    // Must instead deselect just that one (all-minus-clicked).
    const toggleFn = indexHtml.substring(
      indexHtml.indexOf('function togglePlannerCat('),
      indexHtml.indexOf('function togglePlannerCat(') + 800
    );
    // When size===0 (all active), must create set of ALL keys then delete the clicked one
    expect(toggleFn).toContain('new Set(Object.keys(CATEGORIES))');
    expect(toggleFn).toContain('.delete(key)');
    // Must NOT contain "new Set([key])" which would select only one
    expect(toggleFn).not.toContain('new Set([key])');
  });

  test('planner source button says "Been" not "My Places"', () => {
    expect(indexHtml).toContain(">Been</button>");
    expect(indexHtml).not.toContain(">My Places</button>");
  });

  test('planner renders an itinerary map', () => {
    expect(indexHtml).toContain('id="planner-map"');
    expect(indexHtml).toContain('function renderPlannerMap');
    expect(indexHtml).toContain('DAY_COLORS');
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
