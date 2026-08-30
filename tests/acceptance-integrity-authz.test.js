// Behavioral acceptance tests: referential integrity + a systematic IDOR
// matrix + share-token lifecycle + admin authz. Real HTTP calls via
// supertest against the real Express app. No source-text regex pins.

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const testDataDir = path.join(__dirname, '..', 'data-test-acceptance-integrity');
if (!fs.existsSync(testDataDir)) fs.mkdirSync(testDataDir, { recursive: true });
process.env.DATA_DIR = testDataDir;
process.env.JWT_SECRET = 'acceptance-integrity-secret';
// First email is admin. All three must be present so registration succeeds
// (server enforces the allowlist when ALLOWED_EMAILS is non-empty).
process.env.ALLOWED_EMAILS = 'admin@accept.test,usera@accept.test,userb@accept.test';

const request = require('supertest');
const app = require('../server/index');
const db = require('../server/db');

const ADMIN = { username: 'admin@accept.test', password: 'adminpass123' };
const USER_A = { username: 'usera@accept.test', password: 'userapass123' };
const USER_B = { username: 'userb@accept.test', password: 'userbpass123' };

let adminToken, tokenA, tokenB;

beforeAll(async () => {
  await db.users.remove({}, { multi: true });
  await db.locations.remove({}, { multi: true });
  await db.trips.remove({}, { multi: true });
  await db.collections.remove({}, { multi: true });
  await db.transits.remove({}, { multi: true });
  await db.auditLog.remove({}, { multi: true });

  const rAdmin = await request(app).post('/api/auth/register').send(ADMIN);
  adminToken = rAdmin.body.token;
  const rA = await request(app).post('/api/auth/register').send(USER_A);
  tokenA = rA.body.token;
  const rB = await request(app).post('/api/auth/register').send(USER_B);
  tokenB = rB.body.token;
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

function as(token, req) { return req.set('Authorization', `Bearer ${token}`); }

async function createLocation(token, overrides = {}) {
  const res = await as(token, request(app).post('/api/locations')).send({ name: 'Loc', lat: 1, lng: 1, ...overrides });
  expect(res.status).toBe(200);
  return res.body;
}
async function createTrip(token, overrides = {}) {
  const res = await as(token, request(app).post('/api/trips')).send({ name: 'Trip', ...overrides });
  expect(res.status).toBe(200);
  return res.body;
}
async function createCollection(token, overrides = {}) {
  const res = await as(token, request(app).post('/api/collections')).send({ name: 'Col', ...overrides });
  expect(res.status).toBe(200);
  return res.body;
}
async function createTransit(token, overrides = {}) {
  const res = await as(token, request(app).post('/api/transits')).send({
    mode: 'flight', fromLat: 1, fromLng: 1, toLat: 2, toLng: 2, ...overrides,
  });
  expect(res.status).toBe(200);
  return res.body;
}

// ─── IDOR matrix — data-driven, one entry per per-id route ──────────────
describe('IDOR matrix: user B must never read/write/delete user A\'s resources', () => {
  const cases = [
    {
      label: 'PUT /api/locations/:id',
      create: () => createLocation(tokenA, { name: 'A-loc' }),
      method: 'put', path: (id) => `/api/locations/${id}`, body: { name: 'HACKED' },
      fetchList: () => as(tokenA, request(app).get('/api/locations')).then(r => r.body),
      field: 'name', origValue: 'A-loc',
    },
    {
      label: 'DELETE /api/locations/:id',
      create: () => createLocation(tokenA, { name: 'A-loc-del' }),
      method: 'delete', path: (id) => `/api/locations/${id}`, body: {},
      fetchList: () => as(tokenA, request(app).get('/api/locations')).then(r => r.body),
      field: 'name', origValue: 'A-loc-del',
    },
    {
      label: 'PUT /api/trips/:id',
      create: () => createTrip(tokenA, { name: 'A-trip' }),
      method: 'put', path: (id) => `/api/trips/${id}`, body: { name: 'HACKED' },
      fetchList: () => as(tokenA, request(app).get('/api/trips')).then(r => r.body),
      field: 'name', origValue: 'A-trip',
    },
    {
      label: 'DELETE /api/trips/:id',
      create: () => createTrip(tokenA, { name: 'A-trip-del' }),
      method: 'delete', path: (id) => `/api/trips/${id}`, body: {},
      fetchList: () => as(tokenA, request(app).get('/api/trips')).then(r => r.body),
      field: 'name', origValue: 'A-trip-del',
    },
    {
      label: 'POST /api/trips/:id/share',
      create: () => createTrip(tokenA, { name: 'A-trip-share' }),
      method: 'post', path: (id) => `/api/trips/${id}/share`, body: {},
      fetchList: () => as(tokenA, request(app).get('/api/trips')).then(r => r.body),
      field: 'shareToken', origValue: undefined, // must remain un-shared
    },
    {
      label: 'PUT /api/collections/:id',
      create: () => createCollection(tokenA, { name: 'A-col' }),
      method: 'put', path: (id) => `/api/collections/${id}`, body: { name: 'HACKED' },
      fetchList: () => as(tokenA, request(app).get('/api/collections')).then(r => r.body),
      field: 'name', origValue: 'A-col',
    },
    {
      label: 'DELETE /api/collections/:id',
      create: () => createCollection(tokenA, { name: 'A-col-del' }),
      method: 'delete', path: (id) => `/api/collections/${id}`, body: {},
      fetchList: () => as(tokenA, request(app).get('/api/collections')).then(r => r.body),
      field: 'name', origValue: 'A-col-del',
    },
    {
      label: 'PUT /api/transits/:id',
      create: () => createTransit(tokenA, { notes: 'A-transit' }),
      method: 'put', path: (id) => `/api/transits/${id}`, body: { notes: 'HACKED' },
      fetchList: () => as(tokenA, request(app).get('/api/transits')).then(r => r.body),
      field: 'notes', origValue: 'A-transit',
    },
    {
      label: 'DELETE /api/transits/:id',
      create: () => createTransit(tokenA, { notes: 'A-transit-del' }),
      method: 'delete', path: (id) => `/api/transits/${id}`, body: {},
      fetchList: () => as(tokenA, request(app).get('/api/transits')).then(r => r.body),
      field: 'notes', origValue: 'A-transit-del',
    },
  ];

  test.each(cases)('$label -> 404 for user B, A\'s record unaffected', async (c) => {
    const orig = await c.create();
    const res = await as(tokenB, request(app)[c.method](c.path(orig._id))).send(c.body);
    expect(res.status).toBe(404);

    const list = await c.fetchList();
    const found = list.find(x => x._id === orig._id);

    if (c.method === 'delete') {
      // A's record must still exist, untouched.
      expect(found).toBeDefined();
      expect(found[c.field]).toBe(c.origValue);
    } else {
      expect(found).toBeDefined();
      expect(found[c.field]).toBe(c.origValue);
    }
  });

  test('DELETE /api/trips/:id/share -> 404 for user B, share stays active for A', async () => {
    const trip = await createTrip(tokenA, { name: 'A-trip-unshare' });
    const shareRes = await as(tokenA, request(app).post(`/api/trips/${trip._id}/share`));
    expect(shareRes.status).toBe(200);
    const shareToken = shareRes.body.shareToken;

    const res = await as(tokenB, request(app).delete(`/api/trips/${trip._id}/share`));
    expect(res.status).toBe(404);

    const check = await request(app).get(`/api/share/${shareToken}`);
    expect(check.status).toBe(200); // still shared — B's attempt did not revoke it
  });
});

// GET /api/locations, /api/trips, /api/collections, /api/transits scope by
// userId server-side (there is no single-item GET route for locations), so
// list scoping is the relevant cross-user leak surface for reads.
describe('List endpoints never leak another user\'s rows', () => {
  test('user B\'s lists never contain user A\'s records', async () => {
    await createLocation(tokenA, { name: 'A-only-loc' });
    await createTrip(tokenA, { name: 'A-only-trip' });
    await createCollection(tokenA, { name: 'A-only-col' });
    await createTransit(tokenA, { notes: 'A-only-transit' });

    const [locs, trips, cols, transits] = await Promise.all([
      as(tokenB, request(app).get('/api/locations')).then(r => r.body),
      as(tokenB, request(app).get('/api/trips')).then(r => r.body),
      as(tokenB, request(app).get('/api/collections')).then(r => r.body),
      as(tokenB, request(app).get('/api/transits')).then(r => r.body),
    ]);
    expect(locs.some(l => l.name === 'A-only-loc')).toBe(false);
    expect(trips.some(t => t.name === 'A-only-trip')).toBe(false);
    expect(cols.some(c => c.name === 'A-only-col')).toBe(false);
    expect(transits.some(t => t.notes === 'A-only-transit')).toBe(false);
  });
});

// ─── Referential integrity ────────────────────────────────────────────────
describe('Trip delete cascade unlinks locations AND transits', () => {
  test('DELETE trip clears tripId on both a stop location and a stop transit', async () => {
    const trip = await createTrip(tokenA, { name: 'CascadeTrip' });
    const loc = await createLocation(tokenA, { name: 'CascadeLoc', tripId: trip._id });
    const transit = await createTransit(tokenA, { tripId: trip._id, notes: 'CascadeTransit' });

    const del = await as(tokenA, request(app).delete(`/api/trips/${trip._id}`));
    expect(del.status).toBe(200);
    expect(del.body.unlinkedLocs).toBe(1);
    expect(del.body.unlinkedTransits).toBe(1);

    const locs = await as(tokenA, request(app).get('/api/locations')).then(r => r.body);
    const gotLoc = locs.find(l => l._id === loc._id);
    expect(gotLoc.tripId).toBeNull();

    const transits = await as(tokenA, request(app).get('/api/transits')).then(r => r.body);
    const gotTransit = transits.find(t => t._id === transit._id);
    expect(gotTransit.tripId).toBeNull();
  });
});

describe('Deleting a trip-stop location does not break trip or location listing', () => {
  test('trip still loads (200) and GET /api/locations does not 500 after deleting a stop', async () => {
    const trip = await createTrip(tokenA, { name: 'StopDeleteTrip' });
    const loc = await createLocation(tokenA, { name: 'StopToDelete', tripId: trip._id });

    const del = await as(tokenA, request(app).delete(`/api/locations/${loc._id}`));
    expect(del.status).toBe(200);

    const tripsRes = await as(tokenA, request(app).get('/api/trips'));
    expect(tripsRes.status).toBe(200);
    expect(tripsRes.body.some(t => t._id === trip._id)).toBe(true);

    const locsRes = await as(tokenA, request(app).get('/api/locations'));
    expect(locsRes.status).toBe(200);
    expect(locsRes.body.some(l => l._id === loc._id)).toBe(false);
  });
});

// ─── Share-token lifecycle ────────────────────────────────────────────────
describe('Share-token lifecycle (full behavioral)', () => {
  test('shared trip exposes safe fields only, never private data; unshare kills the token', async () => {
    const trip = await createTrip(tokenA, { name: 'ShareTrip' });
    const stop = await createLocation(tokenA, {
      name: 'ShareStop', tripId: trip._id, tripOrder: 0,
      notes: 'PRIVATE', myRating: 5,
    });

    const shareRes = await as(tokenA, request(app).post(`/api/trips/${trip._id}/share`));
    expect(shareRes.status).toBe(200);
    const shareToken = shareRes.body.shareToken;
    expect(shareToken).toMatch(/^[0-9a-f]{40}$/);

    // No auth header at all — this must be publicly reachable.
    const pub = await request(app).get(`/api/share/${shareToken}`);
    expect(pub.status).toBe(200);
    const raw = JSON.stringify(pub.body);
    expect(raw).not.toMatch(/PRIVATE/);
    expect(raw).not.toMatch(/userId/i);
    expect(raw).not.toMatch(/myRating/i);
    expect(raw).not.toMatch(/shareToken/i);
    // Sanity: the stop itself IS present (safe fields only).
    expect(pub.body.locations.some(l => l._id === stop._id)).toBe(true);

    const unshare = await as(tokenA, request(app).delete(`/api/trips/${trip._id}/share`));
    expect(unshare.status).toBe(200);

    const after = await request(app).get(`/api/share/${shareToken}`);
    expect(after.status).toBe(404);
  });

  test('malformed / nonexistent tokens -> 404', async () => {
    const tooShort = await request(app).get('/api/share/abc');
    expect(tooShort.status).toBe(404);

    const nonHex = await request(app).get(`/api/share/${'z'.repeat(40)}`);
    expect(nonHex.status).toBe(404);

    const wellFormedButUnknown = await request(app).get(`/api/share/${crypto.randomBytes(20).toString('hex')}`);
    expect(wellFormedButUnknown.status).toBe(404);
  });

  test('a share link for trip 1 excludes locations belonging to trip 2 of the same user', async () => {
    const trip1 = await createTrip(tokenA, { name: 'Trip1Isolated' });
    const trip2 = await createTrip(tokenA, { name: 'Trip2Isolated' });
    const loc1 = await createLocation(tokenA, { name: 'Trip1Stop', tripId: trip1._id });
    const loc2 = await createLocation(tokenA, { name: 'Trip2Stop', tripId: trip2._id });

    const shareRes = await as(tokenA, request(app).post(`/api/trips/${trip1._id}/share`));
    const pub = await request(app).get(`/api/share/${shareRes.body.shareToken}`);
    expect(pub.status).toBe(200);
    const names = pub.body.locations.map(l => l.name);
    expect(names).toContain('Trip1Stop');
    expect(names).not.toContain('Trip2Stop');
    void loc1; void loc2;
  });
});

// ─── Admin authorization ───────────────────────────────────────────────────
describe('Admin routes reject non-admin users', () => {
  test('GET /api/admin/users -> 403 for non-admin', async () => {
    const res = await as(tokenB, request(app).get('/api/admin/users'));
    expect(res.status).toBe(403);
  });
  test('POST /api/admin/reset-password -> 403 for non-admin', async () => {
    const res = await as(tokenB, request(app).post('/api/admin/reset-password')).send({ username: USER_A.username, newPassword: 'whatever123' });
    expect(res.status).toBe(403);
  });
  test('POST /api/admin/merge-accounts -> 403 for non-admin', async () => {
    const res = await as(tokenB, request(app).post('/api/admin/merge-accounts')).send({ fromUsername: USER_A.username, toUsername: USER_B.username });
    expect(res.status).toBe(403);
  });
  test('GET /api/admin/backups -> 403 for non-admin', async () => {
    const res = await as(tokenB, request(app).get('/api/admin/backups'));
    expect(res.status).toBe(403);
  });
});

describe('Admin reset-password enforces the 8-char floor', () => {
  test('1-char newPassword -> 400 even for a real admin', async () => {
    const res = await as(adminToken, request(app).post('/api/admin/reset-password')).send({ username: USER_B.username, newPassword: 'x' });
    expect(res.status).toBe(400);
  });
});

// ─── Backup path traversal ─────────────────────────────────────────────────
describe('Backup download path traversal is defended', () => {
  test('GET /api/my-backup/../../etc/passwd never returns a real file leak', async () => {
    const res = await as(tokenA, request(app).get('/api/my-backup/../../etc/passwd'));
    // Whatever Express/path-to-regexp does with the traversal segments, the
    // response must never be a 200 file download containing passwd-like content.
    if (res.status === 200) {
      expect(res.text).not.toMatch(/root:.*:0:0:/);
      expect(res.headers['content-disposition']).toBeUndefined();
    } else {
      expect([403, 404]).toContain(res.status);
    }
  });

  test('URL-encoded traversal variant never returns a real file leak', async () => {
    const res = await as(tokenA, request(app).get('/api/my-backup/' + encodeURIComponent('../../etc/passwd')));
    if (res.status === 200) {
      expect(res.text).not.toMatch(/root:.*:0:0:/);
    } else {
      expect([403, 404]).toContain(res.status);
    }
  });

  test('double-encoded traversal variant never returns a real file leak', async () => {
    const res = await as(tokenA, request(app).get('/api/my-backup/..%2f..%2fetc%2fpasswd'));
    if (res.status === 200) {
      expect(res.text).not.toMatch(/root:.*:0:0:/);
    } else {
      expect([403, 404]).toContain(res.status);
    }
  });
});
