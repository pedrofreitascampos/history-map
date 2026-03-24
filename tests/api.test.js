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

  test('create collection', async () => {
    const res = await request(app).post('/api/collections').set('Authorization', `Bearer ${token}`)
      .send({ name: 'UNESCO', emoji: '🏰', totalItems: 1199 });
    expect(res.status).toBe(200);
    colId = res.body._id;
  });

  test('list collections', async () => {
    const res = await request(app).get('/api/collections').set('Authorization', `Bearer ${token}`);
    expect(res.body).toHaveLength(1);
  });

  test('update collection', async () => {
    const res = await request(app).put(`/api/collections/${colId}`).set('Authorization', `Bearer ${token}`)
      .send({ totalItems: 1200 });
    expect(res.body.totalItems).toBe(1200);
  });

  test('delete collection', async () => {
    await request(app).delete(`/api/collections/${colId}`).set('Authorization', `Bearer ${token}`);
    const list = await request(app).get('/api/collections').set('Authorization', `Bearer ${token}`);
    expect(list.body).toHaveLength(0);
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
