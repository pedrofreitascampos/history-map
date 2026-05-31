// Separate module instance — no ANTHROPIC_API_KEY env set, no per-user key.
// Tests the 501 and enabled:false paths.
const path = require('path');
const fs = require('fs');

const testDataDir = path.join(__dirname, '..', 'data-test-narrate-nokey');
if (!fs.existsSync(testDataDir)) fs.mkdirSync(testDataDir, { recursive: true });
process.env.DATA_DIR = testDataDir;
process.env.JWT_SECRET = 'narrate-nokey-test-secret';
process.env.ALLOWED_EMAILS = '';
// Intentionally NOT setting ANTHROPIC_API_KEY

const mockCreate = jest.fn();
jest.mock('@anthropic-ai/sdk', () => ({
  default: jest.fn().mockImplementation(() => ({
    messages: { create: mockCreate },
  })),
}));

const request = require('supertest');

// Use jest.isolateModules so this instance has no ANTHROPIC_API_KEY captured
let app, db;
beforeAll(async () => {
  jest.resetModules();
  app = require('../server/index');
  db = require('../server/db');
  await db.users.remove({}, { multi: true });
  await db.trips.remove({}, { multi: true });
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

let token;
beforeAll(async () => {
  const reg = await request(app)
    .post('/api/auth/register')
    .send({ username: 'nokey_final', password: 'nokey_pass_final' });
  token = reg.body.token;
});

describe('GET /api/trips/narrate-status', () => {
  test('returns enabled:false when no ANTHROPIC_API_KEY and no user key', async () => {
    const res = await request(app)
      .get('/api/trips/narrate-status')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.enabled).toBe(false);
  });
});

describe('POST /api/trips/narrate', () => {
  test('no key → 501, message mentions "not configured"', async () => {
    const res = await request(app)
      .post('/api/trips/narrate')
      .set('Authorization', `Bearer ${token}`)
      .send({ text: 'A week exploring Tokyo' });

    expect(res.status).toBe(501);
    expect(res.body.error).toMatch(/not configured/i);
    expect(mockCreate).not.toHaveBeenCalled();
  });
});
