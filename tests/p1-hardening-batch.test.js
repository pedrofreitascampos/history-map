// S2 P1 hardening batch (2026-06-04). Pins five fixes shipped as a single
// security-finishing-touches sweep:
//   1. Per-endpoint rate limits on /api/trips/narrate(+status) and
//      /api/places/discover so a runaway LLM/Places caller can't burn through
//      cost behind the permissive 200/min global limiter.
//   2. CSP connectSrc now includes https://photon.komoot.io — the client has
//      6 fetch sites against it (geocoding + Discover-via-Photon flow).
//   3. render.yaml declares ANTHROPIC_API_KEY (sync:false) so the env-key
//      fallback path actually loads on Render deploys.
//   4. @anthropic-ai/sdk pinned exact 0.30.1 (no caret on a 0.x release).
//   5. sanitizeLocationUpdate strips <script>/<iframe>/javascript: from notes
//      and caps it at 10 000 chars — defense-in-depth for the LLM web-import
//      snippet → notes flow.

const path = require('path');
const fs = require('fs');

const testDataDir = path.join(__dirname, '..', 'data-test-p1-hardening');
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

describe('S2 P1 hardening batch', () => {
  // ── 4. SDK exact-pin ──
  test('@anthropic-ai/sdk is exact-pinned (no caret on 0.x)', () => {
    const pkg = require('../package.json');
    expect(pkg.dependencies['@anthropic-ai/sdk']).toBe('0.30.1');
    expect(pkg.dependencies['@anthropic-ai/sdk']).not.toMatch(/^[\^~]/);
  });

  // ── 3. render.yaml ANTHROPIC_API_KEY ──
  test('render.yaml declares ANTHROPIC_API_KEY env var (sync:false)', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'render.yaml'), 'utf-8');
    expect(src).toMatch(/^\s*-\s*key:\s*ANTHROPIC_API_KEY\s*$/m);
    // The sync:false belt — runtime secret, never auto-synced from the
    // dashboard (matches every other secret in the file).
    const block = src.split(/\n/).reduce((acc, line, i, lines) => {
      if (/^\s*-\s*key:\s*ANTHROPIC_API_KEY\s*$/.test(line)) acc.push(lines[i + 1] || '');
      return acc;
    }, []);
    expect(block.length).toBeGreaterThan(0);
    expect(block[0]).toMatch(/sync:\s*false/);
  });

  // ── 2. CSP photon.komoot.io ──
  test('CSP connectSrc includes photon.komoot.io', async () => {
    const res = await request(app).get('/');
    expect(res.status).toBe(200);
    const csp = res.headers['content-security-policy'] || '';
    expect(csp).toContain('photon.komoot.io');
    // Sanity: still inside connect-src, not e.g. img-src.
    const connectDirective = csp.split(';').find(d => d.trim().startsWith('connect-src')) || '';
    expect(connectDirective).toContain('photon.komoot.io');
  });

  // ── 1. Per-endpoint rate limits ──
  test('server/index.js mounts a dedicated rate limit on /api/trips/narrate', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'server', 'index.js'), 'utf-8');
    // app.use([...,'/api/trips/narrate',...], rateLimit(...)) — single string
    // OR array form. Match both shapes.
    const narrateRateLimit = /app\.use\(\s*(?:'\/api\/trips\/narrate'|\[[^\]]*'\/api\/trips\/narrate'[^\]]*\])\s*,\s*rateLimit\(/;
    expect(src).toMatch(narrateRateLimit);
    // narrate-status shares the same limiter (path covered in the array form).
    expect(src).toMatch(/\/api\/trips\/narrate-status/);
  });

  test('server/index.js mounts a dedicated rate limit on /api/places/discover', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'server', 'index.js'), 'utf-8');
    expect(src).toMatch(/app\.use\(\s*'\/api\/places\/discover'\s*,\s*rateLimit\(/);
  });

  test('per-endpoint limiters use the isTest bypass (max 10000) so the suite stays green', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'server', 'index.js'), 'utf-8');
    // Both new limiters reference isTest ? 10000 : N in their max arg.
    // Grab the two app.use lines and assert isTest is in scope.
    const narrateLine = src.split('\n').find(l => l.includes("'/api/trips/narrate-status'") && l.includes('rateLimit'));
    const discoverLine = src.split('\n').find(l => l.includes("'/api/places/discover'") && l.includes('rateLimit'));
    expect(narrateLine).toBeTruthy();
    expect(discoverLine).toBeTruthy();
    expect(narrateLine).toMatch(/isTest\s*\?\s*10000/);
    expect(discoverLine).toMatch(/isTest\s*\?\s*10000/);
  });

  test('narrate rate-limit is bypassed under NODE_ENV=test (regression: keeps suite stable)', async () => {
    // Fire 15 GETs at narrate-status — 5 above the 10/min production cap.
    // Under isTest=true the cap is 10 000, so none should 429.
    await db.users.remove({}, { multi: true });
    const reg = await request(app)
      .post('/api/auth/register')
      .send({ username: 'narratecap', password: 'narratepass123' });
    expect(reg.status).toBe(200);
    const token = reg.body.token;
    for (let i = 0; i < 15; i++) {
      const r = await request(app)
        .get('/api/trips/narrate-status')
        .set('Authorization', `Bearer ${token}`);
      expect(r.status).not.toBe(429);
    }
  });

  // ── 5. sanitizeLocationUpdate notes ──
  describe('sanitizeLocationUpdate — notes defense-in-depth', () => {
    let token;

    beforeAll(async () => {
      await db.users.remove({}, { multi: true });
      await db.locations.remove({}, { multi: true });
      const reg = await request(app)
        .post('/api/auth/register')
        .send({ username: 'notesguard', password: 'notespass123' });
      expect(reg.status).toBe(200);
      token = reg.body.token;
    });

    async function postLoc(notes) {
      const r = await request(app)
        .post('/api/locations')
        .set('Authorization', `Bearer ${token}`)
        .send({ name: 'Test', lat: 0, lng: 0, status: 'bucket', notes });
      expect(r.status).toBe(200);
      return r.body;
    }

    test('strips <script>…</script> blocks (lowercase)', async () => {
      const loc = await postLoc('Hello <script>alert(1)</script> world');
      expect(loc.notes).not.toMatch(/<script/i);
      expect(loc.notes).not.toMatch(/alert\(1\)/);
      expect(loc.notes).toContain('Hello');
      expect(loc.notes).toContain('world');
    });

    test('strips <SCRIPT>…</SCRIPT> blocks (uppercase / case-insensitive)', async () => {
      const loc = await postLoc('A<SCRIPT SRC="x.js"></SCRIPT>B');
      expect(loc.notes).not.toMatch(/<script/i);
      expect(loc.notes).toBe('AB');
    });

    test('strips <iframe>…</iframe> blocks', async () => {
      const loc = await postLoc('safe <iframe src="evil"></iframe> tail');
      expect(loc.notes).not.toMatch(/<iframe/i);
      expect(loc.notes).toContain('safe');
      expect(loc.notes).toContain('tail');
    });

    test('strips unclosed <script> opening tag (defensive)', async () => {
      const loc = await postLoc('orphan <script src="evil.js"> tail');
      expect(loc.notes).not.toMatch(/<script/i);
    });

    test('neutralises javascript: URI scheme', async () => {
      const loc = await postLoc('click javascript:alert(1) here');
      expect(loc.notes).not.toMatch(/javascript:/i);
      expect(loc.notes).toContain('click');
      expect(loc.notes).toContain('alert(1)');
    });

    test('neutralises vbscript: URI scheme', async () => {
      const loc = await postLoc('VBSCRIPT:msgbox 1 — historical IE vector');
      expect(loc.notes).not.toMatch(/vbscript:/i);
    });

    test('caps notes at 10 000 chars', async () => {
      const loc = await postLoc('a'.repeat(20000));
      expect(loc.notes.length).toBe(10000);
    });

    test('drops notes entirely when type is not string', async () => {
      // Non-string notes goes through pickLocationFields (allowed) but
      // sanitizeLocationUpdate must delete it before write.
      const r = await request(app)
        .post('/api/locations')
        .set('Authorization', `Bearer ${token}`)
        .send({ name: 'Typed', lat: 1, lng: 1, status: 'bucket', notes: { html: '<script>x</script>' } });
      expect(r.status).toBe(200);
      // Stored loc has no notes field (or undefined).
      expect(r.body.notes === undefined || r.body.notes === null || r.body.notes === '').toBe(true);
    });

    test('preserves legitimate prose unchanged', async () => {
      const prose = 'Recommended by Pierre — the soufflé is supposedly life-changing. Reservation needed 2+ weeks ahead.';
      const loc = await postLoc(prose);
      expect(loc.notes).toBe(prose);
    });
  });
});
