'use strict';

const path = require('path');
const fs = require('fs');

const testDataDir = path.join(__dirname, '..', 'data-test-import-website');
if (!fs.existsSync(testDataDir)) fs.mkdirSync(testDataDir, { recursive: true });
process.env.DATA_DIR = testDataDir;
process.env.JWT_SECRET = 'import-website-test-secret';
process.env.ALLOWED_EMAILS = '';

const request = require('supertest');
const app = require('../server/index');
const db = require('../server/db');

const USER = { username: 'importwebuser', password: 'importwebpass123' };
let token;

beforeAll(async () => {
  await db.users.remove({}, { multi: true });
  await db.auditLog.remove({}, { multi: true });
  const reg = await request(app).post('/api/auth/register').send(USER);
  token = reg.body.token;
});

afterAll(() => {
  const wipe = (dir) => {
    if (!fs.existsSync(dir)) return;
    for (const f of fs.readdirSync(dir)) {
      const p = path.join(dir, f);
      if (fs.statSync(p).isDirectory()) { wipe(p); fs.rmdirSync(p); }
      else fs.unlinkSync(p);
    }
  };
  wipe(testDataDir);
  if (fs.existsSync(testDataDir)) fs.rmdirSync(testDataDir);
});

afterEach(() => {
  jest.restoreAllMocks();
});

function mockFetch(html, { status = 200, ok = true } = {}) {
  jest.spyOn(global, 'fetch').mockResolvedValue({
    ok,
    status,
    arrayBuffer: async () => Buffer.from(html, 'utf-8'),
  });
}

// ── Auth ──────────────────────────────────────────────────────────────────────

describe('POST /api/import/website — auth', () => {
  test('unauthenticated request returns 401', async () => {
    const res = await request(app).post('/api/import/website').send({ url: 'https://www.timeout.com/lisbon/restaurants/best' });
    expect(res.status).toBe(401);
  });
});

// ── URL validation ────────────────────────────────────────────────────────────

describe('POST /api/import/website — URL validation', () => {
  test('missing url returns 400 invalid_url', async () => {
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({});
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_url');
  });

  test('non-string url returns 400 invalid_url', async () => {
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 12345 });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_url');
  });

  test('ftp:// url returns 400 invalid_url', async () => {
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'ftp://www.timeout.com/lisbon/restaurants' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_url');
  });

  test('javascript: url returns 400 invalid_url', async () => {
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'javascript:alert(1)' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_url');
  });

  test('https://localhost returns 400 invalid_url (SSRF)', async () => {
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://localhost/foo' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_url');
  });

  test('https://127.0.0.1 returns 400 invalid_url (SSRF)', async () => {
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://127.0.0.1/foo' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_url');
  });

  test('RFC1918 192.168.x.x returns 400 invalid_url (SSRF)', async () => {
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://192.168.1.1/foo' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_url');
  });

  test('RFC1918 10.x.x.x returns 400 invalid_url (SSRF)', async () => {
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://10.0.0.1/foo' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_url');
  });

  test('RFC1918 172.16.x.x returns 400 invalid_url (SSRF)', async () => {
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://172.16.0.1/foo' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_url');
  });

  // 2026-06-03 cybersec MED-2: link-local + cloud metadata blocked. Without
  // these, an authenticated user with an Anthropic key could hit Render's
  // metadata service (any-host LLM path no longer gated to timeout.com).
  test('AWS/GCP link-local 169.254.169.254 returns 400 invalid_url (SSRF)', async () => {
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://169.254.169.254/latest/meta-data/' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_url');
  });

  test('GCP metadata.google.internal returns 400 invalid_url (SSRF)', async () => {
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://metadata.google.internal/computeMetadata/v1/' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_url');
  });

  test('IPv6 link-local fe80:: returns 400 invalid_url (SSRF)', async () => {
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://[fe80::1]/foo' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_url');
  });

  test('IPv6 ULA fd00:: returns 400 invalid_url (SSRF)', async () => {
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://[fd12:3456::1]/foo' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_url');
  });

  test('IPv4-mapped IPv6 loopback ::ffff:127.0.0.1 returns 400 invalid_url (SSRF)', async () => {
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://[::ffff:127.0.0.1]/foo' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_url');
  });

  test('unsupported host returns 400 host_not_supported', async () => {
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://example.com/foo' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('host_not_supported');
  });
});

// ── Upstream fetch errors ─────────────────────────────────────────────────────

describe('POST /api/import/website — upstream fetch errors', () => {
  test('fetch throws returns 502 fetch_failed', async () => {
    jest.spyOn(global, 'fetch').mockRejectedValue(new Error('network timeout'));
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://www.timeout.com/lisbon/restaurants/best' });
    expect(res.status).toBe(502);
    expect(res.body.error).toBe('fetch_failed');
    // Must not leak upstream error message
    expect(JSON.stringify(res.body)).not.toContain('network timeout');
  });

  test('fetch returns 404 returns 502 with status-tagged error (lets client toast distinguish moved page)', async () => {
    mockFetch('Not Found', { status: 404, ok: false });
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://www.timeout.com/lisbon/restaurants/best' });
    expect(res.status).toBe(502);
    expect(res.body.error).toBe('fetch_failed_404');
  });

  test('fetch returns 503 surfaces in error string (lets client say "site temporarily down")', async () => {
    mockFetch('Service Unavailable', { status: 503, ok: false });
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://www.timeout.com/lisbon/restaurants/best' });
    expect(res.status).toBe(502);
    expect(res.body.error).toBe('fetch_failed_503');
  });

  test('response body >5MB returns 413 response_too_large', async () => {
    const bigBuf = Buffer.alloc(5 * 1024 * 1024 + 1, 'x');
    jest.spyOn(global, 'fetch').mockResolvedValue({
      ok: true,
      status: 200,
      arrayBuffer: async () => bigBuf,
    });
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://www.timeout.com/lisbon/restaurants/best' });
    expect(res.status).toBe(413);
    expect(res.body.error).toBe('response_too_large');
  });
});

// ── Parsing — JSON-LD path ────────────────────────────────────────────────────

describe('POST /api/import/website — JSON-LD parsing', () => {
  test('valid ItemList JSON-LD extracts venues with names and addresses', async () => {
    const html = `<html><head><title>50 Best Restaurants in Lisbon | Time Out</title>
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "ItemList",
  "name": "50 Best Restaurants in Lisbon",
  "itemListElement": [
    {
      "@type": "ListItem",
      "position": 1,
      "item": {
        "@type": "Restaurant",
        "name": "Cervejaria Ramiro",
        "address": { "@type": "PostalAddress", "streetAddress": "Avenida Almirante Reis 1" }
      }
    },
    {
      "@type": "ListItem",
      "position": 2,
      "item": {
        "@type": "Restaurant",
        "name": "Taberna da Rua das Flores",
        "address": "Rua das Flores 103"
      }
    },
    {
      "@type": "ListItem",
      "position": 3,
      "item": {
        "@type": "Restaurant",
        "name": "Time Out Market"
      }
    }
  ]
}
</script>
</head></html>`;
    mockFetch(html);
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://www.timeout.com/lisbon/restaurants/50-best' });
    expect(res.status).toBe(200);
    expect(res.body.source).toBe('timeout');
    expect(res.body.venues).toHaveLength(3);
    expect(res.body.venues[0].name).toBe('Cervejaria Ramiro');
    expect(res.body.venues[0].address).toBe('Avenida Almirante Reis 1');
    expect(res.body.venues[1].address).toBe('Rua das Flores 103');
    expect(res.body.venues[2].name).toBe('Time Out Market');
    expect(res.body.venues[2].address).toBeUndefined();
  });

  test('JSON-LD with @type as array containing ItemList', async () => {
    const html = `<html><head><title>Test</title>
<script type="application/ld+json">
{
  "@type": ["WebPage", "ItemList"],
  "itemListElement": [
    { "item": { "name": "Faz Figura" } }
  ]
}
</script></head></html>`;
    mockFetch(html);
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://www.timeout.com/lisbon/bars/best' });
    expect(res.status).toBe(200);
    expect(res.body.venues).toHaveLength(1);
    expect(res.body.venues[0].name).toBe('Faz Figura');
  });

  test('malformed JSON-LD block is skipped gracefully', async () => {
    const html = `<html><head><title>Test</title>
<script type="application/ld+json">{ INVALID JSON }</script>
<script type="application/ld+json">
{"@type":"ItemList","itemListElement":[{"item":{"name":"Valid Place"}}]}
</script></head></html>`;
    mockFetch(html);
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://www.timeout.com/lisbon/bars/best' });
    expect(res.status).toBe(200);
    expect(res.body.venues).toHaveLength(1);
    expect(res.body.venues[0].name).toBe('Valid Place');
  });
});

// ── Parsing — numbered-headings fallback ─────────────────────────────────────

describe('POST /api/import/website — numbered-headings fallback', () => {
  test('h3 numbered headings with address tags extracted correctly', async () => {
    const html = `<html><head><title>Best Restaurants</title></head><body>
<h3>1. Cervejaria Ramiro</h3><address>Avenida Almirante Reis 1</address>
<h3>2. Solar dos Presuntos</h3><address>Rua Portas de Santo Antao 150</address>
<h3>3. Tasca do Chico</h3><p>A cosy fado venue with excellent petiscos.</p>
</body></html>`;
    mockFetch(html);
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://www.timeout.com/lisbon/restaurants/best' });
    expect(res.status).toBe(200);
    expect(res.body.venues).toHaveLength(3);
    expect(res.body.venues[0].name).toBe('Cervejaria Ramiro');
    expect(res.body.venues[0].address).toBe('Avenida Almirante Reis 1');
    expect(res.body.venues[1].name).toBe('Solar dos Presuntos');
    expect(res.body.venues[1].address).toBe('Rua Portas de Santo Antao 150');
    expect(res.body.venues[2].name).toBe('Tasca do Chico');
    expect(res.body.venues[2].snippet).toBeDefined();
    expect(res.body.venues[2].address).toBeUndefined();
  });

  test('h2 numbered headings are also matched', async () => {
    const html = `<html><head><title>Best Bars</title></head><body>
<h2>1. Pavilhao Chines</h2><address>Rua Dom Pedro V 89</address>
<h2>2. Bar Foxtrot</h2><p>Intimate cocktail bar in Principe Real.</p>
</body></html>`;
    mockFetch(html);
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://www.timeout.com/lisbon/bars/best' });
    expect(res.status).toBe(200);
    expect(res.body.venues[0].name).toBe('Pavilhao Chines');
    expect(res.body.venues[0].address).toBe('Rua Dom Pedro V 89');
    expect(res.body.venues[1].snippet).toMatch(/cocktail bar/);
  });

  test('snippet is capped at 200 chars', async () => {
    const longText = 'A'.repeat(300);
    const html = `<html><head><title>Test</title></head><body>
<h3>1. Long Snippet Place</h3><p>${longText}</p>
</body></html>`;
    mockFetch(html);
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://www.timeout.com/lisbon/restaurants/best' });
    expect(res.status).toBe(200);
    expect(res.body.venues[0].snippet.length).toBe(200);
  });

  // 2026-06-03 regression: Time Out wraps the leading number in <span> and
  // separates it from the name with &nbsp;. The raw inner text becomes
  // "<span>1.</span>&nbsp;Miga" — stripTags leaves "1.&nbsp;Miga", which
  // fails /^\d+\.\s+/ because &nbsp; isn't whitespace before entity-decoding.
  // Captured live from timeout.com/london/restaurants/best-restaurants-in-london.
  test('current Time Out shape: <h3><span>N.</span>&nbsp;Name</h3> still extracts the name', async () => {
    const html = `<html><head><title>The 50 Best Restaurants in London 2026 | Time Out</title></head><body>
<h3 class="_h3_c6c0h_1" data-testid="tile-title_testID"><span>1.</span>&nbsp;Miga</h3>
<h3 class="_h3_c6c0h_1" data-testid="tile-title_testID"><span>2.</span>&nbsp;Oma</h3>
<h3 class="_h3_c6c0h_1" data-testid="tile-title_testID"><span>3.</span>&nbsp;Plates</h3>
<h3 class="_h3_c6c0h_1" data-testid="tile-title_testID"></h3>
</body></html>`;
    mockFetch(html);
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://www.timeout.com/london/restaurants/best-restaurants-in-london' });
    expect(res.status).toBe(200);
    expect(res.body.venues.map(v => v.name)).toEqual(['Miga', 'Oma', 'Plates']);
    expect(res.body.articleTitle).toMatch(/50 Best Restaurants in London/);
    expect(res.body.city).toBe('London');
  });

  test('current Time Out shape: heading with empty inner (placeholder tile) is skipped, not a "name: undefined"', async () => {
    const html = `<html><head><title>Best</title></head><body>
<h3 class="_h3_c6c0h_1" data-testid="tile-title_testID"></h3>
<h3 class="_h3_c6c0h_1" data-testid="tile-title_testID"><span>1.</span>&nbsp;Real Place</h3>
</body></html>`;
    mockFetch(html);
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://www.timeout.com/london/restaurants/best' });
    expect(res.status).toBe(200);
    expect(res.body.venues).toHaveLength(1);
    expect(res.body.venues[0].name).toBe('Real Place');
  });
});

// ── City detection ────────────────────────────────────────────────────────────

describe('POST /api/import/website — city detection', () => {
  test('/lisbon/restaurants/best-of-2026 → city="Lisbon"', async () => {
    mockFetch('<html><head><title>Best</title></head></html>');
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://www.timeout.com/lisbon/restaurants/best-of-2026' });
    expect(res.status).toBe(200);
    expect(res.body.city).toBe('Lisbon');
  });

  test('/new-york/bars/... → city="New York"', async () => {
    mockFetch('<html><head><title>Best Bars</title></head></html>');
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://www.timeout.com/new-york/bars/best-cocktail-bars' });
    expect(res.status).toBe(200);
    expect(res.body.city).toBe('New York');
  });

  test('URL with content category as first segment → city=null', async () => {
    mockFetch('<html><head><title>Best Restaurants</title></head></html>');
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://www.timeout.com/restaurants/best' });
    expect(res.status).toBe(200);
    expect(res.body.city).toBeNull();
  });
});

// ── articleTitle ──────────────────────────────────────────────────────────────

describe('POST /api/import/website — articleTitle', () => {
  test('extracts title from <title> tag', async () => {
    mockFetch('<html><head><title>The 50 best restaurants in Lisbon | Time Out</title></head></html>');
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://www.timeout.com/lisbon/restaurants/best' });
    expect(res.status).toBe(200);
    expect(res.body.articleTitle).toBe('The 50 best restaurants in Lisbon | Time Out');
  });

  test('falls back to <h1> when no <title>', async () => {
    mockFetch('<html><head></head><body><h1>The 50 best bars in <span>Lisbon</span></h1></body></html>');
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://www.timeout.com/lisbon/bars/best' });
    expect(res.status).toBe(200);
    expect(res.body.articleTitle).toBe('The 50 best bars in Lisbon');
  });

  test('articleTitle is null when neither <title> nor <h1> present', async () => {
    mockFetch('<html><head></head><body><p>nothing here</p></body></html>');
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://www.timeout.com/lisbon/bars/best' });
    expect(res.status).toBe(200);
    expect(res.body.articleTitle).toBeNull();
  });
});

// ── Garbage / zero-venue ─────────────────────────────────────────────────────

describe('POST /api/import/website — garbage HTML', () => {
  test('garbage HTML returns 200 with venues=[] and correct shape', async () => {
    mockFetch('<html><body><p>This page has no venue listings at all.</p></body></html>');
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://www.timeout.com/lisbon/restaurants/best' });
    expect(res.status).toBe(200);
    expect(res.body.venues).toEqual([]);
    expect(res.body.source).toBe('timeout');
    expect(Object.keys(res.body)).toEqual(expect.arrayContaining(['city', 'articleTitle', 'source', 'venues']));
  });
});

// ── Entity decoding ───────────────────────────────────────────────────────────

describe('POST /api/import/website — entity decoding', () => {
  test('HTML entities in name are decoded', async () => {
    const html = `<html><head><title>Test</title>
<script type="application/ld+json">
{"@type":"ItemList","itemListElement":[
  {"item":{"name":"Foo &amp; Bar"}},
  {"item":{"name":"O&#39;Brien&#39;s"}},
  {"item":{"name":"The &quot;Grand&quot; Cafe"}}
]}
</script></head></html>`;
    mockFetch(html);
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://www.timeout.com/lisbon/restaurants/best' });
    expect(res.status).toBe(200);
    expect(res.body.venues[0].name).toBe('Foo & Bar');
    expect(res.body.venues[1].name).toBe("O'Brien's");
    expect(res.body.venues[2].name).toBe('The "Grand" Cafe');
  });
});

// ── Cap at 100 venues ─────────────────────────────────────────────────────────

describe('POST /api/import/website — venue cap', () => {
  test('150 venues in JSON-LD are capped at 100', async () => {
    const items = Array.from({ length: 150 }, (_, i) => ({
      '@type': 'ListItem',
      position: i + 1,
      item: { '@type': 'Restaurant', name: `Venue ${i + 1}` },
    }));
    const html = `<html><head><title>Big List</title>
<script type="application/ld+json">
${JSON.stringify({ '@type': 'ItemList', itemListElement: items })}
</script></head></html>`;
    mockFetch(html);
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://www.timeout.com/lisbon/restaurants/best' });
    expect(res.status).toBe(200);
    expect(res.body.venues).toHaveLength(100);
    expect(res.body.venues[0].name).toBe('Venue 1');
    expect(res.body.venues[99].name).toBe('Venue 100');
  });
});

// ── Response shape ────────────────────────────────────────────────────────────

describe('POST /api/import/website — response shape', () => {
  test('success response has all required fields', async () => {
    const html = `<html><head><title>Best Lisbon Restaurants | Time Out</title>
<script type="application/ld+json">
{"@type":"ItemList","itemListElement":[{"item":{"name":"A Cevicheria"}}]}
</script></head></html>`;
    mockFetch(html);
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://www.timeout.com/lisbon/restaurants/best' });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('city');
    expect(res.body).toHaveProperty('articleTitle');
    expect(res.body).toHaveProperty('source', 'timeout');
    expect(res.body).toHaveProperty('venues');
    expect(Array.isArray(res.body.venues)).toBe(true);
  });

  // 2026-06-03 cybersec MED-1: fetch must use redirect:'error' so a 301/302
  // from an attacker-controlled host can't bounce the server-side fetch into
  // a private/metadata IP after the SSRF_BLOCK hostname check has passed.
  test("fetch is called with redirect:'error' (source-grep pin)", () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'server', 'index.js'), 'utf-8');
    // Be tolerant of either single or double quotes around 'error'.
    expect(src).toMatch(/redirect:\s*['"]error['"]/);
  });

  test('timeout.com without www. prefix is also matched', async () => {
    const noWwwHtml = [
      '<html><head><title>Test</title>',
      '<script type="application/ld+json">',
      '{"@type":"ItemList","itemListElement":[{"item":{"name":"Some Spot"}}]}',
      '</script></head></html>',
    ].join('\n');
    mockFetch(noWwwHtml);
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://timeout.com/lisbon/restaurants/best' });
    expect(res.status).toBe(200);
    expect(res.body.source).toBe('timeout');
  });
});
