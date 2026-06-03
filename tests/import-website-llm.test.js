'use strict';

// Tests the LLM-powered web-import adapter shipped 2026-06-03 (audit P0).
// Covers: adapter unit (HTML stripping, char cap), route wiring (engine
// selection, host_not_supported gating, sanitised errors), and the
// /api/anthropic/status endpoint that drives the engine-attribution UX.

const path = require('path');
const fs = require('fs');

const testDataDir = path.join(__dirname, '..', 'data-test-import-website-llm');
if (!fs.existsSync(testDataDir)) fs.mkdirSync(testDataDir, { recursive: true });
process.env.DATA_DIR = testDataDir;
process.env.JWT_SECRET = 'import-website-llm-test-secret';
process.env.ALLOWED_EMAILS = '';
process.env.ANTHROPIC_API_KEY = 'sk-ant-env-test-key';

// Mock @anthropic-ai/sdk BEFORE requiring the app — same pattern as narrate.test.js.
const mockCreate = jest.fn();
jest.mock('@anthropic-ai/sdk', () => {
  return {
    default: jest.fn().mockImplementation(() => ({
      messages: { create: mockCreate },
    })),
  };
});

const request = require('supertest');
const app = require('../server/index');
const db = require('../server/db');
const {
  parseVenuesLLM,
  stripHtmlForLLM,
  HTML_TEXT_CAP,
  MAX_VENUES,
  PARSE_VENUES_TOOL,
  SYSTEM_PROMPT,
} = require('../server/import-adapters/llm');

const USER = { username: 'llmimportuser', password: 'llmimportpass123' };
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

beforeEach(() => {
  mockCreate.mockReset();
  jest.restoreAllMocks();
});

function mockFetch(html, { status = 200, ok = true } = {}) {
  jest.spyOn(global, 'fetch').mockResolvedValue({
    ok,
    status,
    arrayBuffer: async () => Buffer.from(html, 'utf-8'),
  });
}

function happyToolUse({ venues = [], city = null, articleTitle = null } = {}) {
  return Promise.resolve({
    content: [
      {
        type: 'tool_use',
        name: 'parse_venues',
        input: { city, articleTitle, venues },
      },
    ],
    usage: { input_tokens: 5000, output_tokens: 400, cache_read_input_tokens: 4800 },
  });
}

// ─── Pure adapter — stripHtmlForLLM ────────────────────────────────────────

describe('stripHtmlForLLM', () => {
  test('removes <script>, <style>, <noscript>, <iframe>, <svg> and HTML comments', () => {
    const html = '<html><head><script>alert(1)</script><style>body{}</style>' +
      '<noscript>x</noscript></head><body>' +
      '<!-- secret --><iframe>y</iframe><svg><path/></svg>' +
      '<h1>Best Bars</h1><p>Hello</p></body></html>';
    const out = stripHtmlForLLM(html);
    expect(out).not.toMatch(/alert\(1\)/);
    expect(out).not.toMatch(/body\{\}/);
    expect(out).not.toMatch(/<svg|<iframe|<noscript|<!--|secret/);
    expect(out).toContain('Best Bars');
    expect(out).toContain('Hello');
  });

  test('decodes common HTML entities so the model reads natural text', () => {
    const out = stripHtmlForLLM('<p>Foo&nbsp;&amp;&nbsp;Bar &#39;Baz&#39; &quot;Q&quot;</p>');
    expect(out).toBe("Foo & Bar 'Baz' \"Q\"");
  });

  test('respects HTML_TEXT_CAP so a malicious oversized page cannot blow up token bill', () => {
    const big = '<p>' + 'a'.repeat(HTML_TEXT_CAP + 5000) + '</p>';
    const out = stripHtmlForLLM(big);
    expect(out.length).toBe(HTML_TEXT_CAP);
  });

  test('non-string input returns empty string (defensive)', () => {
    expect(stripHtmlForLLM(null)).toBe('');
    expect(stripHtmlForLLM(undefined)).toBe('');
    expect(stripHtmlForLLM({})).toBe('');
  });
});

// ─── parseVenuesLLM unit ───────────────────────────────────────────────────

describe('parseVenuesLLM', () => {
  test('happy path: forced parse_venues tool with cached system prompt', async () => {
    mockCreate.mockResolvedValueOnce(happyToolUse({
      venues: [
        { name: 'Miga', address: '12 Spitalfields, London', snippet: 'Modern Portuguese.' },
        { name: 'Oma', address: 'Borough Market', snippet: null },
      ],
      city: 'London',
      articleTitle: 'The 50 Best Restaurants in London 2026',
    }));
    const result = await parseVenuesLLM('<h1>Best</h1>', 'https://timeout.com/london/best', 'sk-ant-test');
    expect(result.venues).toHaveLength(2);
    expect(result.venues[0].name).toBe('Miga');
    expect(result.venues[0].address).toBe('12 Spitalfields, London');
    expect(result.venues[1].snippet).toBeUndefined();  // null snippet dropped
    expect(result.city).toBe('London');
    expect(result.articleTitle).toMatch(/50 Best/);

    expect(mockCreate).toHaveBeenCalledTimes(1);
    const callArgs = mockCreate.mock.calls[0][0];
    expect(callArgs.model).toBe('claude-haiku-4-5-20251001');
    expect(callArgs.tool_choice).toEqual({ type: 'tool', name: 'parse_venues' });
    expect(callArgs.tools[0].name).toBe('parse_venues');
    expect(callArgs.system[0].cache_control).toEqual({ type: 'ephemeral' });
    expect(callArgs.system[0].text).toBe(SYSTEM_PROMPT);
  });

  test('caps returned venues at MAX_VENUES even if model returns more', async () => {
    const many = Array.from({ length: MAX_VENUES + 50 }, (_, i) => ({ name: `V${i}` }));
    mockCreate.mockResolvedValueOnce(happyToolUse({ venues: many }));
    const result = await parseVenuesLLM('<p>x</p>', 'https://example.com', 'sk-ant-test');
    expect(result.venues).toHaveLength(MAX_VENUES);
  });

  test('drops venue rows with empty/non-string names (defensive against model drift)', async () => {
    mockCreate.mockResolvedValueOnce(happyToolUse({
      venues: [
        { name: 'Good' },
        { name: '' },
        { name: null },
        { name: '   ' },
        { name: 'Also Good' },
      ],
    }));
    const result = await parseVenuesLLM('<p>x</p>', 'https://example.com', 'sk-ant-test');
    expect(result.venues.map(v => v.name)).toEqual(['Good', 'Also Good']);
  });

  test('caps snippet at 200 chars (defensive against model drift)', async () => {
    mockCreate.mockResolvedValueOnce(happyToolUse({
      venues: [{ name: 'X', snippet: 'A'.repeat(500) }],
    }));
    const result = await parseVenuesLLM('<p>x</p>', 'https://example.com', 'sk-ant-test');
    expect(result.venues[0].snippet.length).toBe(200);
  });

  test('no apiKey throws llm_no_key (501) without touching SDK', async () => {
    await expect(parseVenuesLLM('<p>x</p>', 'https://example.com', '')).rejects.toMatchObject({
      code: 'llm_no_key',
      status: 501,
    });
    expect(mockCreate).not.toHaveBeenCalled();
  });

  test('Anthropic 401 → llm_error_401 with no upstream body leak', async () => {
    mockCreate.mockRejectedValueOnce({ status: 401, error: { type: 'authentication_error', message: 'invalid x-api-key abc123' } });
    let caught;
    try { await parseVenuesLLM('<p>x</p>', 'https://example.com', 'sk-bad'); }
    catch (e) { caught = e; }
    expect(caught.code).toBe('llm_error_401');
    expect(caught.status).toBe(401);
    expect(String(caught.message)).not.toContain('abc123');
  });

  test('Anthropic 429 → llm_error_429', async () => {
    mockCreate.mockRejectedValueOnce({ status: 429, error: { message: 'rate limited' } });
    await expect(parseVenuesLLM('<p>x</p>', 'https://example.com', 'sk-test')).rejects.toMatchObject({
      code: 'llm_error_429',
    });
  });

  test('response missing tool_use → llm_no_tool_use', async () => {
    mockCreate.mockResolvedValueOnce({
      content: [{ type: 'text', text: 'sorry I cannot parse that' }],
      usage: { input_tokens: 10, output_tokens: 5 },
    });
    await expect(parseVenuesLLM('<p>x</p>', 'https://example.com', 'sk-test')).rejects.toMatchObject({
      code: 'llm_no_tool_use',
    });
  });
});

// ─── /api/anthropic/status ────────────────────────────────────────────────

describe('GET /api/anthropic/status', () => {
  test('returns enabled:true + mode:smart when env key set, no key leakage', async () => {
    const res = await request(app)
      .get('/api/anthropic/status')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.enabled).toBe(true);
    expect(res.body.mode).toBe('smart');
    expect(JSON.stringify(res.body)).not.toContain('sk-ant-env-test-key');
  });

  test('401 without auth', async () => {
    const res = await request(app).get('/api/anthropic/status');
    expect(res.status).toBe(401);
  });
});

// ─── /api/import/website wiring ───────────────────────────────────────────

describe('POST /api/import/website — LLM engine selection', () => {
  test('any host (e.g. eater.com) succeeds via LLM when key is configured', async () => {
    mockFetch('<html><body><h1>Best in NYC</h1><p>some text</p></body></html>');
    mockCreate.mockResolvedValueOnce(happyToolUse({
      venues: [{ name: 'Le Bernardin', address: '155 W 51st St' }],
      city: 'New York',
      articleTitle: 'Best Restaurants',
    }));
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://www.eater.com/maps/best-nyc-restaurants' });
    expect(res.status).toBe(200);
    expect(res.body.engine).toBe('llm');
    expect(res.body.source).toBe('llm');
    expect(res.body.venues).toHaveLength(1);
    expect(res.body.venues[0].name).toBe('Le Bernardin');
    expect(res.body.city).toBe('New York');
  });

  test('timeout.com still works via LLM when key is configured (engine="llm", not "regex")', async () => {
    mockFetch('<html><body><h3>1. Miga</h3></body></html>');
    mockCreate.mockResolvedValueOnce(happyToolUse({ venues: [{ name: 'Miga' }] }));
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://www.timeout.com/london/restaurants/best' });
    expect(res.status).toBe(200);
    expect(res.body.engine).toBe('llm');
    expect(res.body.source).toBe('llm');
  });

  test('SSRF guard fires BEFORE engine selection (LLM cannot be used to bypass)', async () => {
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://127.0.0.1/secret' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_url');
    expect(mockCreate).not.toHaveBeenCalled();
  });

  test('Anthropic 401 surfaces as llm_key_rejected, sanitised', async () => {
    mockFetch('<html><body>test</body></html>');
    mockCreate.mockRejectedValueOnce({ status: 401, error: { message: 'invalid x-api-key secret-abc' } });
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://www.eater.com/best' });
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('llm_key_rejected');
    expect(JSON.stringify(res.body)).not.toContain('secret-abc');
  });

  test('Anthropic 429 → llm_rate_limited', async () => {
    mockFetch('<html><body>test</body></html>');
    mockCreate.mockRejectedValueOnce({ status: 429, error: { message: 'too many requests' } });
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://www.eater.com/best' });
    expect(res.body.error).toBe('llm_rate_limited');
    expect(JSON.stringify(res.body)).not.toContain('too many requests');
  });

  test('engine field is always present in success response shape', async () => {
    mockFetch('<html><body>test</body></html>');
    mockCreate.mockResolvedValueOnce(happyToolUse({ venues: [] }));
    const res = await request(app)
      .post('/api/import/website')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://example.com/x' });
    expect(res.body).toHaveProperty('engine');
    expect(['llm', 'regex']).toContain(res.body.engine);
  });
});

// ─── Static markup pins ────────────────────────────────────────────────────

describe('Static markup pins (regression guards)', () => {
  test('import view has #web-import-engine-hint placeholder', () => {
    const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');
    expect(html).toMatch(/id="web-import-engine-hint"/);
  });

  test('refreshWebImportEngineHint function is defined in inline script', () => {
    const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');
    expect(html).toMatch(/async function refreshWebImportEngineHint\(/);
  });

  test('engine chip strings are present (regression: dont regress UX language)', () => {
    const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');
    expect(html).toMatch(/Parsed by Claude Haiku/);
    expect(html).toMatch(/Parsed by Time Out adapter \(regex\)/);
  });

  test('switchView wires the import-view hint refresh', () => {
    const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');
    expect(html).toMatch(/refreshWebImportEngineHint\(\)/);
  });
});
