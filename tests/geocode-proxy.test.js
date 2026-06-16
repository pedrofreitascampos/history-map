// Nominatim proxy + throttle — static source tests.
// Verifies the server proxy exists with correct guards and that
// the frontend no longer calls Nominatim directly.

const fs = require('fs');
const path = require('path');

const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');
const serverSrc = fs.readFileSync(path.join(__dirname, '..', 'server', 'index.js'), 'utf-8');

describe('Geocode proxy — server routes', () => {
  test('GET /api/geocode route is defined', () => {
    expect(serverSrc).toMatch(/app\.get\(['"]\/api\/geocode['"]/);
  });

  test('GET /api/geocode/reverse route is defined', () => {
    expect(serverSrc).toMatch(/app\.get\(['"]\/api\/geocode\/reverse['"]/);
  });

  test('both routes require auth middleware', () => {
    const fwdIdx = serverSrc.indexOf("app.get('/api/geocode'");
    const fwdSlice = serverSrc.slice(fwdIdx, fwdIdx + 80);
    expect(fwdSlice).toContain('auth');

    const revIdx = serverSrc.indexOf("app.get('/api/geocode/reverse'");
    const revSlice = serverSrc.slice(revIdx, revIdx + 80);
    expect(revSlice).toContain('auth');
  });

  test('_proxyNominatim is defined with a serial chain', () => {
    expect(serverSrc).toContain('function _proxyNominatim(');
    expect(serverSrc).toMatch(/_nominatimChain/);
  });

  test('throttle enforces ≥1050ms between calls', () => {
    const fnStart = serverSrc.indexOf('function _proxyNominatim(');
    const fnSlice = serverSrc.slice(fnStart, fnStart + 600);
    expect(fnSlice).toContain('1050');
  });

  test('cache uses TTL constant and max size cap', () => {
    expect(serverSrc).toContain('GEOCODE_CACHE_TTL');
    expect(serverSrc).toContain('GEOCODE_CACHE_MAX');
    expect(serverSrc).toMatch(/24 \* 60 \* 60 \* 1000/);
  });

  test('User-Agent header is set on Nominatim requests', () => {
    const fnStart = serverSrc.indexOf('function _proxyNominatim(');
    const fnSlice = serverSrc.slice(fnStart, fnStart + 600);
    expect(fnSlice).toContain('User-Agent');
  });

  test('/api/geocode validates q param', () => {
    const routeIdx = serverSrc.indexOf("app.get('/api/geocode'");
    const routeSlice = serverSrc.slice(routeIdx, routeIdx + 300);
    expect(routeSlice).toMatch(/status\(400\)/);
    expect(routeSlice).toContain('q required');
  });

  test('/api/geocode clamps limit to 10', () => {
    const routeIdx = serverSrc.indexOf("app.get('/api/geocode'");
    const routeSlice = serverSrc.slice(routeIdx, routeIdx + 300);
    expect(routeSlice).toMatch(/Math\.min.*10/);
  });
});

describe('Geocode proxy — no direct Nominatim calls in frontend', () => {
  test('no nominatim.openstreetmap.org URLs remain in index.html', () => {
    expect(html).not.toContain('nominatim.openstreetmap.org');
  });

  test('forward geocode calls use /api/geocode', () => {
    const matches = (html.match(/\/api\/geocode\?q=/g) || []).length;
    expect(matches).toBeGreaterThanOrEqual(8);
  });

  test('reverse geocode calls use /api/geocode/reverse', () => {
    const matches = (html.match(/\/api\/geocode\/reverse\?lat=/g) || []).length;
    expect(matches).toBeGreaterThanOrEqual(3);
  });

  test('nominatimPool tasks use relative proxy URL (url: `/api/geocode`)', () => {
    const poolIdx = html.indexOf('async function nominatimPool(');
    const afterPool = html.indexOf('async function nominatimPool(', poolIdx + 10);
    // The tasks built before the pool calls use /api/geocode
    expect(html).toContain('url: `/api/geocode?');
    expect(html).toContain('url: `/api/geocode/reverse?');
  });
});
