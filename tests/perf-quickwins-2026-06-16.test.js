// Audit 2026-06-16 quick-wins batch: preconnect, deferred Leaflet, JSON cache
// headers, async backup write, /healthz, SW API-cache removal.

const path = require('path');
const fs = require('fs');

const indexHtml = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');
const serverSrc = fs.readFileSync(path.join(__dirname, '..', 'server', 'index.js'), 'utf-8');
const swJs = fs.readFileSync(path.join(__dirname, '..', 'public', 'sw.js'), 'utf-8');

describe('Cold-load head', () => {
  test('preconnect hints for the 4 CDN origins', () => {
    ['unpkg.com', 'cdn.jsdelivr.net', 'fonts.googleapis.com', 'fonts.gstatic.com'].forEach((o) => {
      expect(indexHtml).toMatch(new RegExp(`rel="preconnect"\\s+href="https://${o.replace('.', '\\.')}"`));
    });
  });

  test('Leaflet trio is deferred (off critical path)', () => {
    expect(indexHtml).toMatch(/<script defer src="https:\/\/unpkg\.com\/leaflet@1\.9\.4/);
    expect(indexHtml).toMatch(/<script defer src="https:\/\/unpkg\.com\/leaflet\.markercluster/);
    expect(indexHtml).toMatch(/<script defer src="https:\/\/unpkg\.com\/leaflet\.heat/);
  });
});

describe('Server perf', () => {
  test('admin1.json + cities.json get a long-lived Cache-Control', () => {
    const idx = serverSrc.indexOf("'/admin1.json', '/cities.json'");
    expect(idx).toBeGreaterThan(-1);
    const block = serverSrc.slice(idx, idx + 300);
    expect(block).toMatch(/Cache-Control/);
    expect(block).toMatch(/max-age=\d{5,}/);
  });

  test('runBackup writes asynchronously (no event-loop block)', () => {
    expect(serverSrc).toMatch(/await fs\.promises\.writeFile\(backupFile/);
    expect(serverSrc).not.toMatch(/fs\.writeFileSync\(backupFile/);
  });

  test('/healthz route is registered before the SPA catch-all', () => {
    const healthIdx = serverSrc.indexOf("app.get('/healthz'");
    const catchAllIdx = serverSrc.indexOf("app.get('*'");
    expect(healthIdx).toBeGreaterThan(-1);
    expect(catchAllIdx).toBeGreaterThan(healthIdx);
  });
});

describe('Service worker', () => {
  test('no API response cache bucket remains', () => {
    expect(swJs).not.toContain('API_CACHE');
    expect(swJs).not.toContain('oikumene-api');
  });

  test('/api/ requests bail to network without caching', () => {
    const idx = swJs.indexOf("pathname.startsWith('/api/')");
    expect(idx).toBeGreaterThan(-1);
    expect(swJs.slice(idx, idx + 40)).toMatch(/return\s*;/);
  });
});

// /healthz is exercised behaviorally in tests/security-batch-2026-06-16.test.js,
// which already boots the app; here we only assert it's wired (source above).
