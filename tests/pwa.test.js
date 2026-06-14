// PWA regression tests — manifest, service worker, and offline wiring.

const path = require('path');
const fs = require('fs');

const indexHtml = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');
const swJs      = fs.readFileSync(path.join(__dirname, '..', 'public', 'sw.js'),       'utf-8');
const manifest  = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'public', 'manifest.json'), 'utf-8'));
const serverJs  = fs.readFileSync(path.join(__dirname, '..', 'server', 'index.js'),    'utf-8');

// ── Manifest ──────────────────────────────────────────────────────────────
describe('PWA manifest', () => {
  test('manifest.json has required fields', () => {
    expect(manifest.name).toBeTruthy();
    expect(manifest.short_name).toBeTruthy();
    expect(manifest.start_url).toBe('/');
    expect(manifest.display).toBe('standalone');
    expect(manifest.theme_color).toBeTruthy();
    expect(manifest.background_color).toBeTruthy();
  });

  test('manifest has at least one icon', () => {
    expect(Array.isArray(manifest.icons)).toBe(true);
    expect(manifest.icons.length).toBeGreaterThan(0);
    expect(manifest.icons[0].src).toBeTruthy();
  });

  test('index.html links to manifest', () => {
    expect(indexHtml).toMatch(/<link rel="manifest" href="\/manifest\.json">/);
  });

  test('index.html has theme-color meta', () => {
    expect(indexHtml).toMatch(/<meta name="theme-color"/);
  });

  test('index.html has apple-mobile-web-app-capable meta', () => {
    expect(indexHtml).toMatch(/apple-mobile-web-app-capable/);
  });

  test('icon.svg file exists', () => {
    const iconPath = path.join(__dirname, '..', 'public', 'icon.svg');
    expect(fs.existsSync(iconPath)).toBe(true);
    const svg = fs.readFileSync(iconPath, 'utf-8');
    expect(svg).toContain('<svg');
    expect(svg).toContain('</svg>');
  });
});

// ── Service Worker — wiring ───────────────────────────────────────────────
describe('PWA service worker — wiring', () => {
  test('index.html registers service worker in DOMContentLoaded', () => {
    expect(indexHtml).toMatch(/serviceWorker.*in.*navigator/);
    expect(indexHtml).toMatch(/serviceWorker\.register\(['"]\/sw\.js['"]\)/);
  });

  test('sw.js served with no-store via dedicated route in server', () => {
    expect(serverJs).toMatch(/app\.get\(['"]\/sw\.js['"]/);
    const swRouteIdx = serverJs.indexOf("app.get('/sw.js'");
    const block = serverJs.slice(swRouteIdx, swRouteIdx + 200);
    expect(block).toContain('no-store');
  });

  test('index.html has offline event listener', () => {
    expect(indexHtml).toMatch(/addEventListener\(['"]offline['"]/);
  });

  test('index.html has online event listener', () => {
    expect(indexHtml).toMatch(/addEventListener\(['"]online['"]/);
  });
});

// ── Service Worker — event handlers ──────────────────────────────────────
describe('PWA service worker — event handlers', () => {
  test('sw.js has install handler that calls skipWaiting', () => {
    expect(swJs).toMatch(/addEventListener\(['"]install['"]/);
    expect(swJs).toContain('skipWaiting');
  });

  test('sw.js has activate handler that clears old caches', () => {
    expect(swJs).toMatch(/addEventListener\(['"]activate['"]/);
    expect(swJs).toContain('caches.delete');
    expect(swJs).toContain('clients.claim');
  });

  test('sw.js has fetch handler', () => {
    expect(swJs).toMatch(/addEventListener\(['"]fetch['"]/);
  });

  test('sw.js intercepts CartoDB tile requests', () => {
    expect(swJs).toContain('basemaps.cartocdn.com');
  });

  test('sw.js has tile cache with MAX_TILES cap', () => {
    expect(swJs).toContain('MAX_TILES');
    expect(swJs).toMatch(/MAX_TILES\s*=\s*\d+/);
  });

  test('sw.js skips non-GET requests', () => {
    expect(swJs).toMatch(/request\.method.*!==.*GET|method.*GET.*return/);
  });

  test('sw.js never caches /api/auth endpoints', () => {
    expect(swJs).toContain('/api/auth');
    const authIdx = swJs.indexOf('/api/auth');
    const block = swJs.slice(authIdx - 30, authIdx + 60);
    expect(block).toMatch(/return|skip/i);
  });

  test('sw.js skips /s/ share pages (dynamic nonce per request)', () => {
    expect(swJs).toMatch(/pathname.*startsWith.*['"]\/s\//);
  });

  test('sw.js defines CACHE_VER for easy cache busting', () => {
    expect(swJs).toMatch(/CACHE_VER\s*=\s*['"][^'"]+['"]/);
  });
});
