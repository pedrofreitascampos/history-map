// Oikumene Service Worker — offline tile cache + app shell
// Bump CACHE_VER to force cache replacement on next deploy.
const CACHE_VER = 'v1';
const SHELL_CACHE = 'oikumene-shell-' + CACHE_VER;
const TILE_CACHE  = 'oikumene-tiles-' + CACHE_VER;
const API_CACHE   = 'oikumene-api-'   + CACHE_VER;
const ALL_CACHES  = [SHELL_CACHE, TILE_CACHE, API_CACHE];

// Tile cache cap: ~200 tiles ≈ 2–4 MB (Stadia tiles average ~15 KB each).
const MAX_TILES = 200;

// ── Install: skip waiting so new SW activates immediately ─────────────────
self.addEventListener('install', e => {
  e.waitUntil(self.skipWaiting());
});

// ── Activate: evict caches from old versions + claim all clients ──────────
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys.filter(k => !ALL_CACHES.includes(k)).map(k => caches.delete(k))
      ))
      .then(() => self.clients.claim())
  );
});

// ── Fetch: route by origin and path ──────────────────────────────────────
self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;

  const url = new URL(e.request.url);
  const { origin, pathname } = url;

  // CartoDB map tiles → cache-first (view offline areas you've already loaded)
  if (origin.endsWith('.basemaps.cartocdn.com')) {
    e.respondWith(cacheTileFirst(e.request));
    return;
  }

  // CDN assets (Leaflet, Chart.js, etc.) → cache-first (versioned, immutable)
  if (origin === 'https://unpkg.com' || origin === 'https://cdn.jsdelivr.net') {
    e.respondWith(cacheFirst(e.request, SHELL_CACHE));
    return;
  }

  // Only handle own-origin requests from here on
  if (origin !== self.location.origin) return;

  // Share pages are dynamic (CSP nonce per request) — network only
  if (pathname.startsWith('/s/')) return;

  // Auth endpoints — always network (never cache tokens)
  if (pathname.startsWith('/api/auth')) return;

  // Other API GET requests → network-first, stale cache as offline fallback
  if (pathname.startsWith('/api/')) {
    e.respondWith(networkFirst(e.request, API_CACHE));
    return;
  }

  // Share target: serve app shell, frontend parses URL params
  if (url.pathname === '/share-target') {
    e.respondWith(fetch(e.request).catch(() => caches.match('/')));
    return;
  }

  // App shell (HTML, static files, manifest, icons) → network-first with cache fallback
  e.respondWith(networkFirst(e.request, SHELL_CACHE));
});

// ── Strategy: cache-first (tiles) with LRU-style cap ─────────────────────
async function cacheTileFirst(req) {
  const cache = await caches.open(TILE_CACHE);
  const cached = await cache.match(req);
  if (cached) return cached;
  try {
    const res = await fetch(req);
    if (res.ok) {
      const keys = await cache.keys();
      if (keys.length >= MAX_TILES) await cache.delete(keys[0]);
      await cache.put(req, res.clone());
    }
    return res;
  } catch (_) {
    return new Response('', { status: 503, statusText: 'Offline' });
  }
}

// ── Strategy: cache-first (CDN / immutable assets) ────────────────────────
async function cacheFirst(req, cacheName) {
  const cache = await caches.open(cacheName);
  const cached = await cache.match(req);
  if (cached) return cached;
  try {
    const res = await fetch(req);
    if (res.ok) await cache.put(req, res.clone());
    return res;
  } catch (_) {
    return new Response('', { status: 503, statusText: 'Offline' });
  }
}

// ── Strategy: network-first with cache fallback ───────────────────────────
async function networkFirst(req, cacheName) {
  const cache = cacheName ? await caches.open(cacheName) : null;
  try {
    const res = await fetch(req);
    if (cache && res.ok) await cache.put(req, res.clone());
    return res;
  } catch (_) {
    if (cache) {
      const cached = await cache.match(req);
      if (cached) return cached;
    }
    return new Response('Offline', { status: 503, statusText: 'Offline' });
  }
}
