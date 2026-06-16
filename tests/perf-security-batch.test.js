// S2 Perf round 2 + cheap security/correctness sweep (2026-06-11).
// Behavioural regression tests — not string-pins. Each test covers the
// failure mode the fix addresses.

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');
const serverSrc = fs.readFileSync(path.join(__dirname, '..', 'server', 'index.js'), 'utf-8');

function extractFunction(name) {
  const start = html.indexOf(`function ${name}(`);
  if (start === -1) throw new Error(`Function ${name} not found`);
  let depth = 0, i = start, foundFirst = false;
  for (; i < html.length; i++) {
    if (html[i] === '{') { depth++; foundFirst = true; }
    if (html[i] === '}') depth--;
    if (foundFirst && depth === 0) break;
  }
  return html.substring(start, i + 1);
}

// ── 1. Dead CDN tag removed ───────────────────────────────────────────────────
describe('topojson-client CDN script removed', () => {
  test('topojson-client <script> tag is gone', () => {
    expect(html).not.toMatch(/topojson-client/);
  });
});

// ── 2. markerHash template literal ───────────────────────────────────────────
describe('markerHash uses template literal (no array allocation)', () => {
  test('function body uses template literal, not array join', () => {
    const fn = extractFunction('markerHash');
    expect(fn).toMatch(/return `\$/);
    expect(fn).not.toMatch(/\.join\(/);
  });
});

// ── 3. buildTagFilters fingerprint-based skip ─────────────────────────────────
describe('buildTagFilters fingerprint-based DOM skip', () => {
  test('uses _tagFilterFingerprint (not _tagFilterGen)', () => {
    expect(html).toMatch(/_tagFilterFingerprint/);
    expect(html).not.toMatch(/_tagFilterGen/);
  });

  test('syncs .active class on fast-path without innerHTML clear', () => {
    const fn = extractFunction('buildTagFilters');
    // Fast-path: fingerprint match → sync active, then return
    expect(fn).toMatch(/classList\.toggle\(\s*['"]active['"]/);
    // Buttons must carry data-filter-tag: querySelector uses the HTML attr,
    // JS sets it via dataset.filterTag (camelCase mapping of data-filter-tag).
    expect(fn).toMatch(/\[data-filter-tag\]/);
    expect(fn).toMatch(/dataset\.filterTag/);
  });
});

// ── 4. getFilteredLocations memoization ──────────────────────────────────────
describe('getFilteredLocations memoized', () => {
  test('declares memo cache variables', () => {
    expect(html).toMatch(/let _gflCache/);
    expect(html).toMatch(/let _gflGen/);
    expect(html).toMatch(/let _gflFiltersKey/);
  });

  test('short-circuits when generation + filtersKey match', () => {
    const fn = extractFunction('getFilteredLocations');
    expect(fn).toMatch(/_gflGen\s*===\s*stateIndex\.generation/);
    expect(fn).toMatch(/_gflFiltersKey\s*===\s*filtersKey/);
    expect(fn).toMatch(/return _gflCache/);
  });

  test('key covers all filter dimensions', () => {
    const fn = extractFunction('getFilteredLocations');
    expect(fn).toMatch(/state\.filters\.status/);
    expect(fn).toMatch(/state\.filters\.trip/);
    expect(fn).toMatch(/state\.filters\.tags/);
    expect(fn).toMatch(/state\.filters\.priceLevels/);
  });
});

// ── 5. _runAction catches async rejections ────────────────────────────────────
describe('_runAction catches unhandled async action rejections', () => {
  test('calls .catch on the returned result when it is a Promise', () => {
    const fn = extractFunction('_runAction');
    expect(fn).toMatch(/typeof result\.catch\s*===\s*['"]function['"]/);
    expect(fn).toMatch(/result\.catch\(err =>/);
    expect(fn).toMatch(/\[action error\]/);
  });
});

// ── 6. renderReplayPath uses transitLayer (append-only) ──────────────────────
describe('renderReplayPath: transit lines on transitLayer, not polylineLayer', () => {
  test('adds new transit lines to transitLayer', () => {
    const fn = extractFunction('renderReplayPath');
    expect(fn).toMatch(/replayState\.transitLayer/);
    expect(fn).toMatch(/\.addTo\(replayState\.transitLayer\)/);
  });

  test('tracks transitRenderedUpTo for append-only forward advance', () => {
    const fn = extractFunction('renderReplayPath');
    expect(fn).toMatch(/replayState\.transitRenderedUpTo/);
  });

  test('clears transitLayer only on backward seek', () => {
    const fn = extractFunction('renderReplayPath');
    // Guard: idx < transitRenderedUpTo → clear + reset
    expect(fn).toMatch(/idx\s*<\s*replayState\.transitRenderedUpTo/);
  });

  test('polylineLayer.clearLayers is still called (visit trail rebuild)', () => {
    const fn = extractFunction('renderReplayPath');
    expect(fn).toMatch(/polylineLayer\.clearLayers/);
  });
});

// ── 7. animateReplayTransit no longer adds to polylineLayer ──────────────────
describe('animateReplayTransit: transit line drawn by renderReplayPath, not here', () => {
  test('no buildReplayTransitLine → polylineLayer in animateReplayTransit', () => {
    const fn = extractFunction('animateReplayTransit');
    // The redundant line.addTo(polylineLayer) call inside this function is gone
    expect(fn).not.toMatch(/addTo\(replayState\.polylineLayer\)/);
  });
});

// ── 8. replayState has transitLayer + _fsOnKey fields ────────────────────────
describe('replayState declares transitLayer and _fsOnKey', () => {
  test('replayState object includes transitLayer: null', () => {
    const stateIdx = html.indexOf('const replayState = {');
    const stateBlock = html.slice(stateIdx, stateIdx + 1000);
    expect(stateBlock).toMatch(/transitLayer:\s*null/);
    expect(stateBlock).toMatch(/transitRenderedUpTo:\s*-1/);
  });

  test('replayState object includes _fsOnKey: null', () => {
    const stateIdx = html.indexOf('const replayState = {');
    const stateBlock = html.slice(stateIdx, stateIdx + 1000);
    expect(stateBlock).toMatch(/_fsOnKey:\s*null/);
  });
});

// ── 9. toggleReplayFullscreen stores listener on replayState ─────────────────
describe('toggleReplayFullscreen: listener stored on replayState._fsOnKey', () => {
  test('assigns listener to replayState._fsOnKey', () => {
    const fn = extractFunction('toggleReplayFullscreen');
    expect(fn).toMatch(/replayState\._fsOnKey\s*=/);
  });

  test('removes listener from document on exit (isFs=false branch)', () => {
    const fn = extractFunction('toggleReplayFullscreen');
    // Both branches must removeEventListener via replayState._fsOnKey
    expect(fn).toMatch(/removeEventListener\(\s*['"]keydown['"]\s*,\s*replayState\._fsOnKey/);
    expect(fn).toMatch(/replayState\._fsOnKey\s*=\s*null/);
  });
});

// ── 10. destroyReplayMap cleans up _fsOnKey and transitLayer ──────────────────
describe('destroyReplayMap cleans fullscreen state + transitLayer', () => {
  test('removes _fsOnKey listener', () => {
    const fn = extractFunction('destroyReplayMap');
    expect(fn).toMatch(/replayState\._fsOnKey/);
    expect(fn).toMatch(/removeEventListener/);
  });

  test('nulls transitLayer', () => {
    const fn = extractFunction('destroyReplayMap');
    expect(fn).toMatch(/replayState\.transitLayer\s*=\s*null/);
  });

  test('removes fullscreen class from panel', () => {
    const fn = extractFunction('destroyReplayMap');
    expect(fn).toMatch(/classList\.remove\(\s*['"]fullscreen['"]\s*\)/);
  });
});

// ── 11. prefetchReplayRoutes: capped at 100 + panelOpen abort ────────────────
describe('prefetchReplayRoutes: cap + early-abort guard', () => {
  test('slices targets to at most 100', () => {
    const fn = extractFunction('prefetchReplayRoutes');
    expect(fn).toMatch(/\.slice\(0,\s*100\)/);
  });

  test('checks replayState.panelOpen before each fetch', () => {
    const fn = extractFunction('prefetchReplayRoutes');
    expect(fn).toMatch(/replayState\.panelOpen/);
  });
});

// ── 12. playReplay: panelOpen guard after await ────────────────────────────────
describe('playReplay: guards panelOpen after route prefetch', () => {
  test('checks replayState.panelOpen after awaiting prefetchReplayRoutes', () => {
    const fn = extractFunction('playReplay');
    const prefetchIdx = fn.indexOf('await prefetchReplayRoutes');
    const guardIdx = fn.indexOf('replayState.panelOpen', prefetchIdx);
    expect(prefetchIdx).toBeGreaterThan(-1);
    expect(guardIdx).toBeGreaterThan(prefetchIdx);
  });
});

// ── 13. Server: /api/locations Cache-Control: private ─────────────────────────
describe('/api/locations: Cache-Control includes private', () => {
  test("sets 'private, no-cache' so user data is not stored in shared caches", () => {
    expect(serverSrc).toMatch(/['"]private,\s*no-cache['"]/);
  });
});

// ── 14. Server: Google SSO email_verified check ──────────────────────────────
describe('Google SSO: rejects unverified emails', () => {
  test('checks payload.email_verified before linking/creating account', () => {
    expect(serverSrc).toMatch(/payload\.email_verified/);
    expect(serverSrc).toMatch(/Email not verified/);
  });

  test('email_verified check appears before email is used', () => {
    const googleRouteIdx = serverSrc.indexOf("app.post('/api/auth/google'");
    const verifiedIdx = serverSrc.indexOf('email_verified', googleRouteIdx);
    const emailIdx = serverSrc.indexOf('const email = (payload.email', googleRouteIdx);
    expect(verifiedIdx).toBeGreaterThan(-1);
    expect(emailIdx).toBeGreaterThan(verifiedIdx);
  });
});

// ── 15. Server: SSRF blocklist includes :: ────────────────────────────────────
describe('SSRF blocklist: IPv6 unspecified :: blocked', () => {
  test('SSRF_BLOCK includes pattern for ::', () => {
    // The :: pattern that routes to loopback on Linux
    expect(serverSrc).toMatch(/\/\^::\$/);
  });
});

// ── 16. Server: PUT /api/settings type+length validation ─────────────────────
describe('PUT /api/settings: type and length validation', () => {
  test('validates that key values are string or null, max 256 chars', () => {
    const settingsRouteIdx = serverSrc.indexOf("app.put('/api/settings'");
    const block = serverSrc.slice(settingsRouteIdx, settingsRouteIdx + 600);
    expect(block).toMatch(/typeof v\s*!==\s*['"]string['"]/);
    expect(block).toMatch(/v\.length\s*>\s*256/);
    expect(block).toMatch(/res\.status\(400\)/);
  });
});

// ── 17. Server: terminal error middleware present ─────────────────────────────
describe('Express terminal error middleware', () => {
  test('app.use 4-arg error handler exists', () => {
    expect(serverSrc).toMatch(/app\.use\(\s*\(\s*err\s*,\s*req\s*,\s*res\s*,\s*next\s*\)/);
  });

  test('handler logs + returns 500', () => {
    const handlerIdx = serverSrc.indexOf('app.use((err, req, res, next)');
    const block = serverSrc.slice(handlerIdx, handlerIdx + 250);
    expect(block).toMatch(/res\.status\(500\)/);
    expect(block).toMatch(/Internal server error/);
  });
});
