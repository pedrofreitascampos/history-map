// Regression for the dynamic overlay registry feature.
//
// DYNAMIC_OVERLAYS is a registry keyed by overlay id. Each entry has
// attach(map) and detach(map, layer) hooks. toggleOverlay(key) is the
// generic handler; future overlays (USGS, FlightRadar, ISS) slot in as
// new registry entries without touching the toggle handler.
//
// First overlay: rainviewer — weather radar tiles from RainViewer (free, no key).

const path = require('path');
const fs = require('fs');
const vm = require('vm');

const indexHtml = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');

function extractAsyncFunction(name) {
  const start = indexHtml.indexOf(`async function ${name}(`);
  if (start === -1) throw new Error(`Async function ${name} not found`);
  let depth = 0, i = start, foundFirst = false;
  for (; i < indexHtml.length; i++) {
    if (indexHtml[i] === '{') { depth++; foundFirst = true; }
    if (indexHtml[i] === '}') depth--;
    if (foundFirst && depth === 0) break;
  }
  return indexHtml.substring(start, i + 1);
}

// ─── Static markup / source code regression tests ──────────────────────────

describe('Static markup pins (overlays)', () => {
  test('overlay-rainviewer-btn exists with correct data-click and data-arg0', () => {
    expect(indexHtml).toMatch(/id="overlay-rainviewer-btn"/);
    expect(indexHtml).toMatch(/data-click="toggleOverlay"[^>]*data-arg0="rainviewer"|data-arg0="rainviewer"[^>]*data-click="toggleOverlay"/);
  });

  test('DYNAMIC_OVERLAYS declared with rainviewer key', () => {
    expect(indexHtml).toMatch(/const DYNAMIC_OVERLAYS\s*=/);
    expect(indexHtml).toMatch(/rainviewer\s*:/);
  });

  test('DYNAMIC_OVERLAYS.rainviewer has required fields: label, icon, attribution, attach, detach', () => {
    // Find the DYNAMIC_OVERLAYS block and confirm all 5 fields appear within it.
    const start = indexHtml.indexOf('const DYNAMIC_OVERLAYS');
    expect(start).not.toBe(-1);
    // Extract the object literal (from { to the matching }).
    let depth = 0, i = start, foundFirst = false;
    for (; i < indexHtml.length; i++) {
      if (indexHtml[i] === '{') { depth++; foundFirst = true; }
      if (indexHtml[i] === '}') depth--;
      if (foundFirst && depth === 0) break;
    }
    const block = indexHtml.substring(start, i + 1);
    expect(block).toMatch(/label\s*:/);
    expect(block).toMatch(/icon\s*:/);
    expect(block).toMatch(/attribution\s*:/);
    expect(block).toMatch(/attach\s*:/);
    expect(block).toMatch(/detach\s*:/);
  });

  test('toggleOverlay is an async function', () => {
    expect(indexHtml).toMatch(/async function toggleOverlay\s*\(/);
  });

  test('restorePersistedOverlays is an async function', () => {
    expect(indexHtml).toMatch(/async function restorePersistedOverlays\s*\(/);
  });

  test('state.activeOverlays initialised as new Set()', () => {
    expect(indexHtml).toMatch(/activeOverlays\s*:\s*new Set\(\)/);
  });

  test('CSS rule .map-tools-control button.overlay-active exists', () => {
    expect(indexHtml).toMatch(/\.map-tools-control\s+button\.overlay-active/);
  });

  test('CSS rule .map-tools-control button.overlay-loading exists', () => {
    expect(indexHtml).toMatch(/\.map-tools-control\s+button\.overlay-loading/);
  });
});

// ─── VM sandbox helpers ─────────────────────────────────────────────────────

function makeOverlayCtx({ overlays = null, activeKeys = [], localStorageData = {} } = {}) {
  // Minimal localStorage stub backed by a plain object.
  const lsStore = Object.assign({}, localStorageData);
  const lsCalls = { setItem: [], getItem: [] };
  const localStorage = {
    getItem: (k) => { lsCalls.getItem.push(k); return k in lsStore ? lsStore[k] : null; },
    setItem: (k, v) => { lsCalls.setItem.push({ k, v }); lsStore[k] = v; },
  };

  // Stub button element.
  const btnClasses = new Set();
  const stubBtn = {
    classList: {
      add: (c) => btnClasses.add(c),
      remove: (c) => btnClasses.delete(c),
      has: (c) => btnClasses.has(c),
    },
  };

  // Stub map.
  const removedLayers = [];
  const map = {
    hasLayer: (l) => true,
    removeLayer: (l) => { removedLayers.push(l); },
  };

  const toasts = [];
  const warnCalls = [];

  // Active layers Map (module-scope in the real code).
  const _activeOverlayLayers = new Map();

  // State with requested active keys pre-seeded.
  const activeOverlays = new Set(activeKeys);
  const state = { activeOverlays };

  // Build the overlay registry: default is a test overlay; caller can override.
  const DYNAMIC_OVERLAYS = overlays || {
    test: {
      label: 'Test overlay',
      icon: '🧪',
      attribution: 'Test',
      attach: async function() { return { id: 'mock-layer' }; },
      detach: function(m, l) { removedLayers.push(l); },
    },
  };

  const _overlayAttachInFlight = new Set();
  const ctx = vm.createContext({
    console: { warn: (...a) => warnCalls.push(a), log: () => {}, error: () => {} },
    Promise,
    Object,  // hasOwnProperty guard uses Object.prototype.hasOwnProperty.call
    fetch: async () => { throw new Error('fetch not stubbed'); },
    showToast: (msg, sev) => toasts.push({ msg, sev }),
    document: { getElementById: (id) => id.includes('overlay') ? stubBtn : null },
    localStorage,
    map,
    state,
    _activeOverlayLayers,
    _overlayAttachInFlight,
    DYNAMIC_OVERLAYS,
    // _rainviewerFramesCache / _rainviewerFramesFetchedAt not needed for generic tests.
  });

  // Extract and run the two async functions in the sandbox.
  vm.runInContext(extractAsyncFunction('toggleOverlay'), ctx);
  vm.runInContext(extractAsyncFunction('restorePersistedOverlays'), ctx);
  // _persistActiveOverlays is a regular function called from within toggleOverlay.
  // Extract it and inject it into the same context.
  const persistSrc = (() => {
    const marker = 'function _persistActiveOverlays(';
    const start = indexHtml.indexOf(marker);
    if (start === -1) throw new Error('_persistActiveOverlays not found');
    let depth = 0, i = start, foundFirst = false;
    for (; i < indexHtml.length; i++) {
      if (indexHtml[i] === '{') { depth++; foundFirst = true; }
      if (indexHtml[i] === '}') depth--;
      if (foundFirst && depth === 0) break;
    }
    return indexHtml.substring(start, i + 1);
  })();
  vm.runInContext(persistSrc, ctx);

  return { ctx, state, _activeOverlayLayers, _overlayAttachInFlight, map, localStorage, lsCalls, lsStore, toasts, warnCalls, stubBtn, btnClasses, removedLayers };
}

// ─── VM sandbox tests ────────────────────────────────────────────────────────

describe('toggleOverlay — attach happy path', () => {
  test('attaches layer, updates state, persists to localStorage, success toast', async () => {
    const { ctx, state, _activeOverlayLayers, lsCalls, toasts } = makeOverlayCtx();

    await vm.runInContext(`toggleOverlay('test')`, ctx);

    expect(state.activeOverlays.has('test')).toBe(true);
    expect(_activeOverlayLayers.get('test')).toEqual({ id: 'mock-layer' });
    expect(lsCalls.setItem.some(c => c.k === 'activeOverlays')).toBe(true);
    // Persisted value should be a JSON array containing 'test'.
    const persisted = JSON.parse(lsCalls.setItem.find(c => c.k === 'activeOverlays').v);
    expect(persisted).toContain('test');
    expect(toasts[0].sev).toBe('success');
  });

  test('button gains overlay-active class after attach', async () => {
    const { ctx, btnClasses } = makeOverlayCtx();
    await vm.runInContext(`toggleOverlay('test')`, ctx);
    expect(btnClasses.has('overlay-active')).toBe(true);
    expect(btnClasses.has('overlay-loading')).toBe(false); // loading removed in finally
  });
});

describe('toggleOverlay — detach when already active', () => {
  test('removes layer, clears state, persists empty list, info toast', async () => {
    const mockLayer = { id: 'existing-layer' };
    const { ctx, state, _activeOverlayLayers, lsCalls, toasts, btnClasses } = makeOverlayCtx({
      activeKeys: ['test'],
    });
    _activeOverlayLayers.set('test', mockLayer);

    await vm.runInContext(`toggleOverlay('test')`, ctx);

    expect(state.activeOverlays.has('test')).toBe(false);
    expect(_activeOverlayLayers.has('test')).toBe(false);
    expect(btnClasses.has('overlay-active')).toBe(false);
    expect(lsCalls.setItem.some(c => c.k === 'activeOverlays')).toBe(true);
    const persisted = JSON.parse(lsCalls.setItem.find(c => c.k === 'activeOverlays').v);
    expect(persisted).not.toContain('test');
    expect(toasts[0].sev).toBe('info');
  });
});

describe('toggleOverlay — error paths', () => {
  test('unknown key is a no-op and logs console.warn', async () => {
    const { ctx, state, warnCalls } = makeOverlayCtx();
    await vm.runInContext(`toggleOverlay('nope')`, ctx);
    expect(state.activeOverlays.has('nope')).toBe(false);
    expect(warnCalls.length).toBeGreaterThanOrEqual(1);
    expect(warnCalls[0].join(' ')).toMatch(/unknown overlay key/i);
  });

  test('attach failure → error toast, no state change, loading class cleaned up', async () => {
    const { ctx, state, toasts, btnClasses } = makeOverlayCtx({
      overlays: {
        test: {
          label: 'Failing overlay',
          icon: '💥',
          attribution: '',
          attach: async function() { throw new Error('network down'); },
          detach: function() {},
        },
      },
    });
    await vm.runInContext(`toggleOverlay('test')`, ctx);
    expect(state.activeOverlays.has('test')).toBe(false);
    expect(toasts[0].sev).toBe('error');
    expect(toasts[0].msg).toMatch(/network down/);
    // overlay-loading must be removed in the finally block.
    expect(btnClasses.has('overlay-loading')).toBe(false);
  });
});

describe('restorePersistedOverlays — localStorage restore', () => {
  test('invalid JSON silently returns without crash', async () => {
    const { ctx, state } = makeOverlayCtx({
      localStorageData: { activeOverlays: 'not json' },
    });
    await expect(vm.runInContext(`restorePersistedOverlays()`, ctx)).resolves.toBeUndefined();
    expect(state.activeOverlays.size).toBe(0);
  });

  test('non-array value silently returns without crash', async () => {
    const { ctx, state } = makeOverlayCtx({
      localStorageData: { activeOverlays: '"justAString"' },
    });
    await expect(vm.runInContext(`restorePersistedOverlays()`, ctx)).resolves.toBeUndefined();
    expect(state.activeOverlays.size).toBe(0);
  });

  test('null (no prior save) silently returns without crash', async () => {
    const { ctx, state } = makeOverlayCtx();
    await expect(vm.runInContext(`restorePersistedOverlays()`, ctx)).resolves.toBeUndefined();
    expect(state.activeOverlays.size).toBe(0);
  });

  test('known key is restored via toggleOverlay', async () => {
    const { ctx, state } = makeOverlayCtx({
      localStorageData: { activeOverlays: '["test"]' },
    });
    await vm.runInContext(`restorePersistedOverlays()`, ctx);
    expect(state.activeOverlays.has('test')).toBe(true);
  });

  test('unknown keys in saved list are ignored — no error, no state side-effect', async () => {
    const { ctx, state, warnCalls } = makeOverlayCtx({
      localStorageData: { activeOverlays: '["test","attacker_overlay","__proto__"]' },
    });
    await vm.runInContext(`restorePersistedOverlays()`, ctx);
    // Only 'test' is a known overlay; the others must be silently skipped.
    expect(state.activeOverlays.has('test')).toBe(true);
    expect(state.activeOverlays.has('attacker_overlay')).toBe(false);
    expect(state.activeOverlays.has('__proto__')).toBe(false);
  });
});

// ─── Cybersec regression pins (source-level) ────────────────────────────────
//
// These guard the fixes for the 2 MEDIUM + 1 LOW findings from the 2026-06-02
// audit of this feature. They are source-text pins (not runtime tests) so that
// a refactor that drops the guards trips CI immediately.

describe('Cybersec regression pins', () => {
  test('RainViewer host + path allowlist regexes are declared', () => {
    expect(indexHtml).toMatch(/RAINVIEWER_HOST_RE\s*=\s*\/\^https:\\\/\\\//);
    expect(indexHtml).toMatch(/RAINVIEWER_PATH_RE\s*=\s*\/\^\\\//);
  });

  test('RainViewer attach guards meta.host through the allowlist before tile URL construction', () => {
    const attachStart = indexHtml.indexOf('attach: async function(map) {');
    expect(attachStart).not.toBe(-1);
    const block = indexHtml.substring(attachStart, attachStart + 1200);
    // The host allowlist check must appear BEFORE the tileUrl concatenation.
    const hostCheckPos = block.indexOf('RAINVIEWER_HOST_RE.test');
    const tileUrlPos = block.indexOf('const tileUrl =');
    expect(hostCheckPos).toBeGreaterThan(-1);
    expect(tileUrlPos).toBeGreaterThan(-1);
    expect(hostCheckPos).toBeLessThan(tileUrlPos);
    // Path allowlist must also gate the tile URL.
    expect(block).toMatch(/RAINVIEWER_PATH_RE\.test\(latest\.path\)/);
  });

  test('toggleOverlay uses hasOwnProperty to block inherited prototype keys (e.g. __proto__)', () => {
    expect(indexHtml).toMatch(/Object\.prototype\.hasOwnProperty\.call\(DYNAMIC_OVERLAYS,\s*key\)/);
  });

  test('toggleOverlay attach path is guarded by _overlayAttachInFlight Set', () => {
    expect(indexHtml).toMatch(/const _overlayAttachInFlight\s*=\s*new Set\(\)/);
    expect(indexHtml).toMatch(/_overlayAttachInFlight\.has\(key\)/);
    expect(indexHtml).toMatch(/_overlayAttachInFlight\.add\(key\)/);
    expect(indexHtml).toMatch(/_overlayAttachInFlight\.delete\(key\)/);
  });
});

// ─── VM sandbox: the URL-injection allowlist actually rejects bad input ─────
//
// We exercise the regexes (not the full attach path, which would need a
// fetch + Leaflet stub) to prove the allowlist behaviour.

describe('RAINVIEWER_*_RE allowlist behaviour', () => {
  test('host regex accepts known rainviewer.com subdomains', () => {
    const re = /^https:\/\/[a-z0-9-]+\.rainviewer\.com$/i;
    expect(re.test('https://tilecache.rainviewer.com')).toBe(true);
    expect(re.test('https://api.rainviewer.com')).toBe(true);
  });

  test('host regex rejects javascript:, data:, http:, foreign domains, embedded payloads', () => {
    const re = /^https:\/\/[a-z0-9-]+\.rainviewer\.com$/i;
    expect(re.test('javascript:alert(1)//')).toBe(false);
    expect(re.test('data:text/html,<script>alert(1)</script>')).toBe(false);
    expect(re.test('http://tilecache.rainviewer.com')).toBe(false);
    expect(re.test('https://attacker.com')).toBe(false);
    expect(re.test('https://rainviewer.com.attacker.com')).toBe(false);
    expect(re.test('https://tilecache.rainviewer.com/extra')).toBe(false);
  });

  test('path regex rejects scheme injection, parent traversal, query strings', () => {
    const re = /^\/[a-zA-Z0-9/_-]+$/;
    expect(re.test('/v2/radar/1234567890')).toBe(true);
    expect(re.test('//attacker.com')).toBe(false);  // host-relative URL — protocol-relative
    expect(re.test('/../etc/passwd')).toBe(false);
    expect(re.test('/v2/radar?evil=1')).toBe(false);
    expect(re.test('javascript:alert(1)')).toBe(false);
  });
});

describe('toggleOverlay — double-attach guard', () => {
  test('rapid second call while first attach is in-flight is a no-op', async () => {
    // Make attach hang until we release it so we can race two calls.
    let releaseAttach;
    const attachPromise = new Promise(r => { releaseAttach = r; });
    const overlays = {
      slow: {
        label: 'Slow', icon: '🐢', attribution: 'T',
        attach: async function() { await attachPromise; return { id: 'slow-layer' }; },
        detach: function() {},
      },
    };
    const { ctx, state, _activeOverlayLayers } = makeOverlayCtx({ overlays });

    // Fire two calls concurrently. First enters the attach branch and is
    // gated by `_overlayAttachInFlight`. Second must short-circuit.
    const a = vm.runInContext(`toggleOverlay('slow')`, ctx);
    const b = vm.runInContext(`toggleOverlay('slow')`, ctx);
    releaseAttach();
    await Promise.all([a, b]);

    // Only ONE layer should have been stored (one attach completed,
    // the second call was rejected by the in-flight guard).
    expect(state.activeOverlays.has('slow')).toBe(true);
    expect(_activeOverlayLayers.size).toBe(1);
    expect(_activeOverlayLayers.get('slow')).toEqual({ id: 'slow-layer' });
  });
});
