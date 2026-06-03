// Replay map auto-zooms to the next trip's envelope (2026-06-04).
// User ask: when the replay advances from one trip to another, the map
// should fly/fit to a bounding box that covers the new trip's visits +
// transit endpoints. Staying inside the same trip = no zoom; entering a
// frame with tripId=null = stay where we are.

const path = require('path');
const fs = require('fs');
const vm = require('vm');

const indexHtml = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');

function extractFunction(name) {
  const start = indexHtml.indexOf(`function ${name}(`);
  if (start === -1) throw new Error(`Function ${name} not found`);
  let depth = 0, i = start, foundFirst = false;
  for (; i < indexHtml.length; i++) {
    if (indexHtml[i] === '{') { depth++; foundFirst = true; }
    if (indexHtml[i] === '}') depth--;
    if (foundFirst && depth === 0) break;
  }
  return indexHtml.substring(start, i + 1);
}

// ── Pure helper: computeTripEnvelope(frames, tripId) ───────────────────
describe('computeTripEnvelope (pure)', () => {
  const sandbox = {};
  vm.createContext(sandbox);
  vm.runInContext(extractFunction('computeTripEnvelope'), sandbox);

  test('returns [] when tripId is null', () => {
    const out = sandbox.computeTripEnvelope(
      [{ kind: 'visit', tripId: 'A', lat: 1, lng: 2 }],
      null,
    );
    expect(out).toEqual([]);
  });

  test('returns [] when tripId is undefined', () => {
    const out = sandbox.computeTripEnvelope(
      [{ kind: 'visit', tripId: 'A', lat: 1, lng: 2 }],
      undefined,
    );
    expect(out).toEqual([]);
  });

  test('returns [] when no frames match', () => {
    const out = sandbox.computeTripEnvelope(
      [{ kind: 'visit', tripId: 'A', lat: 1, lng: 2 }],
      'B',
    );
    expect(out).toEqual([]);
  });

  test('returns [] when frames is not an array', () => {
    expect(sandbox.computeTripEnvelope(null, 'A')).toEqual([]);
    expect(sandbox.computeTripEnvelope(undefined, 'A')).toEqual([]);
  });

  test('collects visit lat/lng for matching trip', () => {
    const frames = [
      { kind: 'visit', tripId: 'A', lat: 38.7, lng: -9.1 },
      { kind: 'visit', tripId: 'A', lat: 41.1, lng: -8.6 },
      { kind: 'visit', tripId: 'B', lat: 35.6, lng: 139.7 }, // wrong trip
    ];
    const out = sandbox.computeTripEnvelope(frames, 'A');
    expect(out).toEqual([[38.7, -9.1], [41.1, -8.6]]);
  });

  test('collects transit endpoints for matching trip', () => {
    const frames = [
      { kind: 'transit', tripId: 'A', fromLat: 38.7, fromLng: -9.1, toLat: 48.8, toLng: 2.3 },
    ];
    const out = sandbox.computeTripEnvelope(frames, 'A');
    expect(out).toEqual([[38.7, -9.1], [48.8, 2.3]]);
  });

  test('combines visits + transits in one trip envelope', () => {
    const frames = [
      { kind: 'visit', tripId: 'A', lat: 38.7, lng: -9.1 },
      { kind: 'transit', tripId: 'A', fromLat: 38.7, fromLng: -9.1, toLat: 48.8, toLng: 2.3 },
      { kind: 'visit', tripId: 'A', lat: 48.8, lng: 2.3 },
    ];
    const out = sandbox.computeTripEnvelope(frames, 'A');
    expect(out).toHaveLength(4);
    expect(out).toContainEqual([38.7, -9.1]);
    expect(out).toContainEqual([48.8, 2.3]);
  });

  test('skips invalid coords (NaN, undefined)', () => {
    const frames = [
      { kind: 'visit', tripId: 'A', lat: NaN, lng: -9.1 },
      { kind: 'visit', tripId: 'A', lat: 38.7, lng: -9.1 },
      { kind: 'transit', tripId: 'A', fromLat: 1, fromLng: 2, toLat: undefined, toLng: 4 },
    ];
    const out = sandbox.computeTripEnvelope(frames, 'A');
    // Valid: visit (38.7,-9.1), transit from (1,2). Transit's to side dropped.
    expect(out).toEqual([[38.7, -9.1], [1, 2]]);
  });

  test('ignores frames with matching tripId but unknown kind', () => {
    const frames = [
      { kind: 'visit', tripId: 'A', lat: 1, lng: 2 },
      { kind: 'mystery', tripId: 'A', lat: 5, lng: 6 },
    ];
    expect(sandbox.computeTripEnvelope(frames, 'A')).toEqual([[1, 2]]);
  });
});

// ── Integration: _maybeZoomToTripEnvelope hook through advanceToFrame ──
describe('_maybeZoomToTripEnvelope wiring', () => {
  // Stand up a JSDOM-free sandbox that mocks the bits Leaflet would supply.
  // We extract the helper + its caller and check the trip-change semantics:
  // first frame of trip A → fitBounds called; mid-trip frames → no call;
  // crossing into trip B → fitBounds called again; null tripId → no call.

  function buildSandbox() {
    const calls = { flyToBounds: 0, fitBounds: 0, lastBounds: null };
    const fakeMap = {
      flyToBounds(b) { calls.flyToBounds++; calls.lastBounds = b; },
      fitBounds(b) { calls.fitBounds++; calls.lastBounds = b; },
    };
    const sandbox = {
      L: {
        // Leaflet's latLngBounds accepts an array of [lat,lng]; we just
        // pass through so the test can inspect the points.
        latLngBounds(pts) { return { _pts: pts }; },
      },
      replayState: {
        frames: [],
        currentIdx: -1,
        renderedUpTo: -1,
        currentTripId: undefined,
        map: fakeMap,
        markersLayer: { addLayer() {}, clearLayers() {}, removeLayer() {} },
        polylineLayer: { addLayer() {}, clearLayers() {} },
        pathLines: { old: null, mid: null, recent: null },
        lastBoundaries: { oldEnd: -1, midEnd: -1, total: -1 },
      },
      document: {
        getElementById() { return null; },
      },
      // Stubbed-out helpers advanceToFrame depends on.
      buildReplayMarker() { return null; },
      buildReplayTransitLine() { return []; },
      renderReplayPath() {},
      updateReplayPositionLabel() {},
      calls,
    };
    vm.createContext(sandbox);
    vm.runInContext(extractFunction('computeTripEnvelope'), sandbox);
    vm.runInContext(extractFunction('_maybeZoomToTripEnvelope'), sandbox);
    return sandbox;
  }

  test('first frame in trip A triggers flyToBounds (animate)', () => {
    const sb = buildSandbox();
    sb.replayState.frames = [
      { kind: 'visit', tripId: 'A', lat: 38.7, lng: -9.1 },
      { kind: 'visit', tripId: 'A', lat: 41.1, lng: -8.6 },
    ];
    vm.runInContext(`_maybeZoomToTripEnvelope(0, { animate: true })`, sb);
    expect(sb.calls.flyToBounds).toBe(1);
    expect(sb.calls.fitBounds).toBe(0);
    expect(sb.replayState.currentTripId).toBe('A');
    expect(sb.calls.lastBounds._pts).toEqual([[38.7, -9.1], [41.1, -8.6]]);
  });

  test('staying in trip A — no second zoom', () => {
    const sb = buildSandbox();
    sb.replayState.frames = [
      { kind: 'visit', tripId: 'A', lat: 38.7, lng: -9.1 },
      { kind: 'visit', tripId: 'A', lat: 41.1, lng: -8.6 },
    ];
    vm.runInContext(`_maybeZoomToTripEnvelope(0, { animate: true })`, sb);
    vm.runInContext(`_maybeZoomToTripEnvelope(1, { animate: true })`, sb);
    expect(sb.calls.flyToBounds).toBe(1); // Still just the first call.
  });

  test('crossing from trip A to trip B triggers a fresh zoom', () => {
    const sb = buildSandbox();
    sb.replayState.frames = [
      { kind: 'visit', tripId: 'A', lat: 38.7, lng: -9.1 },
      { kind: 'visit', tripId: 'B', lat: 35.6, lng: 139.7 },
      { kind: 'visit', tripId: 'B', lat: 34.9, lng: 135.7 },
    ];
    vm.runInContext(`_maybeZoomToTripEnvelope(0, { animate: true })`, sb);
    expect(sb.calls.flyToBounds).toBe(1);
    expect(sb.replayState.currentTripId).toBe('A');
    vm.runInContext(`_maybeZoomToTripEnvelope(1, { animate: true })`, sb);
    expect(sb.calls.flyToBounds).toBe(2);
    expect(sb.replayState.currentTripId).toBe('B');
    expect(sb.calls.lastBounds._pts).toEqual([[35.6, 139.7], [34.9, 135.7]]);
  });

  test('entering null-tripId frame updates currentTripId but does NOT zoom', () => {
    const sb = buildSandbox();
    sb.replayState.frames = [
      { kind: 'visit', tripId: 'A', lat: 38.7, lng: -9.1 },
      { kind: 'visit', tripId: null, lat: 0, lng: 0 },
    ];
    vm.runInContext(`_maybeZoomToTripEnvelope(0, { animate: true })`, sb);
    expect(sb.calls.flyToBounds).toBe(1);
    vm.runInContext(`_maybeZoomToTripEnvelope(1, { animate: true })`, sb);
    expect(sb.calls.flyToBounds).toBe(1); // No new zoom.
    expect(sb.replayState.currentTripId).toBe(null);
  });

  test('animate=false uses fitBounds (seek path)', () => {
    const sb = buildSandbox();
    sb.replayState.frames = [
      { kind: 'visit', tripId: 'A', lat: 38.7, lng: -9.1 },
    ];
    vm.runInContext(`_maybeZoomToTripEnvelope(0, { animate: false })`, sb);
    expect(sb.calls.flyToBounds).toBe(0);
    expect(sb.calls.fitBounds).toBe(1);
  });

  test('no map = no zoom, no crash', () => {
    const sb = buildSandbox();
    sb.replayState.frames = [{ kind: 'visit', tripId: 'A', lat: 1, lng: 2 }];
    sb.replayState.map = null;
    expect(() => vm.runInContext(`_maybeZoomToTripEnvelope(0, { animate: true })`, sb)).not.toThrow();
    expect(sb.calls.flyToBounds).toBe(0);
    expect(sb.calls.fitBounds).toBe(0);
  });

  test('out-of-range idx is a no-op', () => {
    const sb = buildSandbox();
    sb.replayState.frames = [{ kind: 'visit', tripId: 'A', lat: 1, lng: 2 }];
    vm.runInContext(`_maybeZoomToTripEnvelope(-1, { animate: true })`, sb);
    vm.runInContext(`_maybeZoomToTripEnvelope(5, { animate: true })`, sb);
    expect(sb.calls.flyToBounds).toBe(0);
    expect(sb.calls.fitBounds).toBe(0);
  });

  test('empty envelope (matching trip but invalid coords) leaves map untouched', () => {
    const sb = buildSandbox();
    sb.replayState.frames = [
      { kind: 'visit', tripId: 'A', lat: NaN, lng: NaN },
    ];
    vm.runInContext(`_maybeZoomToTripEnvelope(0, { animate: true })`, sb);
    expect(sb.calls.flyToBounds).toBe(0);
    expect(sb.calls.fitBounds).toBe(0);
    // currentTripId still updates so a subsequent same-trip frame is a no-op.
    expect(sb.replayState.currentTripId).toBe('A');
  });
});

// ── Source-level pins: hook is wired into both advanceToFrame and seekReplay ──
describe('replay zoom hook wiring (source pins)', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');

  test('advanceToFrame calls _maybeZoomToTripEnvelope with animate:true', () => {
    const fn = extractFunction('advanceToFrame');
    expect(fn).toMatch(/_maybeZoomToTripEnvelope\(\s*idx\s*,\s*\{\s*animate:\s*true\s*\}\s*\)/);
  });

  test('seekReplay calls _maybeZoomToTripEnvelope with animate:false', () => {
    const fn = extractFunction('seekReplay');
    expect(fn).toMatch(/_maybeZoomToTripEnvelope\(\s*upTo\s*,\s*\{\s*animate:\s*false\s*\}\s*\)/);
  });

  test('replayState declares currentTripId (initial undefined)', () => {
    expect(html).toMatch(/currentTripId:\s*undefined/);
  });

  test('rebuildReplayFrames resets currentTripId so reload triggers a fresh fit', () => {
    const fn = extractFunction('rebuildReplayFrames');
    expect(fn).toMatch(/replayState\.currentTripId\s*=\s*undefined/);
  });

  test('playReplay end-restart resets currentTripId so the re-play re-zooms', () => {
    const fn = extractFunction('playReplay');
    expect(fn).toMatch(/replayState\.currentTripId\s*=\s*undefined/);
  });

  test('seekReplay backwards-scrub resets currentTripId', () => {
    const fn = extractFunction('seekReplay');
    expect(fn).toMatch(/replayState\.currentTripId\s*=\s*undefined/);
  });
});
