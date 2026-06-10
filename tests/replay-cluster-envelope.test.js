// Replay map auto-zoom — geography-based cluster envelope (2026-06-11).
// Supersedes the earlier trip-tagged design. Two-part story:
//   1) computeReplayFrames now synthesizes a car/train/flight transit between
//      EVERY consecutive visit pair within 14 days, regardless of trip tagging
//      — so historical data without tripId still gets animated motion.
//   2) assignReplayClusters tags each frame with a clusterIdx. Boundaries:
//      a visit >500 km from the prior visit anchor starts a new cluster, and
//      flights / >500 km transits get their own cluster (envelope spans both
//      endpoints so the moving icon stays in frame across the arc).
//   3) advanceToFrame + seekReplay call _maybeZoomToClusterEnvelope on every
//      cluster change → flyToBounds (animate) or fitBounds (instant).

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

// Tiny haversine for the assign-cluster sandbox — replaces the real
// implementation so the test stays purely numerical without pulling the
// entire CATEGORIES/etc. dependency graph.
const haversineStub = `
  function haversineKm(la1, ln1, la2, ln2) {
    const R = 6371;
    const dLa = (la2 - la1) * Math.PI / 180;
    const dLn = (ln2 - ln1) * Math.PI / 180;
    const a = Math.sin(dLa/2)**2 + Math.cos(la1*Math.PI/180) * Math.cos(la2*Math.PI/180) * Math.sin(dLn/2)**2;
    return 2 * R * Math.asin(Math.sqrt(a));
  }
`;

// ── computeClusterEnvelope (pure) ────────────────────────────────────────
describe('computeClusterEnvelope (pure)', () => {
  const sandbox = {};
  vm.createContext(sandbox);
  vm.runInContext(extractFunction('computeClusterEnvelope'), sandbox);

  test('returns [] when clusterIdx is null', () => {
    const out = sandbox.computeClusterEnvelope(
      [{ kind: 'visit', clusterIdx: 0, lat: 1, lng: 2 }], null,
    );
    expect(out).toEqual([]);
  });

  test('returns [] when no frames match the cluster', () => {
    const out = sandbox.computeClusterEnvelope(
      [{ kind: 'visit', clusterIdx: 0, lat: 1, lng: 2 }], 5,
    );
    expect(out).toEqual([]);
  });

  test('collects visit lat/lng for matching cluster', () => {
    const frames = [
      { kind: 'visit', clusterIdx: 0, lat: 38.7, lng: -9.1 },
      { kind: 'visit', clusterIdx: 0, lat: 41.1, lng: -8.6 },
      { kind: 'visit', clusterIdx: 1, lat: 35.6, lng: 139.7 }, // wrong cluster
    ];
    expect(sandbox.computeClusterEnvelope(frames, 0)).toEqual([[38.7, -9.1], [41.1, -8.6]]);
  });

  test('combines visits + transits within one cluster', () => {
    const frames = [
      { kind: 'visit', clusterIdx: 0, lat: 38.7, lng: -9.1 },
      { kind: 'transit', clusterIdx: 0, fromLat: 38.7, fromLng: -9.1, toLat: 38.8, toLng: -9.2 },
    ];
    const out = sandbox.computeClusterEnvelope(frames, 0);
    expect(out).toEqual([[38.7, -9.1], [38.7, -9.1], [38.8, -9.2]]);
  });

  test('skips invalid coords', () => {
    const frames = [
      { kind: 'visit', clusterIdx: 0, lat: NaN, lng: 1 },
      { kind: 'visit', clusterIdx: 0, lat: 38.7, lng: -9.1 },
    ];
    expect(sandbox.computeClusterEnvelope(frames, 0)).toEqual([[38.7, -9.1]]);
  });

  test('returns [] when frames is not an array', () => {
    expect(sandbox.computeClusterEnvelope(null, 0)).toEqual([]);
    expect(sandbox.computeClusterEnvelope(undefined, 0)).toEqual([]);
  });
});

// ── assignReplayClusters (pure) ──────────────────────────────────────────
describe('assignReplayClusters (pure)', () => {
  const sandbox = {};
  vm.createContext(sandbox);
  vm.runInContext(haversineStub, sandbox);
  vm.runInContext(extractFunction('assignReplayClusters'), sandbox);

  test('consecutive nearby visits share cluster 0', () => {
    const frames = [
      { kind: 'visit', lat: 38.7, lng: -9.1 }, // Lisbon
      { kind: 'visit', lat: 38.71, lng: -9.12 }, // Lisbon (very close)
      { kind: 'visit', lat: 38.72, lng: -9.13 },
    ];
    sandbox.assignReplayClusters(frames);
    expect(frames.map(f => f.clusterIdx)).toEqual([0, 0, 0]);
  });

  test('visit >500 km from previous anchor starts a new cluster', () => {
    const frames = [
      { kind: 'visit', lat: 38.7, lng: -9.1 }, // Lisbon
      { kind: 'visit', lat: 35.6, lng: 139.7 }, // Tokyo — half the planet away
    ];
    sandbox.assignReplayClusters(frames);
    expect(frames[0].clusterIdx).toBe(0);
    expect(frames[1].clusterIdx).toBe(1);
  });

  test('flight transit gets its own cluster, destination visit starts another', () => {
    const frames = [
      { kind: 'visit', lat: 38.7, lng: -9.1 }, // Lisbon
      { kind: 'transit', mode: 'flight', fromLat: 38.7, fromLng: -9.1, toLat: 35.6, toLng: 139.7 },
      { kind: 'visit', lat: 35.65, lng: 139.71 }, // Tokyo destination
    ];
    sandbox.assignReplayClusters(frames);
    expect(frames[0].clusterIdx).toBe(0);
    expect(frames[1].clusterIdx).toBe(1); // flight in its own cluster
    expect(frames[2].clusterIdx).toBe(2); // destination = fresh cluster
  });

  test('short-haul car transit stays in the current cluster', () => {
    const frames = [
      { kind: 'visit', lat: 38.7, lng: -9.1 },
      { kind: 'transit', mode: 'car', fromLat: 38.7, fromLng: -9.1, toLat: 38.71, toLng: -9.12 },
      { kind: 'visit', lat: 38.72, lng: -9.13 },
    ];
    sandbox.assignReplayClusters(frames);
    expect(frames.map(f => f.clusterIdx)).toEqual([0, 0, 0]);
  });

  test('non-flight transit >500 km still splits to its own cluster', () => {
    const frames = [
      { kind: 'visit', lat: 38.7, lng: -9.1 },
      { kind: 'transit', mode: 'train', fromLat: 38.7, fromLng: -9.1, toLat: 48.8, toLng: 2.3 }, // ~1.5k km
      { kind: 'visit', lat: 48.85, lng: 2.31 },
    ];
    sandbox.assignReplayClusters(frames);
    expect(frames[1].clusterIdx).toBe(1);
    expect(frames[2].clusterIdx).toBe(2);
  });

  test('invalid coords inherit current cluster without bumping', () => {
    const frames = [
      { kind: 'visit', lat: 38.7, lng: -9.1 },
      { kind: 'visit', lat: NaN, lng: NaN },
      { kind: 'visit', lat: 38.71, lng: -9.12 },
    ];
    sandbox.assignReplayClusters(frames);
    expect(frames.map(f => f.clusterIdx)).toEqual([0, 0, 0]);
  });

  test('null/undefined frames input is a no-op', () => {
    expect(() => sandbox.assignReplayClusters(null)).not.toThrow();
    expect(() => sandbox.assignReplayClusters(undefined)).not.toThrow();
  });
});

// ── _maybeZoomToClusterEnvelope (integration with stubbed map) ───────────
describe('_maybeZoomToClusterEnvelope wiring', () => {
  function buildSandbox() {
    const calls = { flyToBounds: 0, fitBounds: 0, lastBounds: null };
    const fakeMap = {
      flyToBounds(b) { calls.flyToBounds++; calls.lastBounds = b; },
      fitBounds(b) { calls.fitBounds++; calls.lastBounds = b; },
    };
    const sandbox = {
      L: { latLngBounds(pts) { return { _pts: pts }; } },
      replayState: {
        frames: [],
        currentIdx: -1,
        currentClusterIdx: undefined,
        map: fakeMap,
      },
      calls,
    };
    vm.createContext(sandbox);
    vm.runInContext(extractFunction('computeClusterEnvelope'), sandbox);
    vm.runInContext(extractFunction('_maybeZoomToClusterEnvelope'), sandbox);
    return sandbox;
  }

  test('first frame triggers flyToBounds and updates currentClusterIdx', () => {
    const sb = buildSandbox();
    sb.replayState.frames = [
      { kind: 'visit', clusterIdx: 0, lat: 38.7, lng: -9.1 },
      { kind: 'visit', clusterIdx: 0, lat: 38.8, lng: -9.2 },
    ];
    vm.runInContext('_maybeZoomToClusterEnvelope(0, { animate: true })', sb);
    expect(sb.calls.flyToBounds).toBe(1);
    expect(sb.replayState.currentClusterIdx).toBe(0);
  });

  test('staying in same cluster does NOT re-zoom', () => {
    const sb = buildSandbox();
    sb.replayState.frames = [
      { kind: 'visit', clusterIdx: 0, lat: 1, lng: 1 },
      { kind: 'visit', clusterIdx: 0, lat: 1.01, lng: 1.01 },
    ];
    vm.runInContext('_maybeZoomToClusterEnvelope(0, { animate: true })', sb);
    vm.runInContext('_maybeZoomToClusterEnvelope(1, { animate: true })', sb);
    expect(sb.calls.flyToBounds).toBe(1);
  });

  test('crossing a flight cluster triggers a fresh zoom', () => {
    const sb = buildSandbox();
    sb.replayState.frames = [
      { kind: 'visit', clusterIdx: 0, lat: 38.7, lng: -9.1 },
      { kind: 'transit', clusterIdx: 1, mode: 'flight', fromLat: 38.7, fromLng: -9.1, toLat: 35.6, toLng: 139.7 },
      { kind: 'visit', clusterIdx: 2, lat: 35.65, lng: 139.71 },
    ];
    vm.runInContext('_maybeZoomToClusterEnvelope(0, { animate: true })', sb);
    vm.runInContext('_maybeZoomToClusterEnvelope(1, { animate: true })', sb);
    vm.runInContext('_maybeZoomToClusterEnvelope(2, { animate: true })', sb);
    expect(sb.calls.flyToBounds).toBe(3);
    // Cluster 1 envelope spans both flight endpoints — the moving icon stays in frame.
    // (Cluster 2 was set by the last call; lastBounds reflects cluster 2.)
    expect(sb.replayState.currentClusterIdx).toBe(2);
  });

  test('animate=false uses fitBounds (scrubber seek path)', () => {
    const sb = buildSandbox();
    sb.replayState.frames = [{ kind: 'visit', clusterIdx: 0, lat: 1, lng: 2 }];
    vm.runInContext('_maybeZoomToClusterEnvelope(0, { animate: false })', sb);
    expect(sb.calls.flyToBounds).toBe(0);
    expect(sb.calls.fitBounds).toBe(1);
  });

  test('out-of-range idx is a no-op', () => {
    const sb = buildSandbox();
    sb.replayState.frames = [{ kind: 'visit', clusterIdx: 0, lat: 1, lng: 2 }];
    vm.runInContext('_maybeZoomToClusterEnvelope(-1, { animate: true })', sb);
    vm.runInContext('_maybeZoomToClusterEnvelope(5, { animate: true })', sb);
    expect(sb.calls.flyToBounds).toBe(0);
  });

  test('null clusterIdx is a no-op (no currentClusterIdx update either)', () => {
    const sb = buildSandbox();
    sb.replayState.frames = [{ kind: 'visit', clusterIdx: null, lat: 1, lng: 2 }];
    vm.runInContext('_maybeZoomToClusterEnvelope(0, { animate: true })', sb);
    expect(sb.calls.flyToBounds).toBe(0);
    expect(sb.replayState.currentClusterIdx).toBeUndefined();
  });
});

// ── Source pins: hook wired into advanceToFrame + seekReplay + replayState ─
describe('replay cluster-zoom wiring (source pins)', () => {
  const html = indexHtml;

  test('advanceToFrame calls _maybeZoomToClusterEnvelope with animate:true', () => {
    const fn = extractFunction('advanceToFrame');
    expect(fn).toMatch(/_maybeZoomToClusterEnvelope\(\s*idx\s*,\s*\{\s*animate:\s*true\s*\}\s*\)/);
  });

  test('seekReplay calls _maybeZoomToClusterEnvelope with animate:false', () => {
    const fn = extractFunction('seekReplay');
    expect(fn).toMatch(/_maybeZoomToClusterEnvelope\(\s*upTo\s*,\s*\{\s*animate:\s*false\s*\}\s*\)/);
  });

  test('replayState declares currentClusterIdx (initial undefined)', () => {
    expect(html).toMatch(/currentClusterIdx:\s*undefined/);
  });

  test('rebuildReplayFrames resets currentClusterIdx', () => {
    expect(extractFunction('rebuildReplayFrames')).toMatch(/currentClusterIdx\s*=\s*undefined/);
  });

  test('playReplay end-restart resets currentClusterIdx', () => {
    expect(extractFunction('playReplay')).toMatch(/currentClusterIdx\s*=\s*undefined/);
  });

  test('seekReplay backwards-scrub resets currentClusterIdx', () => {
    expect(extractFunction('seekReplay')).toMatch(/currentClusterIdx\s*=\s*undefined/);
  });

  test('computeReplayFrames calls assignReplayClusters', () => {
    expect(extractFunction('computeReplayFrames')).toMatch(/assignReplayClusters\(all\)/);
  });
});

// ── Synthesis no longer gated by tripId ───────────────────────────────────
describe('replay car/train synthesis works without trip tagging', () => {
  const fn = extractFunction('computeReplayFrames');

  test('removes the old `if (trips.length > 0)` gate', () => {
    expect(fn).not.toMatch(/if\s*\(\s*trips\.length\s*>\s*0\s*\)/);
  });

  test('removes the old `if (!f.tripId) continue` gate inside the synthesis loop', () => {
    expect(fn).not.toMatch(/if\s*\(!\s*f\.tripId\s*\)\s*continue/);
  });

  test('the synthesis loop iterates sortedVisits chronologically (not visitsByTrip)', () => {
    expect(fn).toMatch(/const\s+sortedVisits\b/);
    expect(fn).toMatch(/sortedVisits\.length\s*-\s*1/);
  });

  test('synthesis honors a 14-day gap cap so distant visits don’t double up as a fake leg', () => {
    expect(fn).toMatch(/MAX_SYNTH_GAP_DAYS\s*=\s*14/);
  });
});

// ── Fullscreen toggle (UI + handler + ESC wiring) ─────────────────────────
describe('replay fullscreen toggle', () => {
  test('replay-fullscreen-btn button exists in the markup with the toggle handler', () => {
    expect(indexHtml).toMatch(/id="replay-fullscreen-btn"[^>]*data-click="toggleReplayFullscreen"/);
  });

  test('CSS rule defines .replay-panel.fullscreen positioning', () => {
    expect(indexHtml).toMatch(/\.replay-panel\.fullscreen\s*\{[^}]*position:\s*fixed/);
    expect(indexHtml).toMatch(/\.replay-panel\.fullscreen\s*\{[^}]*inset:\s*0/);
  });

  test('CSS rule sizes the map to fill the viewport in fullscreen', () => {
    expect(indexHtml).toMatch(/\.replay-panel\.fullscreen\s+#replay-map\s*\{[^}]*height:\s*calc\(100vh/);
  });

  test('toggleReplayFullscreen flips the class and invalidates the map size', () => {
    const fn = extractFunction('toggleReplayFullscreen');
    expect(fn).toMatch(/classList\.toggle\(\s*['"]fullscreen['"]\s*\)/);
    expect(fn).toMatch(/invalidateSize/);
  });

  test('toggleReplayFullscreen wires an Escape keydown listener to exit', () => {
    const fn = extractFunction('toggleReplayFullscreen');
    expect(fn).toMatch(/e\.key\s*!==?\s*['"]Escape['"]/);
    expect(fn).toMatch(/addEventListener\(\s*['"]keydown['"]/);
  });
});
