// Regression for the 2026-06-03 audit P0 HIGH-PERF ship:
// marker-style and marker-size toggles must run in-place via `marker.setIcon`
// instead of full clearLayers + L.marker rebuild for 1000+ markers (300-600ms
// stall → <50ms). Cluster mode only; heat mode keeps the renderMarkers
// fallback because its individual markers aren't tracked in
// `_renderState.markerById`.
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

function makeCtx({ mapStyle = 'cluster', registry = new Map() } = {}) {
  const setIconCalls = [];
  const renderMarkersCalls = [];
  const clearLayersCalls = [];
  const addLayersCalls = [];
  const removeLayersCalls = [];
  const createIconCalls = [];

  const stateLocations = [];
  for (const [id] of registry) stateLocations.push({ id, status: 'been', category: 'restaurant' });

  const ctx = vm.createContext({
    state: { mapStyle, markerStyle: 'circle', markerSizeMode: 'default', locations: stateLocations },
    stateIndex: { locationById: new Map(stateLocations.map(l => [l.id, l])) },
    _renderState: { markerById: registry, mapStyle, markerSizeMode: 'default', markerStyle: 'circle' },
    markersLayer: {
      clearLayers: () => { clearLayersCalls.push(true); },
      addLayers: (arr) => { addLayersCalls.push(arr); },
      removeLayers: (arr) => { removeLayersCalls.push(arr); },
    },
    createMarkerIcon: (loc) => { createIconCalls.push(loc); return { __icon: true, id: loc.id }; },
    renderMarkers: () => { renderMarkersCalls.push(true); },
    localStorage: { setItem: () => {}, getItem: () => null },
    document: { getElementById: () => null },
    VALID_MARKER_STYLES: ['circle', 'squircle', 'teardrop', 'glyph', 'pill'],
    MARKER_STYLE_DESCRIPTIONS: { circle: '', squircle: '' },
    VALID_MARKER_SIZE_MODES: ['default', 'my-rating', 'google-pop', 'visits', 'bucket'],
    MARKER_SIZE_DESCRIPTIONS: { 'default': '' },
  });
  // Wire setIcon spy onto each marker
  for (const [, entry] of registry) {
    entry.marker.setIcon = (icon) => { setIconCalls.push({ marker: entry.marker, icon }); };
  }

  vm.runInContext(extractFunction('updateAllMarkerIcons'), ctx);
  vm.runInContext(extractFunction('setMarkerSizeMode'), ctx);
  vm.runInContext(extractFunction('setMarkerStyle'), ctx);

  return { ctx, spies: { setIconCalls, renderMarkersCalls, clearLayersCalls, addLayersCalls, removeLayersCalls, createIconCalls } };
}

function seedRegistry(n) {
  const reg = new Map();
  for (let i = 0; i < n; i++) {
    reg.set(`L${i}`, { marker: { _id: i }, hash: 'h' });
  }
  return reg;
}

describe('updateAllMarkerIcons — in-place setIcon path', () => {
  test('setMarkerStyle in cluster mode hits setIcon per marker, NOT clearLayers/addLayers', () => {
    const registry = seedRegistry(3);
    const { ctx, spies } = makeCtx({ mapStyle: 'cluster', registry });

    vm.runInContext(`setMarkerStyle('squircle')`, ctx);

    expect(spies.setIconCalls).toHaveLength(3);
    expect(spies.createIconCalls).toHaveLength(3);
    expect(spies.clearLayersCalls).toHaveLength(0);
    expect(spies.addLayersCalls).toHaveLength(0);
    expect(spies.renderMarkersCalls).toHaveLength(0);
    // Cache updated so subsequent renderMarkers diff doesn't see a phantom change
    expect(ctx.state.markerStyle).toBe('squircle');
    expect(ctx._renderState.markerStyle).toBe('squircle');
  });

  test('setMarkerSizeMode in cluster mode uses in-place path', () => {
    const registry = seedRegistry(5);
    const { ctx, spies } = makeCtx({ mapStyle: 'cluster', registry });

    vm.runInContext(`setMarkerSizeMode('my-rating')`, ctx);

    expect(spies.setIconCalls).toHaveLength(5);
    expect(spies.clearLayersCalls).toHaveLength(0);
    expect(spies.renderMarkersCalls).toHaveLength(0);
    expect(ctx._renderState.markerSizeMode).toBe('my-rating');
  });

  test('heat mode falls back to renderMarkers (no in-place)', () => {
    const registry = seedRegistry(2);
    const { ctx, spies } = makeCtx({ mapStyle: 'heat', registry });

    vm.runInContext(`setMarkerStyle('teardrop')`, ctx);

    expect(spies.renderMarkersCalls).toHaveLength(1);
    expect(spies.setIconCalls).toHaveLength(0);
  });

  test('empty registry falls back to renderMarkers (first paint)', () => {
    const { ctx, spies } = makeCtx({ mapStyle: 'cluster', registry: new Map() });

    vm.runInContext(`setMarkerStyle('glyph')`, ctx);

    expect(spies.renderMarkersCalls).toHaveLength(1);
    expect(spies.setIconCalls).toHaveLength(0);
  });

  test('invalid style coerces to circle + still triggers update', () => {
    const registry = seedRegistry(1);
    const { ctx, spies } = makeCtx({ mapStyle: 'cluster', registry });

    vm.runInContext(`setMarkerStyle('not-a-style')`, ctx);

    expect(ctx.state.markerStyle).toBe('circle');
    expect(spies.setIconCalls).toHaveLength(1);
  });

  test('marker with no corresponding location in stateIndex is skipped, not crashing', () => {
    const registry = seedRegistry(2);
    const { ctx, spies } = makeCtx({ mapStyle: 'cluster', registry });
    // Remove one location from the index after setup
    ctx.stateIndex.locationById.delete('L0');

    vm.runInContext(`setMarkerStyle('pill')`, ctx);

    // L0 skipped, L1 still updated
    expect(spies.setIconCalls).toHaveLength(1);
    expect(spies.renderMarkersCalls).toHaveLength(0);
  });

  test('static pin: setMarkerStyle and setMarkerSizeMode both delegate via updateAllMarkerIcons', () => {
    // The cheap-path guard must be present in BOTH handlers so the perf win
    // covers style AND size toggles.
    expect(indexHtml).toMatch(/function\s+setMarkerStyle[\s\S]{0,500}updateAllMarkerIcons\(\)/);
    expect(indexHtml).toMatch(/function\s+setMarkerSizeMode[\s\S]{0,500}updateAllMarkerIcons\(\)/);
    // updateAllMarkerIcons must actually call setIcon (the perf primitive)
    expect(indexHtml).toMatch(/function\s+updateAllMarkerIcons[\s\S]{0,600}\.setIcon\(/);
    // Old cache-bust line `_renderState.markerStyle = null` must be gone
    expect(indexHtml).not.toMatch(/_renderState\.markerStyle\s*=\s*null/);
  });
});
