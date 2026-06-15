// Graph view on Atlas (#12).
// Static markup + _buildGraphSequence logic.

const path = require('path');
const fs = require('fs');
const vm = require('vm');

const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');

function extractFunction(name) {
  const start = html.indexOf(`function ${name}(`);
  if (start === -1) throw new Error(`Function ${name} not found`);
  let depth = 0, i = start, found = false;
  for (; i < html.length; i++) {
    if (html[i] === '{') { depth++; found = true; }
    if (html[i] === '}') depth--;
    if (found && depth === 0) break;
  }
  return html.substring(start, i + 1);
}

// ── Static markup ─────────────────────────────────────────────────────────
describe('Graph view — static markup', () => {
  test('#graph-btn button exists', () => {
    expect(html).toContain('id="graph-btn"');
  });

  test('graph-btn wired to toggleGraphMode', () => {
    expect(html).toMatch(/id="graph-btn"[^>]*data-click="toggleGraphMode"/);
  });

  test('#graph-panel exists', () => {
    expect(html).toContain('id="graph-panel"');
  });

  test('#graph-status exists', () => {
    expect(html).toContain('id="graph-status"');
  });

  test('_graphMode state variable declared', () => {
    expect(html).toMatch(/let _graphMode\s*=\s*false/);
  });

  test('_graphLayers state variable declared', () => {
    expect(html).toMatch(/let _graphLayers\s*=\s*\[\]/);
  });

  test('_graphPrevTile state variable declared', () => {
    expect(html).toMatch(/let _graphPrevTile\s*=\s*null/);
  });

  test('_buildGraphSequence function defined', () => {
    expect(html).toContain('function _buildGraphSequence(');
  });

  test('toggleGraphMode function defined', () => {
    expect(html).toContain('function toggleGraphMode(');
  });

  test('drawGraph function defined', () => {
    expect(html).toContain('function drawGraph(');
  });

  test('clearGraph function defined', () => {
    expect(html).toContain('function clearGraph(');
  });

  test('_getActiveTileKey function defined', () => {
    expect(html).toContain('function _getActiveTileKey(');
  });

  test('graph-panel has aria-label', () => {
    expect(html).toMatch(/id="graph-panel"[^>]*aria-label/);
  });

  test('graph-panel is inside map-view', () => {
    const mapView = html.match(/id="map-view"[\s\S]*?(?=id="sidebar")/);
    expect(mapView).not.toBeNull();
    expect(mapView[0]).toContain('id="graph-panel"');
  });

  test('toggleGraphMode switches to dark tile', () => {
    const fn = extractFunction('toggleGraphMode');
    expect(fn).toContain('dark');
    expect(fn).toContain('_tileLayers');
  });

  test('toggleGraphMode restores previous tile on exit', () => {
    const fn = extractFunction('toggleGraphMode');
    expect(fn).toContain('_graphPrevTile');
  });

  test('drawGraph uses SVG marker-end for arrows', () => {
    const fn = extractFunction('drawGraph');
    expect(fn).toContain('marker-end');
    expect(fn).toContain('graph-arrow');
  });

  test('drawGraph deduplicates nodes by coordinates', () => {
    const fn = extractFunction('drawGraph');
    expect(fn).toContain('seen');
    expect(fn).toContain('toFixed');
  });
});

// ── _buildGraphSequence logic (vm) ────────────────────────────────────────
function runBuildGraphSequence(locations) {
  const code = [
    extractFunction('_buildGraphSequence'),
    `__result = _buildGraphSequence();`,
  ].join('\n');
  const ctx = vm.createContext({ state: { locations }, Array, Math, JSON, __result: null });
  vm.runInContext(code, ctx);
  return ctx.__result;
}

describe('Graph view — _buildGraphSequence', () => {
  test('returns empty array when no locations', () => {
    const result = runBuildGraphSequence([]);
    expect(result).toEqual([]);
  });

  test('excludes bucket-status locations', () => {
    const locs = [{ status: 'bucket', lat: 38.7, lng: -9.1, visits: [{ date: '2024-01-01' }], name: 'Wish' }];
    const result = runBuildGraphSequence(locs);
    expect(result).toHaveLength(0);
  });

  test('excludes locations without lat/lng', () => {
    const locs = [{ status: 'been', lat: null, lng: null, visits: [{ date: '2024-01-01' }], name: 'No coords' }];
    const result = runBuildGraphSequence(locs);
    expect(result).toHaveLength(0);
  });

  test('excludes needsApproval locations', () => {
    const locs = [{ status: 'been', lat: 38.7, lng: -9.1, needsApproval: true, visits: [{ date: '2024-01-01' }], name: 'Pending' }];
    const result = runBuildGraphSequence(locs);
    expect(result).toHaveLength(0);
  });

  test('includes location with visit dates', () => {
    const locs = [{ status: 'been', lat: 38.7, lng: -9.1, visits: [{ date: '2024-03-15' }], name: 'Lisbon' }];
    const result = runBuildGraphSequence(locs);
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('Lisbon');
    expect(result[0].date).toBe('2024-03-15');
    expect(result[0].lat).toBe(38.7);
    expect(result[0].lng).toBe(-9.1);
  });

  test('falls back to createdAt when visits array is empty', () => {
    const locs = [{ status: 'been', lat: 40.4, lng: -3.7, visits: [], createdAt: '2023-06-01', name: 'Madrid' }];
    const result = runBuildGraphSequence(locs);
    expect(result).toHaveLength(1);
    expect(result[0].date).toBe('2023-06-01');
  });

  test('expands multiple visits per location into separate entries', () => {
    const locs = [{
      status: 'been', lat: 38.7, lng: -9.1,
      visits: [{ date: '2023-01-10' }, { date: '2024-05-20' }],
      name: 'Lisbon'
    }];
    const result = runBuildGraphSequence(locs);
    expect(result).toHaveLength(2);
  });

  test('sorts entries chronologically by date', () => {
    const locs = [
      { status: 'been', lat: 40.4, lng: -3.7, visits: [{ date: '2024-06-01' }], name: 'Madrid' },
      { status: 'been', lat: 38.7, lng: -9.1, visits: [{ date: '2023-03-15' }], name: 'Lisbon' },
      { status: 'been', lat: 41.9, lng: 12.5, visits: [{ date: '2024-01-10' }], name: 'Rome' },
    ];
    const result = runBuildGraphSequence(locs);
    expect(result[0].name).toBe('Lisbon');
    expect(result[1].name).toBe('Rome');
    expect(result[2].name).toBe('Madrid');
  });

  test('skips visits without a date field', () => {
    const locs = [{
      status: 'been', lat: 38.7, lng: -9.1,
      visits: [{ date: '2024-01-01' }, { notes: 'no date' }],
      name: 'Lisbon'
    }];
    const result = runBuildGraphSequence(locs);
    expect(result).toHaveLength(1);
  });

  test('handles multiple locations correctly', () => {
    const locs = [
      { status: 'been', lat: 38.7, lng: -9.1, visits: [{ date: '2023-01-01' }], name: 'Lisbon' },
      { status: 'been', lat: 40.4, lng: -3.7, visits: [{ date: '2023-02-01' }], name: 'Madrid' },
      { status: 'bucket', lat: 48.8, lng: 2.3, visits: [{ date: '2023-03-01' }], name: 'Paris' },
    ];
    const result = runBuildGraphSequence(locs);
    expect(result).toHaveLength(2);
    expect(result.map(r => r.name)).toEqual(['Lisbon', 'Madrid']);
  });
});
