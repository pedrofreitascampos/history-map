// Context-aware Discover — trip centroid seeding + missing-category chips.

const path = require('path');
const fs = require('fs');
const vm = require('vm');

const indexHtml = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');

function extractFunction(name) {
  const start = indexHtml.indexOf(`function ${name}(`);
  if (start === -1) throw new Error(`Function ${name} not found`);
  let depth = 0, i = start, found = false;
  for (; i < indexHtml.length; i++) {
    if (indexHtml[i] === '{') { depth++; found = true; }
    if (indexHtml[i] === '}') depth--;
    if (found && depth === 0) break;
  }
  return indexHtml.substring(start, i + 1);
}

// ── Static markup ─────────────────────────────────────────────────────────
describe('Context-aware Discover — static markup', () => {
  test('#discover-trip-context div exists in discover modal', () => {
    expect(indexHtml).toContain('id="discover-trip-context"');
  });

  test('#discover-trip-context starts hidden', () => {
    const idx = indexHtml.indexOf('id="discover-trip-context"');
    const tag = indexHtml.slice(idx, idx + 120);
    expect(tag).toContain('display:none');
  });

  test('_tripCentroid function defined', () => {
    expect(indexHtml).toContain('function _tripCentroid(');
  });

  test('setDiscoverCategory function defined', () => {
    expect(indexHtml).toContain('function setDiscoverCategory(');
  });

  test('openDiscoverModal references _tripCentroid', () => {
    const fn = extractFunction('openDiscoverModal');
    expect(fn).toContain('_tripCentroid');
  });

  test('openDiscoverModal reads trip-selector value', () => {
    const fn = extractFunction('openDiscoverModal');
    expect(fn).toContain('trip-selector');
  });

  test('openDiscoverModal sets discover-radius', () => {
    const fn = extractFunction('openDiscoverModal');
    expect(fn).toContain('discover-radius');
  });

  test('openDiscoverModal pans map with setView', () => {
    const fn = extractFunction('openDiscoverModal');
    expect(fn).toContain('setView');
  });

  test('setDiscoverCategory targets discover-category select', () => {
    const fn = extractFunction('setDiscoverCategory');
    expect(fn).toContain('discover-category');
  });

  test('setDiscoverCategory chip uses data-click="setDiscoverCategory"', () => {
    const fn = extractFunction('openDiscoverModal');
    expect(fn).toContain('data-click="setDiscoverCategory"');
  });
});

// ── _tripCentroid (vm) ────────────────────────────────────────────────────
function runCentroid(locs) {
  const code = [
    extractFunction('_tripCentroid'),
    `__r = _tripCentroid(${JSON.stringify(locs)});`,
  ].join('\n');
  const ctx = vm.createContext({ Math, Array, Number, __r: null });
  vm.runInContext(code, ctx);
  return ctx.__r;
}

describe('Context-aware Discover — _tripCentroid', () => {
  test('single location → centroid equals that location', () => {
    const r = runCentroid([{ lat: 48.858, lng: 2.294 }]);
    expect(r.lat).toBeCloseTo(48.858, 4);
    expect(r.lng).toBeCloseTo(2.294, 4);
  });

  test('two locations → midpoint', () => {
    const r = runCentroid([{ lat: 0, lng: 0 }, { lat: 2, lng: 4 }]);
    expect(r.lat).toBeCloseTo(1, 4);
    expect(r.lng).toBeCloseTo(2, 4);
  });

  test('three locations → average', () => {
    const r = runCentroid([
      { lat: 48.858, lng: 2.294 },
      { lat: 48.860, lng: 2.296 },
      { lat: 48.862, lng: 2.298 },
    ]);
    expect(r.lat).toBeCloseTo(48.86, 2);
    expect(r.lng).toBeCloseTo(2.296, 2);
  });

  test('empty array → null', () => {
    expect(runCentroid([])).toBeNull();
  });

  test('filters out NaN coords', () => {
    const r = runCentroid([
      { lat: NaN, lng: NaN },
      { lat: 10, lng: 20 },
    ]);
    expect(r.lat).toBeCloseTo(10, 4);
    expect(r.lng).toBeCloseTo(20, 4);
  });

  test('all NaN coords → null', () => {
    expect(runCentroid([{ lat: NaN, lng: NaN }])).toBeNull();
  });
});
