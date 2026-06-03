// Regression for the Regions tab country/region/city view feature.
//   1. Mode switcher toggles `regionsViewMode` + button .active state.
//   2. Country aggregation: per-region counts roll up to per-country totals.
//   3. City snap: nearest city within maxKm wins; further-than-max returns -1.
//   4. City dot radius: sqrt scale clamped to [4, 40].
//   5. Static markup pins: switcher buttons exist + color-scheme uses change event.
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

describe('regions-view: static markup pins', () => {
  test('mode switcher has 3 buttons (country/region/city) with Region default-active', () => {
    expect(indexHtml).toContain('id="regions-mode-switcher"');
    expect(indexHtml).toMatch(/data-mode="country"[^>]+data-click="setRegionsMode"/);
    expect(indexHtml).toMatch(/data-mode="city"[^>]+data-click="setRegionsMode"/);
    // Active state is on the region button (default mode).
    expect(indexHtml).toMatch(/class="filter-group-btn active"[^>]+data-mode="region"/);
    expect(indexHtml).toMatch(/data-mode="region"[^>]+data-click="setRegionsMode"/);
  });

  test('color-scheme select uses data-change (not data-click) with this.value sentinel', () => {
    // data-click on a <select> never fired — the 2026-06-02 sentinel fix only resolves
    // for `change` event. Pin the correct wiring so we don't regress to the old form.
    expect(indexHtml).toMatch(/id="region-color-scheme"[^>]+data-change="updateRegionsColorScheme"[^>]+data-arg0="this\.value"/);
  });

  test('city dataset asset is referenced (sanity check that fetch path is wired)', () => {
    expect(indexHtml).toContain("fetch('/cities.json')");
  });

  test('admin1 boundaries fetch survives (region view unchanged)', () => {
    expect(indexHtml).toContain("fetch('/admin1.json')");
  });
});

describe('aggregateRegionsByCountry — region counts roll up to country', () => {
  function makeCtx() {
    const ctx = vm.createContext({
      stateIndex: { beenLocations: [], generation: 0 },
    });
    // countLocationsByRegion stub: returns whatever the test parks on ctx.__regionStub
    vm.runInContext(`
      function countLocationsByRegion(geo) { return globalThis.__regionStub; }
    `, ctx);
    vm.runInContext(extractFunction('aggregateRegionsByCountry'), ctx);
    return ctx;
  }

  test('two regions in same country sum to one country total', () => {
    const ctx = makeCtx();
    ctx.geo = {
      features: [
        { properties: { name: 'California', country: 'USA' } },     // idx 0
        { properties: { name: 'Texas',      country: 'USA' } },     // idx 1
        { properties: { name: 'Bavaria',    country: 'Germany' } }, // idx 2
      ],
    };
    ctx.regionCounts = new Map([[0, 1], [1, 2], [2, 1]]);
    ctx.__regionStub = {
      regionCounts: ctx.regionCounts,
      regionLocs: new Map([[0, [{id:'a'}]], [1, [{id:'b'},{id:'c'}]], [2, [{id:'d'}]]]),
    };
    const result = vm.runInContext('aggregateRegionsByCountry(geo, regionCounts)', ctx);
    expect(result.countryCounts.get('USA')).toBe(3);
    expect(result.countryCounts.get('Germany')).toBe(1);
    expect(result.countryFeatures.get('USA').sort()).toEqual([0, 1]);
    expect(result.countryFeatures.get('Germany')).toEqual([2]);
    expect(result.countryLocs.get('USA').length).toBe(3);
  });

  test('feature with no country property is skipped (no crash)', () => {
    const ctx = makeCtx();
    ctx.geo = {
      features: [
        { properties: { name: 'Disputed Zone' } },                // no country
        { properties: { name: 'Lisbon', country: 'Portugal' } },
      ],
    };
    ctx.regionCounts = new Map([[0, 1], [1, 1]]);
    ctx.__regionStub = {
      regionCounts: ctx.regionCounts,
      regionLocs: new Map([[0, [{id:'x'}]], [1, [{id:'y'}]]]),
    };
    const result = vm.runInContext('aggregateRegionsByCountry(geo, regionCounts)', ctx);
    expect(result.countryCounts.get('Portugal')).toBe(1);
    expect(result.countryCounts.size).toBe(1);  // disputed zone dropped
  });

  test('zero-count regions contribute their country feature index but no visits', () => {
    const ctx = makeCtx();
    ctx.geo = {
      features: [
        { properties: { name: 'Alaska', country: 'USA' } },
        { properties: { name: 'Texas',  country: 'USA' } },
      ],
    };
    ctx.regionCounts = new Map();
    ctx.__regionStub = { regionCounts: ctx.regionCounts, regionLocs: new Map() };
    const result = vm.runInContext('aggregateRegionsByCountry(geo, regionCounts)', ctx);
    expect(result.countryCounts.size).toBe(0);
    // Feature index still populated so the choropleth can paint the country empty.
    expect(result.countryFeatures.get('USA').length).toBe(2);
  });
});

describe('snapLocationToCity — haversine nearest within maxKm', () => {
  function makeCtx() {
    const ctx = vm.createContext({});
    vm.runInContext(extractFunction('_haversineKmCity'), ctx);
    vm.runInContext(extractFunction('snapLocationToCity'), ctx);
    vm.runInContext(extractFunction('buildCitiesGrid'), ctx);
    vm.runInContext('let _citiesGrid = null;', ctx);
    return ctx;
  }

  test('point near Lisbon snaps to Lisbon (not Madrid 500km away)', () => {
    const ctx = makeCtx();
    const data = {
      cities: [
        [38.7223, -9.1393, 'Lisbon', 'PT', 545000],   // 0
        [40.4168, -3.7038, 'Madrid', 'ES', 3223000],  // 1
      ],
    };
    ctx.data = data;
    vm.runInContext('_citiesGrid = null; const grid = buildCitiesGrid(data);', ctx);
    const idx = vm.runInContext('snapLocationToCity(38.74, -9.15, data, _citiesGrid, 50)', ctx);
    expect(idx).toBe(0);  // Lisbon
  });

  test('point > maxKm from any city returns -1 (no false attribution)', () => {
    const ctx = makeCtx();
    ctx.data = { cities: [[0, 0, 'Null Island', 'XX', 1000]] };
    vm.runInContext('_citiesGrid = null; buildCitiesGrid(data);', ctx);
    // Point in middle of Atlantic, far from any city
    const idx = vm.runInContext('snapLocationToCity(30, -40, data, _citiesGrid, 50)', ctx);
    expect(idx).toBe(-1);
  });

  test('boundary search hits neighbouring 1° cells (point in cell A, nearest city in cell B)', () => {
    const ctx = makeCtx();
    // City just over the cell boundary (lat 38.001 → floor=38) and probe just under (lat 37.999 → floor=37).
    // Without 9-cell neighbour scan the bucket lookup would miss it.
    ctx.data = { cities: [[38.001, -9.0, 'BorderTown', 'PT', 1000]] };
    vm.runInContext('_citiesGrid = null; buildCitiesGrid(data);', ctx);
    const idx = vm.runInContext('snapLocationToCity(37.999, -9.0, data, _citiesGrid, 50)', ctx);
    expect(idx).toBe(0);
  });

  test('haversine sanity: London ↔ Paris ≈ 344 km (±5)', () => {
    const ctx = makeCtx();
    const km = vm.runInContext('_haversineKmCity(51.5074, -0.1278, 48.8566, 2.3522)', ctx);
    expect(km).toBeGreaterThan(339);
    expect(km).toBeLessThan(349);
  });

  test('tiered selection: tiny city right on top wins NEAREST only if big city is outside nearKm', () => {
    // Lisbon (pop 517k) sits 30km from probe; tiny village (pop 1k) sits 1km from probe.
    // With nearKm=25, no candidate is within 25km — tier-1 misses → fall back to nearest.
    // Nearest is the village.
    const ctx = makeCtx();
    ctx.data = { cities: [
      [38.50, -9.00, 'Lisbon-far', 'PT', 517000],
      [38.71, -9.13, 'VillageNear', 'PT', 1000],
    ] };
    vm.runInContext('_citiesGrid = null; buildCitiesGrid(data);', ctx);
    // probe is at 38.72, -9.14 — village is ~1km, Lisbon-far is ~26km
    const idx = vm.runInContext('snapLocationToCity(38.72, -9.14, data, _citiesGrid, 50)', ctx);
    expect(idx).toBe(1);  // VillageNear (nearest, no big-city within nearKm)
  });

  test('tiered selection: when both within nearKm, MOST POPULOUS wins (not nearest)', () => {
    // Both candidates within 25km of probe; big city is FARTHER away but bigger.
    // Tier-1 should pick the big city even though small one is closer.
    const ctx = makeCtx();
    ctx.data = { cities: [
      [40.71, -74.00, 'Megacity',   'US', 8000000],  // ~5km from probe
      [40.75, -73.98, 'Neighborhood','US', 60000],   // ~1km from probe
    ] };
    vm.runInContext('_citiesGrid = null; buildCitiesGrid(data);', ctx);
    // probe at 40.748, -73.985 (Empire State Building)
    const idx = vm.runInContext('snapLocationToCity(40.748, -73.985, data, _citiesGrid, 50)', ctx);
    expect(idx).toBe(0);  // Megacity (most populous within 25km)
  });
});

describe('cityDotRadius — sqrt scale clamped [4, 40]', () => {
  function makeCtx() {
    const ctx = vm.createContext({});
    vm.runInContext(extractFunction('cityDotRadius'), ctx);
    return ctx;
  }

  test('zero / missing pop falls back to floor radius (4)', () => {
    const ctx = makeCtx();
    expect(vm.runInContext('cityDotRadius(0, 1000000)', ctx)).toBe(4);
    expect(vm.runInContext('cityDotRadius(undefined, 1000000)', ctx)).toBe(4);
  });

  test('max-pop city hits ceiling (40)', () => {
    const ctx = makeCtx();
    // Pop == maxPop should give r = 1 * 36 + 4 = 40
    expect(vm.runInContext('cityDotRadius(22000000, 22000000)', ctx)).toBe(40);
  });

  test('mid-pop city sits between floor and ceiling', () => {
    const ctx = makeCtx();
    const r = vm.runInContext('cityDotRadius(1000000, 22000000)', ctx);
    expect(r).toBeGreaterThan(4);
    expect(r).toBeLessThan(40);
  });

  test('tiny city below sqrt floor still gets minimum 4', () => {
    const ctx = makeCtx();
    // sqrt(100)/sqrt(22M) * 36 + 4 = ~0.077 + 4 = 4.077 → clamps in via min, returns ~4
    const r = vm.runInContext('cityDotRadius(100, 22000000)', ctx);
    expect(r).toBeGreaterThanOrEqual(4);
    expect(r).toBeLessThan(5);
  });
});
