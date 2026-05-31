// _photonDiscover — Photon-backed discovery for category+near-coords.
// vm-sandbox extraction following the pattern in tests/trips-v2.test.js.
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

function extractConst(name) {
  const start = indexHtml.indexOf(`const ${name}`);
  if (start === -1) throw new Error(`Const ${name} not found`);
  let depth = 0, i = start, foundFirst = false;
  for (; i < indexHtml.length; i++) {
    if (indexHtml[i] === '{') { depth++; foundFirst = true; }
    if (indexHtml[i] === '}') depth--;
    if (indexHtml[i] === ';' && depth === 0 && foundFirst) break;
  }
  return indexHtml.substring(start, i + 1);
}

function makeCtx(fetchMock) {
  const ctx = vm.createContext({
    console, Map, Set, Array, Object, Math, JSON, Promise,
    parseFloat, parseInt, isFinite, isNaN, Date, RegExp, Error, Number, String, Boolean,
    encodeURIComponent,
    fetch: fetchMock,
  });
  const code = [
    extractFunction('haversineKm'),
    extractConst('CATEGORY_TO_OSM_TAG'),
    extractAsyncFunction('_photonDiscover'),
  ].join('\n');
  vm.runInContext(code, ctx);
  return ctx;
}

const photonResponse = (features) => ({ ok: true, json: async () => ({ features }) });
const feat = (lat, lng, props) => ({
  geometry: { coordinates: [lng, lat] },
  properties: { name: props.name || 'Unnamed', ...props },
});

describe('_photonDiscover', () => {
  test('calls Photon with the OSM tag for the category, biased to coords', async () => {
    const fetchMock = jest.fn().mockResolvedValue(photonResponse([
      feat(38.71, -9.14, { name: 'Tasca da Esquina', city: 'Lisbon', country: 'Portugal' }),
    ]));
    const ctx = makeCtx(fetchMock);
    await vm.runInContext('_photonDiscover("restaurant", 38.71, -9.14, 5)', ctx);
    const url = fetchMock.mock.calls[0][0];
    expect(url).toContain('photon.komoot.io');
    expect(url).toContain('osm_tag=amenity%3Arestaurant');
    expect(url).toContain('lat=38.71');
    expect(url).toContain('lon=-9.14');
  });

  test('returns name + lat/lng + composed address + distanceKm', async () => {
    const fetchMock = jest.fn().mockResolvedValue(photonResponse([
      feat(38.71, -9.14, { name: 'Tasca', street: 'Rua A', housenumber: '12', city: 'Lisbon', country: 'PT' }),
    ]));
    const ctx = makeCtx(fetchMock);
    const out = await vm.runInContext('_photonDiscover("restaurant", 38.71, -9.14, 5)', ctx);
    expect(out).toHaveLength(1);
    expect(out[0].name).toBe('Tasca');
    expect(out[0].lat).toBe(38.71);
    expect(out[0].lng).toBe(-9.14);
    expect(out[0].address).toBe('Rua A 12, Lisbon, PT');
    expect(out[0].distanceKm).toBeCloseTo(0, 5);
  });

  test('post-filters by radius — places > radiusKm dropped', async () => {
    const fetchMock = jest.fn().mockResolvedValue(photonResponse([
      feat(38.71, -9.14, { name: 'Near' }),     // distance 0
      feat(38.80, -9.14, { name: 'Far' }),       // ~10 km north
      feat(39.50, -9.14, { name: 'Way too far' }), // ~89 km north
    ]));
    const ctx = makeCtx(fetchMock);
    const out = await vm.runInContext('_photonDiscover("restaurant", 38.71, -9.14, 5)', ctx);
    expect(out.map(p => p.name)).toEqual(['Near']);
  });

  test('sorts by distance ascending and caps at 20', async () => {
    const features = [];
    // 25 features at increasing distance (latitude steps of ~0.005°  ≈ 0.55 km)
    for (let i = 24; i >= 0; i--) features.push(feat(38.71 + i * 0.005, -9.14, { name: 'P' + i }));
    const fetchMock = jest.fn().mockResolvedValue(photonResponse(features));
    const ctx = makeCtx(fetchMock);
    const out = await vm.runInContext('_photonDiscover("restaurant", 38.71, -9.14, 50)', ctx);
    expect(out).toHaveLength(20);
    expect(out[0].name).toBe('P0');
    expect(out[19].name).toBe('P19');
  });

  test('throws on unknown category (no OSM tag mapping)', async () => {
    const fetchMock = jest.fn();
    const ctx = makeCtx(fetchMock);
    await expect(vm.runInContext('_photonDiscover("nonsense", 0, 0, 5)', ctx)).rejects.toThrow(/No OSM tag mapping/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test('throws on non-2xx Photon response', async () => {
    const fetchMock = jest.fn().mockResolvedValue({ ok: false, status: 503 });
    const ctx = makeCtx(fetchMock);
    await expect(vm.runInContext('_photonDiscover("restaurant", 0, 0, 5)', ctx)).rejects.toThrow(/Photon 503/);
  });

  test('skips features with invalid coordinates', async () => {
    const fetchMock = jest.fn().mockResolvedValue(photonResponse([
      { geometry: { coordinates: [null, null] }, properties: { name: 'Bad' } },
      feat(38.71, -9.14, { name: 'Good' }),
    ]));
    const ctx = makeCtx(fetchMock);
    const out = await vm.runInContext('_photonDiscover("restaurant", 38.71, -9.14, 5)', ctx);
    expect(out.map(p => p.name)).toEqual(['Good']);
  });
});
