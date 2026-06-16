// Trips v2 — geocodeNarratedStop + createNarratedTrip
// Both are inline in public/index.html. We extract them into a vm sandbox,
// inject mocks for fetch/api/state/document, and assert behaviour.
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

// Minimal osmToCategory stub — return null for everything; the helper falls
// back to 'location' when no category resolved. Real osmToCategory is tested
// elsewhere (import.test.js).
const osmStub = `function osmToCategory(){ return null; }`;

function makeCtx({ fetchImpl, apiImpl, docImpl, openTripManagerImpl, renderMarkersImpl }) {
  const state = { trips: [], locations: [] };
  const toasts = [];
  const sandbox = {
    console,
    Map, Set, Array, Object, Math, JSON, Promise,
    parseFloat, parseInt, isFinite, isNaN,
    Date, RegExp, Error, Number, String, Boolean,
    setTimeout: (fn) => fn(), // run timers inline so polite gap doesn't slow the test
    fetch: fetchImpl,
    api: apiImpl,
    state,
    showToast: (msg, kind) => toasts.push({ msg, kind: kind || 'info' }),
    closeNarrateModal: () => {},
    openTripManager: openTripManagerImpl || (() => {}),
    renderMarkers: renderMarkersImpl || (() => {}),
    esc: (s) => String(s),
    mapId: (o) => ({ ...o, id: o._id || o.id }),
    document: docImpl,
    window: { _narrateParsed: null },
    _toasts: toasts,
  };
  // window is the source of _narrateParsed — but createNarratedTrip reads
  // window._narrateParsed which means the global ref must exist. Bind both.
  sandbox.window._narrateParsed = null;
  const ctx = vm.createContext(sandbox);
  const code = [
    osmStub,
    extractAsyncFunction('geocodeNarratedStop'),
    extractAsyncFunction('createNarratedTrip'),
  ].join('\n');
  vm.runInContext(code, ctx);
  return { ctx, sandbox, state, toasts };
}

const photonHit = (lat, lng, address, key, val) => ({
  ok: true,
  json: async () => ({
    features: [{
      properties: {
        street: address?.street, housenumber: address?.housenumber,
        city: address?.city, state: address?.state, country: address?.country,
        osm_key: key, osm_value: val,
      },
      geometry: { coordinates: [lng, lat] },
    }],
  }),
});
const photonMiss = () => ({ ok: true, json: async () => ({ features: [] }) });
const nominatimHit = (lat, lng, displayName) => ({
  ok: true,
  json: async () => [{ lat: String(lat), lon: String(lng), display_name: displayName, class: 'place', type: 'city' }],
});
const nominatimMiss = () => ({ ok: true, json: async () => [] });
const fetchError = () => { throw new Error('network'); };

describe('geocodeNarratedStop', () => {
  test('Photon hit returns coords + address + category fallback', async () => {
    const fetchMock = jest.fn().mockResolvedValueOnce(
      photonHit(35.6762, 139.6503, { city: 'Tokyo', country: 'Japan' }, 'place', 'city')
    );
    const { ctx } = makeCtx({ fetchImpl: fetchMock });
    const result = await vm.runInContext('geocodeNarratedStop("Tokyo")', ctx);
    expect(result).toEqual({
      lat: 35.6762, lng: 139.6503,
      address: 'Tokyo, Japan',
      category: 'location', // osmStub returns null → fallback
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toContain('photon.komoot.io');
    expect(fetchMock.mock.calls[0][0]).toContain('Tokyo');
  });

  test('Photon miss falls through to Nominatim', async () => {
    const fetchMock = jest.fn()
      .mockResolvedValueOnce(photonMiss())
      .mockResolvedValueOnce(nominatimHit(34.6937, 135.5023, 'Osaka, Japan'));
    const { ctx } = makeCtx({ fetchImpl: fetchMock });
    const result = await vm.runInContext('geocodeNarratedStop("Osaka")', ctx);
    expect(result).toEqual({
      lat: 34.6937, lng: 135.5023,
      address: 'Osaka, Japan',
      category: 'location',
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[1][0]).toContain('/api/geocode');
  });

  test('Photon error falls through to Nominatim', async () => {
    const fetchMock = jest.fn()
      .mockRejectedValueOnce(new Error('network'))
      .mockResolvedValueOnce(nominatimHit(40.7128, -74.006, 'New York, USA'));
    const { ctx } = makeCtx({ fetchImpl: fetchMock });
    const result = await vm.runInContext('geocodeNarratedStop("New York")', ctx);
    expect(result.lat).toBe(40.7128);
    expect(result.lng).toBe(-74.006);
  });

  test('Both providers miss returns null', async () => {
    const fetchMock = jest.fn()
      .mockResolvedValueOnce(photonMiss())
      .mockResolvedValueOnce(nominatimMiss());
    const { ctx } = makeCtx({ fetchImpl: fetchMock });
    const result = await vm.runInContext('geocodeNarratedStop("Atlantis")', ctx);
    expect(result).toBeNull();
  });

  test('Both providers throw returns null (never throws upward)', async () => {
    const fetchMock = jest.fn()
      .mockRejectedValueOnce(new Error('photon down'))
      .mockRejectedValueOnce(new Error('nominatim down'));
    const { ctx } = makeCtx({ fetchImpl: fetchMock });
    const result = await vm.runInContext('geocodeNarratedStop("Anywhere")', ctx);
    expect(result).toBeNull();
  });

  test('Empty name returns null without any fetch', async () => {
    const fetchMock = jest.fn();
    const { ctx } = makeCtx({ fetchImpl: fetchMock });
    const result = await vm.runInContext('geocodeNarratedStop("   ")', ctx);
    expect(result).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test('URL-encodes the query', async () => {
    const fetchMock = jest.fn().mockResolvedValueOnce(photonHit(0, 0, {}, 'place', 'city'));
    const { ctx } = makeCtx({ fetchImpl: fetchMock });
    await vm.runInContext('geocodeNarratedStop("Saint-Émilion & Cité")', ctx);
    expect(fetchMock.mock.calls[0][0]).toContain('Saint-%C3%89milion');
    expect(fetchMock.mock.calls[0][0]).toContain('%26');
  });
});

describe('createNarratedTrip — geocodes stops into bucket locations', () => {
  function setupHappy(parsed) {
    const fetchMock = jest.fn();
    parsed.stops.forEach((s, i) => {
      // Each stop: Photon hit
      fetchMock.mockResolvedValueOnce(photonHit(10 + i, 20 + i, { city: s.name, country: 'X' }, 'place', 'city'));
    });
    const apiCalls = [];
    const apiMock = jest.fn(async (method, url, body) => {
      apiCalls.push({ method, url, body });
      if (url === '/trips') return { _id: 'trip-1', name: body.name };
      if (url === '/locations') return { _id: 'loc-' + apiCalls.filter(c => c.url === '/locations').length, ...body };
      throw new Error('unexpected api ' + method + ' ' + url);
    });
    const docImpl = { getElementById: () => null };
    const { ctx, state, toasts } = makeCtx({
      fetchImpl: fetchMock,
      apiImpl: apiMock,
      docImpl,
    });
    ctx.window._narrateParsed = parsed;
    return { ctx, state, toasts, apiCalls, fetchMock };
  }

  test('creates trip then geocoded bucket locations for each stop', async () => {
    const parsed = {
      name: 'Japan Trip',
      startDate: '2026-09-20',
      endDate: '2026-09-30',
      stops: [
        { name: 'Tokyo', nights: 4 },
        { name: 'Kyoto', nights: 3 },
        { name: 'Osaka', nights: 3 },
      ],
    };
    const { ctx, state, toasts, apiCalls } = setupHappy(parsed);
    await vm.runInContext('createNarratedTrip()', ctx);
    // One trip POST + three location POSTs
    const tripCalls = apiCalls.filter(c => c.url === '/trips');
    const locCalls = apiCalls.filter(c => c.url === '/locations');
    expect(tripCalls).toHaveLength(1);
    expect(locCalls).toHaveLength(3);
    // Each location: bucket status, linked to trip, tripOrder set
    locCalls.forEach((c, i) => {
      expect(c.body.status).toBe('bucket');
      expect(c.body.tripId).toBe('trip-1');
      expect(c.body.tripOrder).toBe(i);
      expect(c.body.name).toBe(parsed.stops[i].name);
      expect(c.body.lat).toBeCloseTo(10 + i, 5);
      expect(c.body.lng).toBeCloseTo(20 + i, 5);
    });
    // state updated
    expect(state.trips).toHaveLength(1);
    expect(state.locations).toHaveLength(3);
    // Summary toast at the end
    const summary = toasts[toasts.length - 1];
    expect(summary.msg).toContain('Trip');
    expect(summary.msg).toContain('3 located');
    expect(summary.kind).toBe('success');
  });

  test('unmatched stop still POSTs a location (placeholder, no lat/lng)', async () => {
    const parsed = { name: 'Solo', stops: [{ name: 'NowhereLand' }] };
    const fetchMock = jest.fn()
      .mockResolvedValueOnce(photonMiss())
      .mockResolvedValueOnce(nominatimMiss());
    const apiCalls = [];
    const apiMock = jest.fn(async (method, url, body) => {
      apiCalls.push({ method, url, body });
      if (url === '/trips') return { _id: 'trip-2', name: body.name };
      if (url === '/locations') return { _id: 'loc-x', ...body };
    });
    const docImpl = { getElementById: () => null };
    const { ctx, toasts } = makeCtx({ fetchImpl: fetchMock, apiImpl: apiMock, docImpl });
    ctx.window._narrateParsed = parsed;
    await vm.runInContext('createNarratedTrip()', ctx);
    const locCall = apiCalls.find(c => c.url === '/locations');
    expect(locCall).toBeDefined();
    expect(locCall.body.name).toBe('NowhereLand');
    expect(locCall.body.status).toBe('bucket');
    expect(locCall.body.tripId).toBe('trip-2');
    expect(locCall.body.lat).toBeUndefined();
    expect(locCall.body.lng).toBeUndefined();
    const summary = toasts[toasts.length - 1];
    expect(summary.msg).toContain('1 unmatched');
  });

  test('trip is still created when every stop geocode misses', async () => {
    const parsed = {
      name: 'Imaginary Tour',
      stops: [{ name: 'Atlantis' }, { name: 'Shangri-La' }],
    };
    const fetchMock = jest.fn()
      .mockResolvedValueOnce(photonMiss()).mockResolvedValueOnce(nominatimMiss())
      .mockResolvedValueOnce(photonMiss()).mockResolvedValueOnce(nominatimMiss());
    const apiCalls = [];
    const apiMock = jest.fn(async (method, url, body) => {
      apiCalls.push({ method, url, body });
      if (url === '/trips') return { _id: 'trip-3', name: body.name };
      if (url === '/locations') return { _id: 'loc-y', ...body };
    });
    const docImpl = { getElementById: () => null };
    const { ctx, state, toasts } = makeCtx({ fetchImpl: fetchMock, apiImpl: apiMock, docImpl });
    ctx.window._narrateParsed = parsed;
    await vm.runInContext('createNarratedTrip()', ctx);
    expect(state.trips).toHaveLength(1);
    expect(apiCalls.filter(c => c.url === '/locations')).toHaveLength(2);
    const summary = toasts[toasts.length - 1];
    expect(summary.msg).toContain('2 unmatched');
  });

  test('failed trip POST aborts before any location is created', async () => {
    const parsed = { name: 'Doomed', stops: [{ name: 'Tokyo' }] };
    const fetchMock = jest.fn();
    const apiCalls = [];
    const apiMock = jest.fn(async (method, url, body) => {
      apiCalls.push({ method, url, body });
      if (url === '/trips') throw new Error('500 boom');
      return {};
    });
    const docImpl = { getElementById: () => null };
    const { ctx, state, toasts } = makeCtx({ fetchImpl: fetchMock, apiImpl: apiMock, docImpl });
    ctx.window._narrateParsed = parsed;
    await vm.runInContext('createNarratedTrip()', ctx);
    expect(apiCalls.filter(c => c.url === '/locations')).toHaveLength(0);
    expect(state.trips).toHaveLength(0);
    expect(fetchMock).not.toHaveBeenCalled();
    const errToast = toasts.find(t => t.kind === 'error');
    expect(errToast.msg).toContain('Failed to create trip');
  });

  test('failed individual location POST is counted as failed but loop continues', async () => {
    const parsed = {
      name: 'Half',
      stops: [{ name: 'Tokyo' }, { name: 'Kyoto' }],
    };
    const fetchMock = jest.fn()
      .mockResolvedValueOnce(photonHit(35, 139, { city: 'Tokyo' }, 'place', 'city'))
      .mockResolvedValueOnce(photonHit(35.01, 135, { city: 'Kyoto' }, 'place', 'city'));
    let locCallCount = 0;
    const apiMock = jest.fn(async (method, url, body) => {
      if (url === '/trips') return { _id: 'trip-4', name: body.name };
      if (url === '/locations') {
        locCallCount++;
        if (locCallCount === 1) throw new Error('db full');
        return { _id: 'loc-ok', ...body };
      }
    });
    const docImpl = { getElementById: () => null };
    const { ctx, state, toasts } = makeCtx({ fetchImpl: fetchMock, apiImpl: apiMock, docImpl });
    ctx.window._narrateParsed = parsed;
    await vm.runInContext('createNarratedTrip()', ctx);
    expect(state.locations).toHaveLength(1); // only the second succeeded
    const summary = toasts[toasts.length - 1];
    expect(summary.msg).toContain('2 located');
    expect(summary.msg).toContain('1 failed');
    expect(summary.kind).toBe('warn');
  });

  test('stop with date range goes into location notes', async () => {
    const parsed = {
      name: 'Dated',
      stops: [{ name: 'Tokyo', startDate: '2026-09-20', endDate: '2026-09-24' }],
    };
    const { ctx, apiCalls } = setupHappy(parsed);
    await vm.runInContext('createNarratedTrip()', ctx);
    const locCall = apiCalls.find(c => c.url === '/locations');
    expect(locCall.body.notes).toContain('2026-09-20');
    expect(locCall.body.notes).toContain('2026-09-24');
  });

  test('parsed with zero stops creates trip only, no fetches', async () => {
    const parsed = { name: 'Empty', stops: [] };
    const fetchMock = jest.fn();
    const apiCalls = [];
    const apiMock = jest.fn(async (method, url, body) => {
      apiCalls.push({ method, url, body });
      if (url === '/trips') return { _id: 'trip-empty', name: body.name };
    });
    const docImpl = { getElementById: () => null };
    const { ctx, state } = makeCtx({ fetchImpl: fetchMock, apiImpl: apiMock, docImpl });
    ctx.window._narrateParsed = parsed;
    await vm.runInContext('createNarratedTrip()', ctx);
    expect(state.trips).toHaveLength(1);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(apiCalls.filter(c => c.url === '/locations')).toHaveLength(0);
  });

  test('stops without name field are skipped (defensive)', async () => {
    const parsed = {
      name: 'Skip',
      stops: [{ name: '' }, { name: '   ' }, { name: 'Tokyo' }],
    };
    const fetchMock = jest.fn()
      .mockResolvedValueOnce(photonHit(35, 139, { city: 'Tokyo' }, 'place', 'city'));
    const apiCalls = [];
    const apiMock = jest.fn(async (method, url, body) => {
      apiCalls.push({ method, url, body });
      if (url === '/trips') return { _id: 'trip-skip', name: body.name };
      if (url === '/locations') return { _id: 'loc-tokyo', ...body };
    });
    const docImpl = { getElementById: () => null };
    const { ctx } = makeCtx({ fetchImpl: fetchMock, apiImpl: apiMock, docImpl });
    ctx.window._narrateParsed = parsed;
    await vm.runInContext('createNarratedTrip()', ctx);
    const locCalls = apiCalls.filter(c => c.url === '/locations');
    expect(locCalls).toHaveLength(1);
    expect(locCalls[0].body.name).toBe('Tokyo');
    // tripOrder reflects original index, not the skipped count
    expect(locCalls[0].body.tripOrder).toBe(2);
  });
});
