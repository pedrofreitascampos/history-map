// Regression for the marker drag-drop relocate feature.
//
// User can grab any main-map marker, drag it, and on drop the new lat/lng
// is PUT to /api/locations/:id. Optimistic UI: loc.lat/lng update immediately,
// rollback on PUT failure (and the marker visually snaps back via setLatLng).
// Per-loc in-flight guard prevents a fast second drop from racing the first's
// PUT.

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

describe('handleMarkerDrop — optimistic relocate + rollback', () => {
  function makeCtx({ failNext = false, locId = 'loc-1', prev = { lat: 1, lng: 2 } } = {}) {
    const loc = { id: locId, lat: prev.lat, lng: prev.lng };
    const apiCalls = [];
    const toasts = [];
    const setLatLngCalls = [];
    const marker = { setLatLng: (ll) => { setLatLngCalls.push(ll); } };
    const ctx = vm.createContext({
      console, Promise, Number,
      showToast: (msg, sev) => { toasts.push({ msg, sev }); },
      api: async (method, p, body) => {
        apiCalls.push({ method, path: p, body });
        if (ctx._failNext) throw new Error('boom');
      },
    });
    ctx._failNext = failNext;
    // The in-flight Set lives at module scope — extract together.
    const setDecl = indexHtml.match(/const _dragDropInFlight = new Set\(\);/)[0];
    vm.runInContext(setDecl + '\n' + extractAsyncFunction('handleMarkerDrop'), ctx);
    return { ctx, loc, marker, apiCalls, toasts, setLatLngCalls };
  }

  test('valid drop: PUTs {lat,lng}, updates loc, success toast (no rollback)', async () => {
    const { ctx, loc, marker, apiCalls, toasts, setLatLngCalls } = makeCtx();
    ctx.marker = marker; ctx.loc = loc;
    await vm.runInContext(`handleMarkerDrop(marker, loc, { lat: 50.123, lng: -10.5 })`, ctx);
    expect(loc.lat).toBe(50.123);
    expect(loc.lng).toBe(-10.5);
    expect(apiCalls.length).toBe(1);
    expect(apiCalls[0].method).toBe('PUT');
    expect(apiCalls[0].path).toBe('/locations/loc-1');
    expect(apiCalls[0].body).toEqual({ lat: 50.123, lng: -10.5 });
    expect(toasts[0].sev).toBe('success');
    // Marker is NOT snapped back on success.
    expect(setLatLngCalls.length).toBe(0);
  });

  test('PUT failure → rollback loc.lat/lng + marker.setLatLng to prev + error toast', async () => {
    const { ctx, loc, marker, apiCalls, toasts, setLatLngCalls } = makeCtx({ failNext: true });
    ctx.marker = marker; ctx.loc = loc;
    await vm.runInContext(`handleMarkerDrop(marker, loc, { lat: 50.123, lng: -10.5 })`, ctx);
    expect(loc.lat).toBe(1);
    expect(loc.lng).toBe(2);
    expect(setLatLngCalls[0]).toEqual([1, 2]);
    expect(toasts[toasts.length - 1].sev).toBe('error');
    expect(toasts[toasts.length - 1].msg).toMatch(/Failed to move/);
  });

  test('bounds guard: lat out of [-90,90] → snap back, error, NO PUT', async () => {
    const { ctx, loc, marker, apiCalls, toasts, setLatLngCalls } = makeCtx();
    ctx.marker = marker; ctx.loc = loc;
    await vm.runInContext(`handleMarkerDrop(marker, loc, { lat: 91, lng: 0 })`, ctx);
    expect(apiCalls.length).toBe(0);
    expect(setLatLngCalls[0]).toEqual([1, 2]);
    expect(toasts[0]).toEqual({ msg: 'Invalid drop location', sev: 'error' });
    expect(loc.lat).toBe(1);
  });

  test('bounds guard: lng out of [-180,180] → snap back, error, NO PUT', async () => {
    const { ctx, loc, marker, apiCalls, toasts } = makeCtx();
    ctx.marker = marker; ctx.loc = loc;
    await vm.runInContext(`handleMarkerDrop(marker, loc, { lat: 0, lng: -181 })`, ctx);
    expect(apiCalls.length).toBe(0);
    expect(toasts[0].sev).toBe('error');
  });

  test('bounds guard: NaN lat → snap back, no PUT', async () => {
    const { ctx, loc, marker, apiCalls } = makeCtx();
    ctx.marker = marker; ctx.loc = loc;
    await vm.runInContext(`handleMarkerDrop(marker, loc, { lat: NaN, lng: 0 })`, ctx);
    expect(apiCalls.length).toBe(0);
  });

  test('concurrent double-drop: second call short-circuited by in-flight guard', async () => {
    const { ctx, loc, apiCalls } = makeCtx();
    const marker = { setLatLng: () => {} };
    ctx.marker = marker; ctx.loc = loc;
    // Make api() wait so first is still in-flight when second fires.
    let resolveFirst;
    ctx.api = (m, p, body) => {
      apiCalls.push({ method: m, path: p, body });
      return new Promise(r => { resolveFirst = r; });
    };
    const a = vm.runInContext(`handleMarkerDrop(marker, loc, { lat: 10, lng: 20 })`, ctx);
    const b = vm.runInContext(`handleMarkerDrop(marker, loc, { lat: 11, lng: 21 })`, ctx);
    resolveFirst();
    await a; await b;
    expect(apiCalls.length).toBe(1);
    // Only the FIRST drop's coords stuck.
    expect(loc.lat).toBe(10);
  });
});

describe('Static markup (regression)', () => {
  test('main-map marker construction passes draggable: true', () => {
    // All 4 main-render-path L.marker(...) calls use the draggable option.
    const matches = indexHtml.match(/L\.marker\(\[loc\.lat, loc\.lng\], \{ icon: createMarkerIcon\(loc\), draggable: true \}\)/g) || [];
    expect(matches.length).toBe(4);
  });

  test('bindMarkerBehavior wires dragend → handleMarkerDrop', () => {
    expect(indexHtml).toMatch(/marker\.on\('dragend'[\s\S]{0,200}handleMarkerDrop\(marker, loc/);
  });

  test('handleMarkerDrop function exists with in-flight Set guard', () => {
    expect(indexHtml).toMatch(/const _dragDropInFlight = new Set\(\);/);
    expect(indexHtml).toMatch(/async function handleMarkerDrop\(marker, loc, newLatLng\)/);
    expect(indexHtml).toMatch(/_dragDropInFlight\.has\(loc\.id\)/);
  });
});
