// Regression for the 2026-06-03 audit P0 HIGH-LIVE mobile-UX batch:
//   1. Save-modal lat/lng dead-end — quickAddPlace fires Photon auto-geocode;
//      saveLocation unhides the (default-hidden) lat/lng row + focuses it
//      when coords missing, instead of just toasting "fill in lat and lng"
//      while the fields are invisible.
//   2. Mobile sidebar covers full viewport — auto-collapse on ≤480px
//      viewport when the user has no saved preference, so the map is
//      visible on first load. Explicit user toggle still wins thereafter.
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

describe('Save-modal lat/lng — auto-geocode + unhide on fail', () => {
  function makeAutoGeoCtx({ editingId = null, name = 'Eiffel Tower', latVal = '', lngVal = '', addressVal = '', fetchImpl = null } = {}) {
    const elements = {
      'loc-lat': { value: latVal, focus: () => { elements['loc-lat'].focused = true; }, scrollIntoView: () => { elements['loc-lat'].scrolled = true; } },
      'loc-lng': { value: lngVal },
      'loc-name': { value: name },
      'loc-address': { value: addressVal },
      'loc-coords-row': { id: 'loc-coords-row', style: { display: 'none' } },
    };
    const ctx = vm.createContext({
      state: { editingId },
      document: { getElementById: (id) => elements[id] || null },
      fetch: fetchImpl || (() => Promise.resolve({ ok: false, json: () => Promise.resolve({}) })),
      Promise,
      Number,
    });
    vm.runInContext(extractAsyncFunction('_autoGeocodeAddModalIfNeeded'), ctx);
    vm.runInContext(extractFunction('_unhideLocCoordsRow'), ctx);
    return { ctx, elements };
  }

  // Mock /api/geocode returning Nominatim-format array
  function mockGeocodeOk(hit) {
    return () => Promise.resolve({
      ok: true,
      json: () => Promise.resolve(hit ? [hit] : []),
    });
  }

  test('_autoGeocodeAddModalIfNeeded fills lat/lng + address from geocode proxy', async () => {
    const fetchImpl = mockGeocodeOk({
      lat: '48.8584', lon: '2.2945',
      display_name: 'Eiffel Tower, Champ de Mars, Paris, France',
    });
    const { ctx, elements } = makeAutoGeoCtx({ name: 'Eiffel Tower', fetchImpl });
    await vm.runInContext(`_autoGeocodeAddModalIfNeeded()`, ctx);
    expect(elements['loc-lat'].value).toBe(48.8584);
    expect(elements['loc-lng'].value).toBe(2.2945);
    expect(elements['loc-address'].value).toContain('Paris');
  });

  test('_autoGeocodeAddModalIfNeeded skipped when editing', async () => {
    let called = false;
    const fetchImpl = () => { called = true; return Promise.resolve({ ok: true, json: () => Promise.resolve([]) }); };
    const { ctx } = makeAutoGeoCtx({ editingId: 'X1', fetchImpl });
    await vm.runInContext(`_autoGeocodeAddModalIfNeeded()`, ctx);
    expect(called).toBe(false);
  });

  test('_autoGeocodeAddModalIfNeeded skipped when both coords already set', async () => {
    let called = false;
    const fetchImpl = () => { called = true; return Promise.resolve({ ok: true, json: () => Promise.resolve([]) }); };
    const { ctx } = makeAutoGeoCtx({ name: 'X', latVal: '10', lngVal: '20', fetchImpl });
    await vm.runInContext(`_autoGeocodeAddModalIfNeeded()`, ctx);
    expect(called).toBe(false);
  });

  test('_autoGeocodeAddModalIfNeeded skipped when name empty', async () => {
    let called = false;
    const fetchImpl = () => { called = true; return Promise.resolve({ ok: true, json: () => Promise.resolve([]) }); };
    const { ctx } = makeAutoGeoCtx({ name: '', fetchImpl });
    await vm.runInContext(`_autoGeocodeAddModalIfNeeded()`, ctx);
    expect(called).toBe(false);
  });

  test('_autoGeocodeAddModalIfNeeded handles network failure gracefully', async () => {
    const fetchImpl = () => Promise.reject(new Error('network error'));
    const { ctx, elements } = makeAutoGeoCtx({ fetchImpl });
    await vm.runInContext(`_autoGeocodeAddModalIfNeeded()`, ctx);
    expect(elements['loc-lat'].value).toBe('');
  });

  test('_autoGeocodeAddModalIfNeeded handles empty results array', async () => {
    const fetchImpl = mockGeocodeOk(null);
    const { ctx, elements } = makeAutoGeoCtx({ fetchImpl });
    await vm.runInContext(`_autoGeocodeAddModalIfNeeded()`, ctx);
    expect(elements['loc-lat'].value).toBe('');
  });

  test('_autoGeocodeAddModalIfNeeded does not clobber address user typed during fetch', async () => {
    const fetchImpl = mockGeocodeOk({
      lat: '48.85', lon: '2.29',
      display_name: 'Paris, France',
    });
    const { ctx, elements } = makeAutoGeoCtx({ addressVal: 'My address', fetchImpl });
    await vm.runInContext(`_autoGeocodeAddModalIfNeeded()`, ctx);
    expect(elements['loc-address'].value).toBe('My address');
  });

  test('_unhideLocCoordsRow flips display + focuses lat input', () => {
    const { ctx, elements } = makeAutoGeoCtx({});
    vm.runInContext(`_unhideLocCoordsRow()`, ctx);
    expect(elements['loc-coords-row'].style.display).toBe('');
    expect(elements['loc-lat'].focused).toBe(true);
  });

  test('static pin: lat/lng row carries id="loc-coords-row" for unhide path', () => {
    expect(indexHtml).toMatch(/id="loc-coords-row"[\s\S]{0,200}id="loc-lat"/);
  });

  test('static pin: saveLocation unhides the row when name present but coords missing', () => {
    // The whole point of this batch: a stuck user with a name typed but no
    // coords must SEE the lat/lng inputs, not just get a toast about them.
    expect(indexHtml).toMatch(/function\s+saveLocation[\s\S]{0,600}_unhideLocCoordsRow\(\)/);
  });

  test('static pin: quickAddPlace delegates to openAddModal (FAB replaces sidebar input)', () => {
    expect(indexHtml).toMatch(/function\s+quickAddPlace\(\)[\s\S]{0,100}openAddModal\(\)/);
    expect(indexHtml).toMatch(/id="add-place-fab"/);
  });
});

describe('Mobile sidebar — auto-collapse on ≤480px first load', () => {
  test('CSS @media (max-width: 480px) makes sidebar full width', () => {
    // The layout rule was already present; this pin guards against a future
    // refactor that drops it (which would re-introduce the audit finding).
    const mq480 = indexHtml.match(/@media\s*\(\s*max-width:\s*480px\s*\)\s*\{[\s\S]{0,2000}\}/);
    expect(mq480).not.toBeNull();
    expect(mq480[0]).toMatch(/#sidebar[\s\S]{0,300}width:\s*100vw/);
    // Toggle slides to the right edge when sidebar is open on mobile so it
    // doesn't sit under the sidebar's right border.
    expect(mq480[0]).toMatch(/sidebar-toggle/);
  });

  test('init() collapses sidebar by default on mobile viewport when no preference', () => {
    // The new heuristic: prefer the saved 'hm_sidebar' value; if absent AND
    // matchMedia('(max-width: 480px)').matches, start collapsed.
    expect(indexHtml).toMatch(/matchMedia\(['"]\(max-width:\s*480px\)['"]\)\.matches/);
    expect(indexHtml).toMatch(/_sbPref\s*===\s*null\s*&&\s*_sbMobileDefault/);
  });

  test('init() still honours explicit user preference over mobile default', () => {
    // _sbPref === '1' wins; '0' must also win (i.e. once the user has
    // toggled OPEN on mobile, that choice sticks). The OR shape guarantees
    // the precedence: `_sbPref === '1' || (null && mobile)`.
    const initBlock = indexHtml.match(/Restore sidebar state[\s\S]{0,800}\}/);
    expect(initBlock).not.toBeNull();
    expect(initBlock[0]).toMatch(/_sbPref\s*===\s*'1'\s*\|\|\s*\(_sbPref\s*===\s*null/);
  });
});
