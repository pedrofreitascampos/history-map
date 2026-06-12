// Web Import client-side — vm-sandbox tests.
// Extracts the 7 web-import functions from the inline script in index.html
// and runs them in a minimal jsdom + vm sandbox so no real network or server
// is involved.

const path = require('path');
const fs = require('fs');
const vm = require('vm');
const { JSDOM } = require('jsdom');

const indexHtml = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');

function extractFunction(name) {
  const start = indexHtml.indexOf(`function ${name}(`);
  if (start === -1) throw new Error(`Function "${name}" not found in index.html`);
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
  if (start === -1) throw new Error(`Async function "${name}" not found in index.html`);
  let depth = 0, i = start, foundFirst = false;
  for (; i < indexHtml.length; i++) {
    if (indexHtml[i] === '{') { depth++; foundFirst = true; }
    if (indexHtml[i] === '}') depth--;
    if (foundFirst && depth === 0) break;
  }
  return indexHtml.substring(start, i + 1);
}

// Build a minimal DOM with all elements the web-import functions touch.
function makeDOM(venues = []) {
  const venueRows = venues.map((v, i) => {
    const isLast = i === venues.length - 1;
    return `<div class="web-import-row" style="${isLast ? '' : 'border-bottom:1px solid #ccc;'}">
      <label>
        <input type="checkbox" class="web-import-check" checked data-idx="${i}" />
        <div>
          <input type="text" class="web-import-name form-input" value="${v.name || ''}" data-idx="${i}" />
          <input type="text" class="web-import-address form-input" value="${v.address || ''}" data-idx="${i}" />
        </div>
      </label>
    </div>`;
  }).join('');

  const dom = new JSDOM(`<!DOCTYPE html><html><body>
    <input type="url" id="web-import-url" />
    <div id="web-import-status"></div>
    <div id="web-import-modal" style="display:none;"></div>
    <div id="web-import-modal-title"></div>
    <div id="web-import-meta"></div>
    <input type="checkbox" id="web-import-toggle-all" checked />
    <div id="web-import-list">${venueRows}</div>
    <button id="web-import-confirm-btn">Import 0 selected</button>
    <div id="toast-container"></div>
  </body></html>`);
  return dom.window.document;
}

// Build a vm sandbox with controllable api, showToast, geocodeNarratedStop.
function makeCtx({ apiImpl, geocodeImpl, docOverride } = {}) {
  const toasts = [];
  const apiCalls = [];
  const doc = docOverride || makeDOM();

  const defaultApi = async (method, url, body) => {
    apiCalls.push({ method, url, body });
    if (url === '/import/website') return { city: null, articleTitle: null, source: 'timeout', venues: [] };
    if (url === '/locations') return { _id: 'loc1', ...body };
    throw new Error('unexpected api call: ' + url);
  };

  const sandbox = {
    console,
    Map, Set, Array, Object, Math, JSON, Promise,
    parseFloat, parseInt, isFinite, isNaN,
    Date, RegExp, Error, Number, String, Boolean,
    // run timers inline so the polite 200ms gap doesn't slow tests
    setTimeout: (fn) => fn(),
    api: apiImpl || defaultApi,
    state: { locations: [] },
    showToast: (msg, kind) => toasts.push({ msg, kind: kind || 'info' }),
    esc: (s) => String(s == null ? '' : s),
    mapId: (o) => ({ ...o, id: o._id || o.id }),
    renderMarkers: () => {},
    geocodeNarratedStop: geocodeImpl || (() => null),
    focusModal: () => {},
    restoreFocus: () => {},
    document: doc,
    window: {},
  };

  const ctx = vm.createContext(sandbox);
  const code = [
    extractFunction('mapWebImportError'),
    extractFunction('closeWebImportModal'),
    extractFunction('updateWebImportSelectedCount'),
    extractFunction('toggleAllWebImport'),
    extractFunction('openWebImportModal'),
    extractAsyncFunction('webImportFetch'),
    extractAsyncFunction('confirmWebImport'),
  ].join('\n');
  vm.runInContext(code, ctx);

  return { ctx, sandbox, toasts, apiCalls };
}

// ─── mapWebImportError unit tests ───────────────────────────────────────────

describe('mapWebImportError', () => {
  let ctx;
  beforeAll(() => { ({ ctx } = makeCtx()); });

  const run = (msg) => vm.runInContext(`mapWebImportError(${JSON.stringify(msg)})`, ctx);

  test('null/undefined returns generic failure', () => {
    expect(run(null)).toBe('Import failed');
    expect(run('')).toBe('Import failed');
  });

  test('invalid_url maps to friendly message', () => {
    expect(run('invalid_url')).toContain('not valid');
    expect(run('400: invalid_url')).toContain('not valid');
  });

  test('host_not_supported maps to friendly message', () => {
    expect(run('host_not_supported')).toContain('not supported yet');
  });

  test('fetch_failed maps to friendly message', () => {
    expect(run('fetch_failed')).toContain('Could not fetch');
  });

  test('fetch_failed_404 maps to "page moved" message (not generic)', () => {
    const m = run('fetch_failed_404');
    expect(m).toMatch(/404|moved/i);
    expect(m).not.toMatch(/blocking/i);  // 404 ≠ blocked
  });

  test('fetch_failed_403 maps to "blocking us" message', () => {
    expect(run('fetch_failed_403')).toMatch(/blocking/i);
  });

  test('fetch_failed_503 maps to "temporarily down" message', () => {
    expect(run('fetch_failed_503')).toMatch(/temporarily down|5xx/i);
  });

  test('response_too_large maps to friendly message', () => {
    expect(run('response_too_large')).toContain('too large');
  });

  // 2026-06-03 cybersec MED-4: previously the fallthrough was
  // `'Import failed: ' + msg` which echoed unknown server error strings into
  // user-visible toasts. Tightened to a static message so an unsanitised
  // upstream error never leaks via this path.
  test('unknown error returns static "Import failed. Please try again." (no msg echo)', () => {
    const result = run('some_other_error');
    expect(result).toBe('Import failed. Please try again.');
    expect(result).not.toContain('some_other_error');
  });
});

// ─── webImportFetch ─────────────────────────────────────────────────────────

describe('webImportFetch', () => {
  test('empty URL shows warn toast and does not call api', async () => {
    const apiMock = jest.fn();
    const { ctx, toasts, apiCalls } = makeCtx({ apiImpl: apiMock });
    // leave #web-import-url value empty (default)
    await vm.runInContext('webImportFetch()', ctx);
    expect(toasts).toHaveLength(1);
    expect(toasts[0].kind).toBe('warn');
    expect(toasts[0].msg).toMatch(/URL/i);
    expect(apiMock).not.toHaveBeenCalled();
  });

  test('api error with invalid_url shows mapped friendly message as error toast', async () => {
    const apiMock = jest.fn().mockRejectedValue(new Error('invalid_url'));
    const doc = makeDOM();
    doc.getElementById('web-import-url').value = 'not-a-real-url';
    const { ctx, toasts } = makeCtx({ apiImpl: apiMock, docOverride: doc });
    await vm.runInContext('webImportFetch()', ctx);
    const errToast = toasts.find(t => t.kind === 'error');
    expect(errToast).toBeDefined();
    expect(errToast.msg).toContain('not valid');
  });

  test('api error with host_not_supported shows mapped friendly message', async () => {
    const apiMock = jest.fn().mockRejectedValue(new Error('host_not_supported'));
    const doc = makeDOM();
    doc.getElementById('web-import-url').value = 'https://tripadvisor.com/foo';
    const { ctx, toasts } = makeCtx({ apiImpl: apiMock, docOverride: doc });
    await vm.runInContext('webImportFetch()', ctx);
    const errToast = toasts.find(t => t.kind === 'error');
    expect(errToast).toBeDefined();
    expect(errToast.msg).toContain('not supported yet');
  });

  test('api error with fetch_failed shows mapped friendly message', async () => {
    const apiMock = jest.fn().mockRejectedValue(new Error('fetch_failed'));
    const doc = makeDOM();
    doc.getElementById('web-import-url').value = 'https://timeout.com/lisbon/foo';
    const { ctx, toasts } = makeCtx({ apiImpl: apiMock, docOverride: doc });
    await vm.runInContext('webImportFetch()', ctx);
    const errToast = toasts.find(t => t.kind === 'error');
    expect(errToast).toBeDefined();
    expect(errToast.msg).toContain('Could not fetch');
  });

  test('api success stashes window._webImport and opens modal', async () => {
    const serverResponse = {
      city: 'Lisbon',
      articleTitle: 'Best restaurants in Lisbon',
      source: 'timeout',
      venues: [{ name: 'Tasca do Chico', address: 'Rua dos Remédios 83', snippet: 'Great fado' }],
    };
    const apiMock = jest.fn().mockResolvedValue(serverResponse);
    const doc = makeDOM(serverResponse.venues);
    doc.getElementById('web-import-url').value = 'https://www.timeout.com/lisbon/restaurants/best';
    const { ctx, sandbox } = makeCtx({ apiImpl: apiMock, docOverride: doc });
    await vm.runInContext('webImportFetch()', ctx);
    expect(sandbox.window._webImport).toMatchObject({
      url: 'https://www.timeout.com/lisbon/restaurants/best',
      city: 'Lisbon',
      articleTitle: 'Best restaurants in Lisbon',
      venues: serverResponse.venues,
    });
    // Modal should be visible after success (now uses .open class, not style.display)
    expect(doc.getElementById('web-import-modal').classList.contains('open')).toBe(true);
  });
});

// ─── updateWebImportSelectedCount ──────────────────────────────────────────

describe('updateWebImportSelectedCount', () => {
  test('updates button label to "Import N selected"', () => {
    const venues = [
      { name: 'A', address: '' },
      { name: 'B', address: '' },
      { name: 'C', address: '' },
    ];
    const doc = makeDOM(venues);
    // Uncheck the second row
    doc.querySelectorAll('.web-import-check')[1].checked = false;
    const { ctx } = makeCtx({ docOverride: doc });
    vm.runInContext('updateWebImportSelectedCount()', ctx);
    const btn = doc.getElementById('web-import-confirm-btn');
    expect(btn.textContent).toBe('Import 2 selected');
    expect(btn.disabled).toBe(false);
  });

  test('disables button when count is 0', () => {
    const venues = [{ name: 'X', address: '' }];
    const doc = makeDOM(venues);
    doc.querySelectorAll('.web-import-check')[0].checked = false;
    const { ctx } = makeCtx({ docOverride: doc });
    vm.runInContext('updateWebImportSelectedCount()', ctx);
    const btn = doc.getElementById('web-import-confirm-btn');
    expect(btn.textContent).toBe('Import 0 selected');
    expect(btn.disabled).toBe(true);
  });
});

// ─── toggleAllWebImport ────────────────────────────────────────────────────

describe('toggleAllWebImport', () => {
  test('unchecked master unchecks every row', () => {
    const venues = [{ name: 'A' }, { name: 'B' }, { name: 'C' }];
    const doc = makeDOM(venues);
    const masterCb = doc.getElementById('web-import-toggle-all');
    masterCb.checked = false;
    const { ctx } = makeCtx({ docOverride: doc });
    vm.runInContext('toggleAllWebImport(document.getElementById("web-import-toggle-all"))', ctx);
    const checks = [...doc.querySelectorAll('.web-import-check')];
    expect(checks.every(cb => !cb.checked)).toBe(true);
    // Button should show 0
    expect(doc.getElementById('web-import-confirm-btn').textContent).toBe('Import 0 selected');
  });

  test('checked master checks every row', () => {
    const venues = [{ name: 'A' }, { name: 'B' }];
    const doc = makeDOM(venues);
    // First uncheck them all
    doc.querySelectorAll('.web-import-check').forEach(cb => { cb.checked = false; });
    const masterCb = doc.getElementById('web-import-toggle-all');
    masterCb.checked = true;
    const { ctx } = makeCtx({ docOverride: doc });
    vm.runInContext('toggleAllWebImport(document.getElementById("web-import-toggle-all"))', ctx);
    const checks = [...doc.querySelectorAll('.web-import-check')];
    expect(checks.every(cb => cb.checked)).toBe(true);
    expect(doc.getElementById('web-import-confirm-btn').textContent).toBe('Import 2 selected');
  });
});

// ─── confirmWebImport ──────────────────────────────────────────────────────

describe('confirmWebImport', () => {
  test('no selected rows shows warn toast and does not POST', async () => {
    const apiMock = jest.fn();
    const venues = [{ name: 'Tasca', address: '' }];
    const doc = makeDOM(venues);
    // Uncheck the only row
    doc.querySelector('.web-import-check').checked = false;
    const { ctx, toasts } = makeCtx({ apiImpl: apiMock, docOverride: doc });
    // Set up _webImport
    ctx.window._webImport = { city: 'Lisbon', articleTitle: null, source: 'timeout', venues };
    await vm.runInContext('confirmWebImport()', ctx);
    expect(toasts.find(t => t.kind === 'warn')).toBeDefined();
    // POST /locations should NOT have been called
    expect(apiMock).not.toHaveBeenCalledWith('POST', '/locations', expect.anything());
  });

  test('POSTs each selected venue as a bucket-status location', async () => {
    const venues = [
      { name: 'Tasca do Chico', address: 'Rua dos Remédios 83', snippet: '' },
      { name: 'Cervejaria Ramiro', address: 'Av. Almirante Reis 1', snippet: '' },
    ];
    const doc = makeDOM(venues);
    const locationCalls = [];
    const apiMock = jest.fn().mockImplementation(async (method, url, body) => {
      if (method === 'POST' && url === '/locations') {
        locationCalls.push(body);
        return { _id: `loc-${locationCalls.length}`, ...body };
      }
      throw new Error('unexpected: ' + url);
    });
    const geocodeMock = jest.fn().mockResolvedValue({ lat: 38.7, lng: -9.1, address: 'Lisbon, PT', category: 'restaurant' });
    const { ctx, sandbox } = makeCtx({ apiImpl: apiMock, geocodeImpl: geocodeMock, docOverride: doc });
    sandbox.window._webImport = { city: 'Lisbon', articleTitle: null, source: 'timeout', venues };
    await vm.runInContext('confirmWebImport()', ctx);
    expect(locationCalls).toHaveLength(2);
    locationCalls.forEach(body => {
      expect(body.status).toBe('bucket');
      expect(body.category).toBe('restaurant');
      expect(body.tags).toContain('timeout');
    });
    expect(locationCalls[0].name).toBe('Tasca do Chico');
    expect(locationCalls[1].name).toBe('Cervejaria Ramiro');
  });

  test('falls back to city in geocode query when venue has no address', async () => {
    const venues = [{ name: 'Adega Típica', address: '', snippet: '' }];
    const doc = makeDOM(venues);
    const geocodeCalls = [];
    const geocodeMock = jest.fn().mockImplementation(async (q) => {
      geocodeCalls.push(q);
      return null;
    });
    const apiMock = jest.fn().mockResolvedValue({ _id: 'l1' });
    const { ctx, sandbox } = makeCtx({ apiImpl: apiMock, geocodeImpl: geocodeMock, docOverride: doc });
    sandbox.window._webImport = { city: 'Porto', articleTitle: null, source: 'timeout', venues };
    await vm.runInContext('confirmWebImport()', ctx);
    expect(geocodeCalls).toHaveLength(1);
    // Query must include city as fallback
    expect(geocodeCalls[0]).toContain('Porto');
    expect(geocodeCalls[0]).toContain('Adega Típica');
  });

  test('carries snippet and articleTitle into location notes', async () => {
    const venues = [{ name: 'Restaurante X', address: '', snippet: 'Amazing food' }];
    const doc = makeDOM(venues);
    const locationCalls = [];
    const apiMock = jest.fn().mockImplementation(async (method, url, body) => {
      if (url === '/locations') locationCalls.push(body);
      return { _id: 'l1', ...body };
    });
    const { ctx, sandbox } = makeCtx({ apiImpl: apiMock, geocodeImpl: () => null, docOverride: doc });
    sandbox.window._webImport = {
      city: 'Lisbon',
      articleTitle: 'Best Restaurants 2025',
      source: 'timeout',
      venues,
    };
    await vm.runInContext('confirmWebImport()', ctx);
    expect(locationCalls).toHaveLength(1);
    const notes = locationCalls[0].notes;
    expect(notes).toContain('Best Restaurants 2025');
    expect(notes).toContain('Amazing food');
  });

  test('failed location POST increments failed count in summary', async () => {
    const venues = [
      { name: 'Good Place', address: '', snippet: '' },
      { name: 'Bad Place', address: '', snippet: '' },
    ];
    const doc = makeDOM(venues);
    let callCount = 0;
    const apiMock = jest.fn().mockImplementation(async (method, url, body) => {
      if (url === '/locations') {
        callCount++;
        if (callCount === 2) throw new Error('server error');
        return { _id: `l${callCount}`, ...body };
      }
      throw new Error('unexpected');
    });
    const { ctx, sandbox, toasts } = makeCtx({ apiImpl: apiMock, geocodeImpl: () => null, docOverride: doc });
    sandbox.window._webImport = { city: null, articleTitle: null, source: 'timeout', venues };
    await vm.runInContext('confirmWebImport()', ctx);
    const summary = toasts[toasts.length - 1];
    expect(summary.msg).toContain('1 failed');
    expect(summary.kind).toBe('warn');
  });

  test('summary toast reports located/unmatched/failed counts', async () => {
    const venues = [
      { name: 'Located', address: 'Rua A', snippet: '' },
      { name: 'Unmatched', address: '', snippet: '' },
    ];
    const doc = makeDOM(venues);
    const apiMock = jest.fn().mockResolvedValue({ _id: 'l1' });
    const geocodeMock = jest.fn()
      .mockResolvedValueOnce({ lat: 38.7, lng: -9.1, address: 'Rua A, Lisbon', category: 'restaurant' })
      .mockResolvedValueOnce(null);
    const { ctx, sandbox, toasts } = makeCtx({ apiImpl: apiMock, geocodeImpl: geocodeMock, docOverride: doc });
    sandbox.window._webImport = { city: 'Lisbon', articleTitle: null, source: 'timeout', venues };
    await vm.runInContext('confirmWebImport()', ctx);
    const summary = toasts[toasts.length - 1];
    expect(summary.msg).toContain('1 located');
    expect(summary.msg).toContain('1 unmatched');
    expect(summary.kind).toBe('success');
  });

  test('adds non-timeout source to tags', async () => {
    const venues = [{ name: 'Place', address: '', snippet: '' }];
    const doc = makeDOM(venues);
    const locationCalls = [];
    const apiMock = jest.fn().mockImplementation(async (method, url, body) => {
      if (url === '/locations') { locationCalls.push(body); return { _id: 'l1', ...body }; }
    });
    const { ctx, sandbox } = makeCtx({ apiImpl: apiMock, geocodeImpl: () => null, docOverride: doc });
    sandbox.window._webImport = { city: null, articleTitle: null, source: 'unknown', venues };
    await vm.runInContext('confirmWebImport()', ctx);
    expect(locationCalls[0].tags).toContain('timeout');
    expect(locationCalls[0].tags).toContain('unknown');
  });
});
