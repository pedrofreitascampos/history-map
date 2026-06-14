// Currency overlay for Regions (#11).
// Static markup + COUNTRY_CURRENCY table + _getFxRates / toggleStatsCurrency / _renderCountryFlags logic.

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
describe('Currency overlay — static markup', () => {
  test('#stats-currency-toggle button exists', () => {
    expect(html).toContain('id="stats-currency-toggle"');
  });

  test('stats-currency-toggle wired to toggleStatsCurrency', () => {
    expect(html).toMatch(/id="stats-currency-toggle"[^>]*data-click="toggleStatsCurrency"/);
  });

  test('COUNTRY_CURRENCY constant defined', () => {
    expect(html).toMatch(/const COUNTRY_CURRENCY\s*=/);
  });

  test('_getFxRates function defined', () => {
    expect(html).toContain('function _getFxRates(');
  });

  test('toggleStatsCurrency function defined', () => {
    expect(html).toContain('function toggleStatsCurrency(');
  });

  test('_renderCountryFlags function defined', () => {
    expect(html).toContain('function _renderCountryFlags(');
  });

  test('_statsShowCurrency state variable declared', () => {
    expect(html).toMatch(/let _statsShowCurrency\s*=\s*false/);
  });

  test('_fxCache state variable declared', () => {
    expect(html).toMatch(/let _fxCache\s*=\s*null/);
  });

  test('_FX_TTL_MS constant declared', () => {
    expect(html).toMatch(/const _FX_TTL_MS\s*=/);
  });

  test('CSP connectSrc includes open.er-api.com', () => {
    const serverSrc = fs.readFileSync(path.join(__dirname, '..', 'server', 'index.js'), 'utf-8');
    expect(serverSrc).toContain('open.er-api.com');
  });

  test('flag-currency CSS class defined', () => {
    expect(html).toContain('flag-currency');
  });

  test('renderStats delegates to _renderCountryFlags', () => {
    const fn = extractFunction('renderStats');
    expect(fn).toContain('_renderCountryFlags');
  });
});

// ── COUNTRY_CURRENCY table ─────────────────────────────────────────────────
describe('Currency overlay — COUNTRY_CURRENCY table', () => {
  function getCurrencyEntry(iso2) {
    const match = html.match(/const COUNTRY_CURRENCY\s*=\s*\{([\s\S]*?)\};/);
    if (!match) throw new Error('COUNTRY_CURRENCY not found');
    const code = `const COUNTRY_CURRENCY = {${match[1]}}; __result = COUNTRY_CURRENCY['${iso2}'];`;
    const ctx = vm.createContext({ __result: undefined });
    vm.runInContext(code, ctx);
    return ctx.__result;
  }

  test('PT maps to EUR with € symbol', () => {
    const entry = getCurrencyEntry('PT');
    expect(entry).toEqual(['EUR', '€']);
  });

  test('US maps to USD with $ symbol', () => {
    const entry = getCurrencyEntry('US');
    expect(entry).toEqual(['USD', '$']);
  });

  test('JP maps to JPY with ¥ symbol', () => {
    const entry = getCurrencyEntry('JP');
    expect(entry[0]).toBe('JPY');
  });

  test('GB maps to GBP with £ symbol', () => {
    const entry = getCurrencyEntry('GB');
    expect(entry).toEqual(['GBP', '£']);
  });

  test('BR maps to BRL', () => {
    const entry = getCurrencyEntry('BR');
    expect(entry[0]).toBe('BRL');
  });

  test('unknown ISO2 returns undefined (no crash)', () => {
    const entry = getCurrencyEntry('ZZ');
    expect(entry).toBeUndefined();
  });
});

// ── _renderCountryFlags logic (vm) ────────────────────────────────────────
function buildRenderContext(locations) {
  const ccMatch = html.match(/const COUNTRY_CURRENCY\s*=\s*\{[\s\S]*?\};/);
  if (!ccMatch) throw new Error('COUNTRY_CURRENCY block not found');
  const codesMatch = html.match(/const COUNTRY_CODES\s*=\s*\{[\s\S]*?\};/);
  if (!codesMatch) throw new Error('COUNTRY_CODES block not found');

  // regionToCountryCode is needed by _renderCountryFlags
  const rFn = extractFunction('regionToCountryCode');

  const domElements = new Map();
  function makeEl(id) {
    const el = { id, innerHTML: '', textContent: '', style: {}, className: '' };
    domElements.set(id, el);
    return el;
  }
  makeEl('countries-flags');
  makeEl('countries-count');

  const ctx = vm.createContext({
    _statsShowCurrency: false,
    state: { locations: locations || [] },
    document: { getElementById: (id) => domElements.get(id) || makeEl(id) },
    domElements,
  });

  vm.runInContext([codesMatch[0], ccMatch[0], extractFunction('esc'), rFn, extractFunction('_renderCountryFlags')].join('\n'), ctx);
  return ctx;
}

describe('Currency overlay — _renderCountryFlags', () => {
  test('_renderCountryFlags is a function', () => {
    const ctx = buildRenderContext([]);
    expect(typeof ctx._renderCountryFlags).toBe('function');
  });

  test('renders empty message when no visited locations', () => {
    const ctx = buildRenderContext([]);
    ctx._renderCountryFlags(null);
    const flagsEl = ctx.domElements.get('countries-flags');
    expect(flagsEl.innerHTML).toContain('No countries visited');
  });

  test('renders flag cards for visited countries', () => {
    const locs = [
      { needsApproval: false, status: 'been', _region: 'Portugal' },
      { needsApproval: false, status: 'been', _region: 'Portugal' },
      { needsApproval: false, status: 'been', _region: 'Japan' },
    ];
    const ctx = buildRenderContext(locs);
    ctx._renderCountryFlags(null);
    const flagsEl = ctx.domElements.get('countries-flags');
    expect(flagsEl.innerHTML).toContain('PT');
  });

  test('shows currency line when rates provided and _statsShowCurrency true', () => {
    const locs = [{ needsApproval: false, status: 'been', _region: 'Japan' }];
    const ctx = buildRenderContext(locs);
    ctx._statsShowCurrency = true;
    ctx._renderCountryFlags({ JPY: 162.5 });
    const flagsEl = ctx.domElements.get('countries-flags');
    expect(flagsEl.innerHTML).toContain('JPY');
  });

  test('no currency line when _statsShowCurrency false', () => {
    const locs = [{ needsApproval: false, status: 'been', _region: 'Japan' }];
    const ctx = buildRenderContext(locs);
    ctx._statsShowCurrency = false;
    ctx._renderCountryFlags({ JPY: 162.5 });
    const flagsEl = ctx.domElements.get('countries-flags');
    expect(flagsEl.innerHTML).not.toContain('JPY');
  });
});

// ── FX cache / TTL ────────────────────────────────────────────────────────
describe('Currency overlay — FX cache constants', () => {
  test('_FX_TTL_MS is 1 hour (3600000 ms)', () => {
    const match = html.match(/const _FX_TTL_MS\s*=\s*(\d+)/);
    expect(match).not.toBeNull();
    expect(Number(match[1])).toBe(3600000);
  });

  test('_getFxRates fetches from open.er-api.com', () => {
    const fn = extractFunction('_getFxRates');
    expect(fn).toContain('open.er-api.com');
  });

  test('_getFxRates uses _fxCache to avoid repeated fetches', () => {
    const fn = extractFunction('_getFxRates');
    expect(fn).toContain('_fxCache');
  });

  test('_getFxRates checks TTL before re-fetching', () => {
    const fn = extractFunction('_getFxRates');
    expect(fn).toContain('_FX_TTL_MS');
  });
});
