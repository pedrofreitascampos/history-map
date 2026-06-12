// Regression coverage for the 2026-06-02 Wishlist view batch.
// Tests: static markup pins, sort/filter/search/empty-state/XSS.
// vm-sandbox pattern mirrors tests/marker-style.test.js and tests/discover-provider.test.js.

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

// ──────────────────────────────────────────────────────────────────────────────
// 1. Static markup pins (no sandbox needed)
// ──────────────────────────────────────────────────────────────────────────────
describe('Wishlist view — static markup pins', () => {
  test('nav tab data-view="wishlist-view" exists with 🔖 emoji (not ⭐ — reserved for ratings)', () => {
    expect(indexHtml).toContain('data-view="wishlist-view"');
    expect(indexHtml).toMatch(/data-view="wishlist-view"[\s\S]{0,200}🔖/);
    expect(indexHtml).not.toMatch(/data-view="wishlist-view"[\s\S]{0,200}⭐/);
  });

  test('<div class="view" id="wishlist-view"> exists', () => {
    expect(indexHtml).toContain('id="wishlist-view"');
  });

  test('four sort options exist', () => {
    expect(indexHtml).toContain('value="strength"');
    expect(indexHtml).toContain('value="rating"');
    expect(indexHtml).toContain('value="name"');
    expect(indexHtml).toContain('value="recent"');
  });

  test('function renderWishlist() exists', () => {
    expect(indexHtml).toContain('function renderWishlist()');
  });

  test('function showOnMapFromWishlist( exists', () => {
    expect(indexHtml).toContain('function showOnMapFromWishlist(');
  });

  test('function deleteFromWishlist( exists', () => {
    expect(indexHtml).toContain('function deleteFromWishlist(');
  });

  test('function onWishlistFilterChange( exists', () => {
    expect(indexHtml).toContain('function onWishlistFilterChange(');
  });

  test('wishlist-item action row reuses logTodayFromPopup (not a new handler)', () => {
    // The Been button in the wishlist must wire to the existing logTodayFromPopup action.
    // Check it appears in the renderWishlist function body context.
    const fnStart = indexHtml.indexOf('function renderWishlist()');
    const fnEnd = (() => {
      let depth = 0, i = fnStart, foundFirst = false;
      for (; i < indexHtml.length; i++) {
        if (indexHtml[i] === '{') { depth++; foundFirst = true; }
        if (indexHtml[i] === '}') depth--;
        if (foundFirst && depth === 0) break;
      }
      return i + 1;
    })();
    const fnBody = indexHtml.substring(fnStart, fnEnd);
    expect(fnBody).toContain('logTodayFromPopup');
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// Shared helpers for vm-sandbox tests
// ──────────────────────────────────────────────────────────────────────────────

const CATEGORIES_STUB = {
  location: { emoji: '📍', label: 'Location' },
  restaurant: { emoji: '🍽️', label: 'Restaurant' },
  museum: { emoji: '🏛️', label: 'Museum' },
};

const escFn = (s) => String(s).replace(/[&<>"']/g, c =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/**
 * Build a vm-sandbox context that captures what renderWishlist renders.
 *
 * The tricky part: `_appendWishlistPage` does:
 *   const frag = document.createElement('div');
 *   frag.innerHTML = _renderWishlistPage(...);
 *   while (frag.firstChild) container.appendChild(frag.firstChild);
 *
 * `while (frag.firstChild)` evaluates firstChild TWICE per iteration —
 * once in the condition and once as the argument to appendChild. To handle
 * this, we make firstChild a PEEK (non-consuming) getter, and advance only
 * when container.appendChild receives a node tagged with the fragment.
 */
function makeWishlistCtx({ locations = [], sortValue = 'strength', tagValue = '', catValue = '', searchValue = '' } = {}) {

  // Fake element builder for createElement('div') — used as the inner fragment.
  // firstChild peeks (non-consuming); advances only when appendedTo is called.
  function makeFakeDiv() {
    const el = {
      _children: [],
      _html: '',
      get innerHTML() { return this._html; },
      set innerHTML(v) {
        this._html = v;
        // Parse the raw HTML into child chunks at top-level timeline-item boundaries.
        this._children = [];
        const re = /<div class="timeline-item/g;
        const starts = [];
        let m;
        while ((m = re.exec(v)) !== null) starts.push(m.index);
        if (starts.length === 0) {
          if (v.trim()) this._children.push({ _html: v, _frag: this, id: undefined });
        } else {
          for (let si = 0; si < starts.length; si++) {
            const from = starts[si];
            const to = si + 1 < starts.length ? starts[si + 1] : v.length;
            this._children.push({ _html: v.slice(from, to), _frag: this, id: undefined });
          }
        }
      },
      // Peek — returns the first child WITHOUT consuming it.
      get firstChild() {
        return this._children.length > 0 ? this._children[0] : null;
      },
      // Called by container.appendChild when it receives a node from this frag.
      _advance() { this._children.shift(); },
      style: { cssText: '' }, className: '', textContent: '', onclick: null, id: '',
    };
    return el;
  }

  // Track load-more button appended at end.
  let _loadMoreAppended = null;
  const containerWithLoadMore = {
    _html: '',
    get innerHTML() { return this._html; },
    set innerHTML(v) { this._html = v; },
    appendChild(node) {
      if (!node) return; // guard against null
      if (node.id === 'wishlist-load-more') {
        _loadMoreAppended = node;
      } else if (node._frag) {
        // Node came from a fragment — advance the fragment pointer then collect html.
        node._frag._advance();
        this._html += (node._html || '');
      } else {
        this._html += (node._html || node.outerHTML || '');
      }
    },
  };

  const selectStub = (val) => {
    const s = { _val: val, innerHTML: '' };
    Object.defineProperty(s, 'value', { get() { return this._val; }, set(v) { this._val = v; } });
    return s;
  };
  const inputStub = (val) => ({ value: val });

  const idMap = {
    'wishlist': containerWithLoadMore,
    'wishlist-sort': selectStub(sortValue),
    'wishlist-tag': selectStub(tagValue),
    'wishlist-cat': selectStub(catValue),
    'wishlist-search': inputStub(searchValue),
    'wishlist-load-more': null,
  };

  const document = {
    getElementById(id) {
      if (id === 'wishlist-load-more') return _loadMoreAppended;
      return idMap[id] !== undefined ? idMap[id] : null;
    },
    createElement(tag) {
      if (tag === 'div') return makeFakeDiv();
      // For the load-more button (createElement('button'))
      const btn = { id: '', className: '', style: { cssText: '' }, textContent: '', onclick: null, _html: '' };
      return btn;
    },
  };

  const ctx = vm.createContext({
    document,
    console,
    Map, Set, Array, Object, Math, JSON, Promise, Date, RegExp,
    Number, String, Boolean, Error,
    parseFloat, parseInt, isFinite, isNaN, encodeURIComponent,
    CATEGORIES: CATEGORIES_STUB,
    esc: escFn,
    stateIndex: { generation: 1 },
    state: { locations },
    confirm: () => true,
    // Module-level guard variables referenced by populateWishlistFilters
    _wishlistFiltersGen: -1,
  });

  const code = [
    extractFunction('populateWishlistFilters'),
    extractFunction('onWishlistFilterChange'),
    extractFunction('renderWishlist'),
  ].join('\n');
  vm.runInContext(code, ctx);

  return { ctx, containerWithLoadMore, getHtml: () => containerWithLoadMore._html };
}

// ──────────────────────────────────────────────────────────────────────────────
// 2. renderWishlist sort by strength
// ──────────────────────────────────────────────────────────────────────────────
describe('renderWishlist — sort by strength', () => {
  test('orders items strength-5, strength-4, strength-3, strength-0 descending', () => {
    const locations = [
      { id: 'a', _id: 'a', status: 'bucket', name: 'Alpha', bucketStrength: 3, category: 'location' },
      { id: 'b', _id: 'b', status: 'bucket', name: 'Beta',  bucketStrength: 0, category: 'location' },
      { id: 'c', _id: 'c', status: 'bucket', name: 'Gamma', bucketStrength: 5, category: 'location' },
      { id: 'd', _id: 'd', status: 'bucket', name: 'Delta', bucketStrength: 4, category: 'location' },
    ];
    const { ctx, getHtml } = makeWishlistCtx({ locations, sortValue: 'strength' });
    vm.runInContext('renderWishlist()', ctx);
    const html = getHtml();
    const order = ['Gamma', 'Delta', 'Alpha', 'Beta'];
    let lastIdx = -1;
    for (const name of order) {
      const idx = html.indexOf(name);
      expect(idx).toBeGreaterThan(-1);
      expect(idx).toBeGreaterThan(lastIdx);
      lastIdx = idx;
    }
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// 3. renderWishlist filter by tag
// ──────────────────────────────────────────────────────────────────────────────
describe('renderWishlist — filter by tag', () => {
  test('only shows items that include the selected tag', () => {
    const locations = [
      { id: '1', _id: '1', status: 'bucket', name: 'Bora Bora',   tags: ['bucketlist'], category: 'location' },
      { id: '2', _id: '2', status: 'bucket', name: 'Porto',       tags: ['family'],     category: 'location' },
      { id: '3', _id: '3', status: 'bucket', name: 'Antarctica',  tags: [],             category: 'location' },
    ];
    const { ctx, getHtml } = makeWishlistCtx({ locations, sortValue: 'name', tagValue: 'bucketlist' });
    vm.runInContext('renderWishlist()', ctx);
    const html = getHtml();
    expect(html).toContain('Bora Bora');
    expect(html).not.toContain('Porto');
    expect(html).not.toContain('Antarctica');
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// 4. renderWishlist filter by search
// ──────────────────────────────────────────────────────────────────────────────
describe('renderWishlist — filter by search', () => {
  test('case-insensitive substring search on name', () => {
    const locations = [
      { id: '1', _id: '1', status: 'bucket', name: 'Bora Bora',   category: 'location' },
      { id: '2', _id: '2', status: 'bucket', name: 'North Korea', category: 'location' },
      { id: '3', _id: '3', status: 'bucket', name: 'Antarctica',  category: 'location' },
    ];
    const { ctx, getHtml } = makeWishlistCtx({ locations, sortValue: 'name', searchValue: 'korea' });
    vm.runInContext('renderWishlist()', ctx);
    const html = getHtml();
    expect(html).toContain('North Korea');
    expect(html).not.toContain('Bora Bora');
    expect(html).not.toContain('Antarctica');
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// 5. renderWishlist empty state
// ──────────────────────────────────────────────────────────────────────────────
describe('renderWishlist — empty state', () => {
  test('shows "No Wishlist Items Yet" when no bucket locations match', () => {
    const locations = [
      { id: '1', _id: '1', status: 'been', name: 'Lisbon', category: 'location' },
      { id: '2', _id: '2', status: 'been', name: 'Porto',  category: 'location' },
    ];
    // We need to inspect what the container innerHTML was SET to (not appended).
    // Use a custom makeCtx that captures innerHTML assignment.
    const setHtmlValues = [];
    const containerCapture = {
      get innerHTML() { return setHtmlValues[setHtmlValues.length - 1] || ''; },
      set innerHTML(v) { setHtmlValues.push(v); },
      appendChild() {},
    };

    const idMap = {
      'wishlist': containerCapture,
      'wishlist-sort': { value: 'strength' },
      'wishlist-tag': { value: '' },
      'wishlist-cat': { value: '' },
      'wishlist-search': { value: '' },
      'wishlist-load-more': null,
    };

    const docStub = {
      getElementById: (id) => idMap[id] !== undefined ? idMap[id] : null,
      createElement: (tag) => ({ id: '', className: '', style: { cssText: '' }, textContent: '', onclick: null }),
    };

    const ctx = vm.createContext({
      document: docStub,
      console, Map, Set, Array, Object, Math, JSON, Promise, Date, RegExp,
      Number, String, Boolean, Error, parseFloat, parseInt, isFinite, isNaN, encodeURIComponent,
      CATEGORIES: CATEGORIES_STUB,
      esc: escFn,
      stateIndex: { generation: 1 },
      state: { locations },
      _wishlistFiltersGen: -1,
    });

    const code = [
      extractFunction('populateWishlistFilters'),
      extractFunction('onWishlistFilterChange'),
      extractFunction('renderWishlist'),
    ].join('\n');
    vm.runInContext(code, ctx);
    vm.runInContext('renderWishlist()', ctx);

    const html = setHtmlValues.join('');
    expect(html).toContain('No Wishlist Items Yet');
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// 6. XSS regression
// ──────────────────────────────────────────────────────────────────────────────
describe('renderWishlist — XSS escaping', () => {
  test('name and tags are escaped — no raw <script> or <img in output', () => {
    const locations = [
      {
        id: 'xss1', _id: 'xss1',
        status: 'bucket',
        name: '<script>alert(1)</script>',
        tags: ['<img onerror=x>'],
        address: '"><svg/onload=alert(1)>',
        category: 'location',
      },
    ];
    const { ctx, getHtml } = makeWishlistCtx({ locations, sortValue: 'name' });
    vm.runInContext('renderWishlist()', ctx);
    const html = getHtml();
    // Must contain the escaped entity, not the raw attack payload
    expect(html).not.toContain('<script>');
    expect(html).not.toContain('<img');
    expect(html).not.toContain('<svg');
    // Escaped versions should be present
    expect(html).toContain('&lt;script&gt;');
  });
});
