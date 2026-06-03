// Regression for the 2026-06-01 marker styling batch:
//   1. Bucket markers now carry a violet wishlist fill (not just dashed border).
//   2. Star badge replaces the numeric rating tag when rating >= 4.0
//      (gold >= 4.5, silver 4.0-4.5).
//   3. Rating source prefers myRating over googleRating (first-person wins).
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

describe('createMarkerIcon — rating star badge + source priority', () => {
  function makeCtx() {
    const divIconCalls = [];
    const ctx = vm.createContext({
      L: { divIcon: (opts) => { divIconCalls.push(opts); return opts; } },
      CATEGORIES: { restaurant: { color: 'red', label: 'Food', emoji: '🍽️' }, location: { color: 'gray', label: 'Place', emoji: '📍' } },
      COLOR_HEX: { red: '#ef4444', gray: '#888888' },
      DEFAULT_HEX: '#888888',
      computeMarkerSize: () => 34,
      pickMarkerEmoji: (loc) => '🍽️',
      esc: (s) => String(s).replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c])),
      state: { markerSizeMode: 'default' },
    });
    vm.runInContext(extractFunction('createMarkerIcon'), ctx);
    return { ctx, divIconCalls };
  }

  test('rating >= 4.5 renders gold star badge AND numeric tag (badge complements number)', () => {
    const { ctx, divIconCalls } = makeCtx();
    vm.runInContext(`createMarkerIcon({ status: 'been', category: 'restaurant', myRating: 4.7 }, {})`, ctx);
    const html = divIconCalls[0].html;
    expect(html).toMatch(/marker-rating-badge gold/);
    expect(html).toContain('★');
    // Numeric tag also shows — at-a-glance star + precise value.
    expect(html).toMatch(/class="marker-rating">4.7</);
  });

  test('rating 4.0-4.5 renders silver star badge AND numeric tag', () => {
    const { ctx, divIconCalls } = makeCtx();
    vm.runInContext(`createMarkerIcon({ status: 'been', category: 'restaurant', myRating: 4.2 }, {})`, ctx);
    const html = divIconCalls[0].html;
    expect(html).toMatch(/marker-rating-badge silver/);
    expect(html).toMatch(/class="marker-rating">4.2</);
  });

  test('rating < 4.0 keeps numeric tag, no star', () => {
    const { ctx, divIconCalls } = makeCtx();
    vm.runInContext(`createMarkerIcon({ status: 'been', category: 'restaurant', googleRating: 3.5 }, {})`, ctx);
    const html = divIconCalls[0].html;
    expect(html).toMatch(/class="marker-rating">3.5/);
    expect(html).not.toMatch(/marker-rating-badge/);
  });

  test('no rating → no badge AND no numeric', () => {
    const { ctx, divIconCalls } = makeCtx();
    vm.runInContext(`createMarkerIcon({ status: 'been', category: 'restaurant' }, {})`, ctx);
    const html = divIconCalls[0].html;
    expect(html).not.toMatch(/marker-rating/);
  });

  test('rating source: myRating wins over googleRating', () => {
    const { ctx, divIconCalls } = makeCtx();
    // myRating 4.6 (gold) + googleRating 3.2 (would be numeric) → gold badge
    vm.runInContext(`createMarkerIcon({ status: 'been', category: 'restaurant', myRating: 4.6, googleRating: 3.2 }, {})`, ctx);
    const html = divIconCalls[0].html;
    expect(html).toMatch(/marker-rating-badge gold/);
  });

  test('been: falls back to googleRating when myRating absent', () => {
    const { ctx, divIconCalls } = makeCtx();
    vm.runInContext(`createMarkerIcon({ status: 'been', category: 'restaurant', googleRating: 4.7 }, {})`, ctx);
    const html = divIconCalls[0].html;
    expect(html).toMatch(/marker-rating-badge gold/);
  });

  // ── Bucket source: bucketStrength wins, falls back to googleRating ──
  // The rating-driving signal differs by status. For bucket items the
  // first-person score is `bucketStrength` (1-5 from the heart slider).
  // myRating doesn't apply to a place the user hasn't visited yet.

  test('bucket: bucketStrength=5 → gold star AND numeric "5.0"', () => {
    const { ctx, divIconCalls } = makeCtx();
    vm.runInContext(`createMarkerIcon({ status: 'bucket', category: 'restaurant', bucketStrength: 5 }, {})`, ctx);
    const html = divIconCalls[0].html;
    expect(html).toMatch(/marker-rating-badge gold/);
    expect(html).toMatch(/class="marker-rating">5.0</);
  });

  test('bucket: bucketStrength=4 → silver star', () => {
    const { ctx, divIconCalls } = makeCtx();
    vm.runInContext(`createMarkerIcon({ status: 'bucket', category: 'restaurant', bucketStrength: 4 }, {})`, ctx);
    const html = divIconCalls[0].html;
    expect(html).toMatch(/marker-rating-badge silver/);
  });

  test('bucket: bucketStrength=3 → numeric tag, no star', () => {
    const { ctx, divIconCalls } = makeCtx();
    vm.runInContext(`createMarkerIcon({ status: 'bucket', category: 'restaurant', bucketStrength: 3 }, {})`, ctx);
    const html = divIconCalls[0].html;
    expect(html).toMatch(/class="marker-rating">3.0</);
    expect(html).not.toMatch(/marker-rating-badge/);
  });

  test('bucket: bucketStrength wins over googleRating (4 silver beats 4.8 gold)', () => {
    const { ctx, divIconCalls } = makeCtx();
    vm.runInContext(`createMarkerIcon({ status: 'bucket', category: 'restaurant', bucketStrength: 4, googleRating: 4.8 }, {})`, ctx);
    const html = divIconCalls[0].html;
    // bucketStrength=4 → silver, not gold (otherwise google's 4.8 would have won)
    expect(html).toMatch(/marker-rating-badge silver/);
    expect(html).not.toMatch(/marker-rating-badge gold/);
  });

  test('bucket: bucketStrength=0 (unset) → falls back to googleRating', () => {
    const { ctx, divIconCalls } = makeCtx();
    vm.runInContext(`createMarkerIcon({ status: 'bucket', category: 'restaurant', bucketStrength: 0, googleRating: 4.6 }, {})`, ctx);
    const html = divIconCalls[0].html;
    expect(html).toMatch(/marker-rating-badge gold/);
  });

  test('bucket: bucketStrength unset, no googleRating → nothing', () => {
    const { ctx, divIconCalls } = makeCtx();
    vm.runInContext(`createMarkerIcon({ status: 'bucket', category: 'restaurant' }, {})`, ctx);
    const html = divIconCalls[0].html;
    expect(html).not.toMatch(/marker-rating/);
  });

  test('been: myRating still trumps googleRating (regression for status-conditional branch)', () => {
    // Sanity: changing the bucket branch must not affect the been branch.
    const { ctx, divIconCalls } = makeCtx();
    vm.runInContext(`createMarkerIcon({ status: 'been', category: 'restaurant', myRating: 5, googleRating: 3.2, bucketStrength: 1 }, {})`, ctx);
    const html = divIconCalls[0].html;
    expect(html).toMatch(/marker-rating-badge gold/);
  });
});

describe('Static markup (regression)', () => {
  test('bucket marker has violet wishlist fill + ring shadow', () => {
    expect(indexHtml).toMatch(/\.marker-icon\.bucket\s*\{[\s\S]{0,300}rgba\(139,\s*92,\s*246,\s*0\.18\)/);
    expect(indexHtml).toMatch(/\.marker-icon\.bucket\s*\{[\s\S]{0,400}rgba\(139,\s*92,\s*246,\s*0\.35\)/);
  });

  test('bucket marker no longer sets opacity: 0.8 (was a penalty look)', () => {
    expect(indexHtml).not.toMatch(/\.marker-icon\.bucket\s*\{[^}]*opacity:\s*0\.8/);
  });

  test('marker-rating-badge CSS rules present (gold + silver variants)', () => {
    expect(indexHtml).toMatch(/\.marker-rating-badge\.gold\s*\{[^}]*#f59e0b/);
    expect(indexHtml).toMatch(/\.marker-rating-badge\.silver\s*\{[^}]*#94a3b8/);
  });

  test('logTodayFromPopup guards against falsy locId', () => {
    expect(indexHtml).toMatch(/async function logTodayFromPopup\(locId\)\s*\{\s*if \(!locId\)/);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Marker style variants (2026-06-02 batch)
// ─────────────────────────────────────────────────────────────────────────────

describe('Marker style variants — static markup pins', () => {
  test('marker-style select exists with exactly 5 options', () => {
    const matches = indexHtml.match(/<select[^>]*id="marker-style"[\s\S]*?<\/select>/);
    expect(matches).not.toBeNull();
    const block = matches[0];
    const options = block.match(/<option\s+value="[^"]*">/g) || [];
    expect(options).toHaveLength(5);
    expect(block).toContain('value="circle"');
    expect(block).toContain('value="squircle"');
    expect(block).toContain('value="teardrop"');
    expect(block).toContain('value="glyph"');
    expect(block).toContain('value="pill"');
  });

  test('VALID_MARKER_STYLES const declared with all 5 values', () => {
    expect(indexHtml).toMatch(/const VALID_MARKER_STYLES\s*=\s*\[/);
    expect(indexHtml).toMatch(/VALID_MARKER_STYLES\s*=\s*\[[^\]]*'circle'[^\]]*\]/);
    expect(indexHtml).toMatch(/VALID_MARKER_STYLES\s*=\s*\[[^\]]*'squircle'[^\]]*\]/);
    expect(indexHtml).toMatch(/VALID_MARKER_STYLES\s*=\s*\[[^\]]*'teardrop'[^\]]*\]/);
    expect(indexHtml).toMatch(/VALID_MARKER_STYLES\s*=\s*\[[^\]]*'glyph'[^\]]*\]/);
    expect(indexHtml).toMatch(/VALID_MARKER_STYLES\s*=\s*\[[^\]]*'pill'[^\]]*\]/);
  });

  test('function setMarkerStyle exists', () => {
    expect(indexHtml).toMatch(/function setMarkerStyle\(/);
  });

  test('MARKER_STYLE_DESCRIPTIONS const exists with all 5 keys', () => {
    expect(indexHtml).toMatch(/const MARKER_STYLE_DESCRIPTIONS\s*=/);
    expect(indexHtml).toMatch(/'circle'\s*:/);
    expect(indexHtml).toMatch(/'squircle'\s*:/);
    expect(indexHtml).toMatch(/'teardrop'\s*:/);
    expect(indexHtml).toMatch(/'glyph'\s*:/);
    expect(indexHtml).toMatch(/'pill'\s*:/);
  });

  test('CSS rule .marker-icon.style-squircle exists', () => {
    expect(indexHtml).toMatch(/\.marker-icon\.style-squircle\s*\{/);
  });

  test('CSS rule .marker-icon.style-teardrop exists', () => {
    expect(indexHtml).toMatch(/\.marker-icon\.style-teardrop\s*\{/);
  });

  test('CSS rule .marker-icon.style-glyph exists', () => {
    expect(indexHtml).toMatch(/\.marker-icon\.style-glyph\s*\{/);
  });

  test('CSS rule .marker-icon.style-pill exists', () => {
    expect(indexHtml).toMatch(/\.marker-icon\.style-pill\s*\{/);
  });
});

describe('Marker style variants — createMarkerIcon vm-sandbox', () => {
  function makeStyleCtx(markerStyle) {
    const divIconCalls = [];
    const ctx = vm.createContext({
      L: { divIcon: (opts) => { divIconCalls.push(opts); return opts; } },
      CATEGORIES: { restaurant: { color: 'red', label: 'Food', emoji: '🍽️' }, location: { color: 'gray', label: 'Place', emoji: '📍' } },
      COLOR_HEX: { red: '#ef4444', gray: '#888888' },
      DEFAULT_HEX: '#888888',
      computeMarkerSize: () => 34,
      pickMarkerEmoji: () => '🍽️',
      esc: (s) => String(s).replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c])),
      state: { markerSizeMode: 'default', markerStyle },
    });
    vm.runInContext(extractFunction('createMarkerIcon'), ctx);
    return { ctx, divIconCalls };
  }

  test('circle style → no style- class suffix', () => {
    const { ctx, divIconCalls } = makeStyleCtx('circle');
    vm.runInContext(`createMarkerIcon({ status: 'been', category: 'restaurant' }, {})`, ctx);
    const html = divIconCalls[0].html;
    expect(html).toMatch(/class="marker-icon been"/);
    expect(html).not.toContain('style-');
  });

  test('squircle style → class contains style-squircle', () => {
    const { ctx, divIconCalls } = makeStyleCtx('squircle');
    vm.runInContext(`createMarkerIcon({ status: 'been', category: 'restaurant' }, {})`, ctx);
    const html = divIconCalls[0].html;
    expect(html).toContain('style-squircle');
  });

  test('teardrop style → class contains style-teardrop, bottom-anchored (iconAnchor.y >= iconSize.y * 0.7)', () => {
    const { ctx, divIconCalls } = makeStyleCtx('teardrop');
    vm.runInContext(`createMarkerIcon({ status: 'been', category: 'restaurant' }, {})`, ctx);
    const result = divIconCalls[0];
    expect(result.html).toContain('style-teardrop');
    expect(result.iconAnchor[1]).toBeGreaterThanOrEqual(result.iconSize[1] * 0.7);
  });

  test('glyph style → class contains style-glyph, html includes color: inline style for dot', () => {
    const { ctx, divIconCalls } = makeStyleCtx('glyph');
    vm.runInContext(`createMarkerIcon({ status: 'been', category: 'restaurant' }, {})`, ctx);
    const result = divIconCalls[0];
    expect(result.html).toContain('style-glyph');
    expect(result.html).toMatch(/color:#ef4444/);
  });

  test('glyph style → bottom-anchored (iconAnchor.y >= iconSize.y * 0.7)', () => {
    const { ctx, divIconCalls } = makeStyleCtx('glyph');
    vm.runInContext(`createMarkerIcon({ status: 'been', category: 'restaurant' }, {})`, ctx);
    const result = divIconCalls[0];
    expect(result.iconAnchor[1]).toBeGreaterThanOrEqual(result.iconSize[1] * 0.7);
  });

  test('pill style with rating → contains style-pill and pill-rating span with ★ value', () => {
    const { ctx, divIconCalls } = makeStyleCtx('pill');
    vm.runInContext(`createMarkerIcon({ status: 'been', category: 'restaurant', googleRating: 4.7 }, {})`, ctx);
    const html = divIconCalls[0].html;
    expect(html).toContain('style-pill');
    expect(html).toContain('pill-rating');
    expect(html).toContain('★ 4.7');
  });

  test('pill style without rating → no pill-rating span', () => {
    const { ctx, divIconCalls } = makeStyleCtx('pill');
    vm.runInContext(`createMarkerIcon({ status: 'been', category: 'restaurant' }, {})`, ctx);
    const html = divIconCalls[0].html;
    expect(html).toContain('style-pill');
    expect(html).not.toContain('pill-rating');
  });

  test('missing markerStyle defaults to circle behaviour (no style- suffix)', () => {
    // Simulates legacy state objects that predate this feature.
    const { ctx, divIconCalls } = makeStyleCtx(undefined);
    vm.runInContext(`createMarkerIcon({ status: 'been', category: 'restaurant' }, {})`, ctx);
    const html = divIconCalls[0].html;
    expect(html).not.toContain('style-');
  });
});

describe('Marker style variants — setMarkerStyle behaviour', () => {
  // makeSetStyleCtx(populatedRegistry?) — when populated, the in-place fast
  // path (`updateAllMarkerIcons`) is exercised; otherwise the renderMarkers
  // fallback runs. Shape mirrors the contract codified in
  // tests/marker-icon-inplace.test.js.
  function makeSetStyleCtx(populatedRegistry = false) {
    const lsStore = {};
    const renderCalls = [];
    const setIconCalls = [];
    const descEl = { textContent: '' };
    const markerById = new Map();
    const stateLocations = [];
    if (populatedRegistry) {
      const loc = { id: 'L0', status: 'been', category: 'restaurant' };
      stateLocations.push(loc);
      markerById.set('L0', { marker: { setIcon: (icon) => { setIconCalls.push(icon); } }, hash: 'h' });
    }
    const renderStateRef = { markerById, markerStyle: 'circle', markerSizeMode: 'default', mapStyle: 'cluster' };
    const ctx = vm.createContext({
      VALID_MARKER_STYLES: ['circle', 'squircle', 'teardrop', 'glyph', 'pill'],
      MARKER_STYLE_DESCRIPTIONS: {
        'circle':   'Classic round marker (default)',
        'squircle': 'iOS-style rounded square stamp',
        'teardrop': 'Apple Maps pin — point lands at coord',
        'glyph':    'Minimal floating emoji with anchor dot',
        'pill':     'Horizontal chip with rating inline',
      },
      VALID_MARKER_SIZE_MODES: ['default', 'my-rating', 'google-pop', 'visits', 'bucket'],
      state: { markerStyle: 'circle', markerSizeMode: 'default', mapStyle: 'cluster', locations: stateLocations },
      stateIndex: { locationById: new Map(stateLocations.map(l => [l.id, l])) },
      createMarkerIcon: () => ({ __icon: true }),
      localStorage: {
        getItem: (k) => lsStore[k] || null,
        setItem: (k, v) => { lsStore[k] = v; },
      },
      document: { getElementById: (id) => id === 'marker-style-desc' ? descEl : null },
      _renderState: renderStateRef,
      renderMarkers: () => { renderCalls.push(1); },
      lsStore,
      renderCalls,
      setIconCalls,
      renderStateRef,
    });
    vm.runInContext(extractFunction('updateAllMarkerIcons'), ctx);
    vm.runInContext(extractFunction('setMarkerStyle'), ctx);
    return ctx;
  }

  test('valid style updates state.markerStyle + persists to localStorage', () => {
    const ctx = makeSetStyleCtx();
    vm.runInContext(`setMarkerStyle('squircle')`, ctx);
    expect(ctx.state.markerStyle).toBe('squircle');
    expect(ctx.lsStore['markerStyle']).toBe('squircle');
  });

  test('invalid style falls back to circle', () => {
    const ctx = makeSetStyleCtx();
    vm.runInContext(`setMarkerStyle('bogus')`, ctx);
    expect(ctx.state.markerStyle).toBe('circle');
    expect(ctx.lsStore['markerStyle']).toBe('circle');
  });

  test('populated registry → in-place setIcon path, _renderState.markerStyle updated (no cache-bust to null)', () => {
    const ctx = makeSetStyleCtx(true);
    vm.runInContext(`setMarkerStyle('glyph')`, ctx);
    expect(ctx.setIconCalls.length).toBe(1);
    expect(ctx.renderCalls.length).toBe(0);
    expect(ctx.renderStateRef.markerStyle).toBe('glyph');
  });

  test('empty registry → falls back to renderMarkers', () => {
    const ctx = makeSetStyleCtx(false);
    vm.runInContext(`setMarkerStyle('pill')`, ctx);
    expect(ctx.renderCalls.length).toBeGreaterThanOrEqual(1);
  });

  test('setMarkerStyle updates the description element text', () => {
    const ctx = makeSetStyleCtx();
    vm.runInContext(`setMarkerStyle('teardrop')`, ctx);
    expect(ctx.document.getElementById('marker-style-desc').textContent).toMatch(/Apple Maps/);
  });
});
