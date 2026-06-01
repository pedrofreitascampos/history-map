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
