// Plan view (replaced Wishlist tab) — static markup + planner logic.

const path = require('path');
const fs = require('fs');
const vm = require('vm');

const indexHtml = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');

function extractFunction(name) {
  const start = indexHtml.indexOf(`function ${name}(`);
  if (start === -1) throw new Error(`Function ${name} not found`);
  let depth = 0, i = start, found = false;
  for (; i < indexHtml.length; i++) {
    if (indexHtml[i] === '{') { depth++; found = true; }
    if (indexHtml[i] === '}') depth--;
    if (found && depth === 0) break;
  }
  return indexHtml.substring(start, i + 1);
}

// ── Static markup ─────────────────────────────────────────────────────────
describe('Plan view — static markup', () => {
  test('nav tab data-view="plan-view" exists', () => {
    expect(indexHtml).toMatch(/data-view="plan-view"/);
  });

  test('nav tab has Plan label', () => {
    const idx = indexHtml.indexOf('data-view="plan-view"');
    const tag = indexHtml.slice(idx, idx + 120);
    expect(tag).toContain('Plan');
  });

  test('<div class="view" id="plan-view"> exists', () => {
    expect(indexHtml).toContain('id="plan-view"');
  });

  test('#plan-status select exists', () => {
    expect(indexHtml).toContain('id="plan-status"');
  });

  test('#plan-min-rating select exists', () => {
    expect(indexHtml).toContain('id="plan-min-rating"');
  });

  test('#plan-max-km select exists', () => {
    expect(indexHtml).toContain('id="plan-max-km"');
  });

  test('#plan-cat-chips container exists', () => {
    expect(indexHtml).toContain('id="plan-cat-chips"');
  });

  test('#plan-party-chips container exists', () => {
    expect(indexHtml).toContain('id="plan-party-chips"');
  });

  test('#plan-results container exists', () => {
    expect(indexHtml).toContain('id="plan-results"');
  });

  test('#plan-cards container exists', () => {
    expect(indexHtml).toContain('id="plan-cards"');
  });

  test('generateItineraries button wired up', () => {
    expect(indexHtml).toMatch(/data-click="generateItineraries"/);
  });

  test('all plan functions defined', () => {
    ['renderPlanView', 'togglePlanCat', 'setPlanParty', '_plannerPool',
     '_greedyRoute', 'generateItineraries', '_renderPlanCards', 'usePlanItinerary']
      .forEach(fn => expect(indexHtml).toContain(`function ${fn}(`));
  });

  test('plan-view in VIEW_HASHES', () => {
    expect(indexHtml).toMatch(/'plan-view'\s*:\s*'plan'/);
  });

  test('switchView calls renderPlanView for plan-view', () => {
    const fn = extractFunction('switchView');
    expect(fn).toContain('renderPlanView');
  });

  test('wishlist-view no longer in nav', () => {
    expect(indexHtml).not.toContain('data-view="wishlist-view"');
  });
});

// ── _greedyRoute logic (vm) ───────────────────────────────────────────────
function runGreedy(pool, startLat, startLng, maxStops, maxKmBetween) {
  const code = [
    `function haversineKm(lat1, lng1, lat2, lng2) {
      return Math.sqrt(Math.pow(lat2-lat1,2)+Math.pow(lng2-lng1,2));
    }`,
    extractFunction('_greedyRoute'),
    `__r = _greedyRoute(${JSON.stringify(pool)}, ${startLat}, ${startLng}, ${maxStops}, ${maxKmBetween});`,
  ].join('\n');
  const ctx = vm.createContext({ Math, Infinity, __r: null });
  vm.runInContext(code, ctx);
  return ctx.__r;
}

const POOL = [
  { lat: 0, lng: 1, name: 'A' },
  { lat: 0, lng: 3, name: 'B' },
  { lat: 0, lng: 2, name: 'C' },
];

describe('Plan view — _greedyRoute', () => {
  test('picks nearest first stop', () => {
    const r = runGreedy(POOL, 0, 0, 3, 99);
    expect(r[0].name).toBe('A');
  });

  test('picks next nearest from last stop', () => {
    const r = runGreedy(POOL, 0, 0, 3, 99);
    expect(r[1].name).toBe('C');
    expect(r[2].name).toBe('B');
  });

  test('respects maxStops', () => {
    expect(runGreedy(POOL, 0, 0, 2, 99)).toHaveLength(2);
  });

  test('respects maxKmBetween — next stop out of range not picked', () => {
    // A at dist 1 from origin (within 2); then B is 10 units from A (outside 2)
    const isolated = [
      { lat: 0, lng: 1, name: 'A' },
      { lat: 0, lng: 11, name: 'B' },
    ];
    const r = runGreedy(isolated, 0, 0, 3, 2);
    expect(r).toHaveLength(1);
    expect(r[0].name).toBe('A');
  });

  test('empty pool returns empty array', () => {
    expect(runGreedy([], 0, 0, 5, 99)).toHaveLength(0);
  });

  test('single item returns that item', () => {
    const r = runGreedy([{ lat: 0, lng: 1, name: 'X' }], 0, 0, 3, 99);
    expect(r).toHaveLength(1);
    expect(r[0].name).toBe('X');
  });
});
