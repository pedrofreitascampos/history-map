// Trip cost tracker — cost fields on stops + transits → per-trip + per-year roll-up.

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
describe('Trip cost — static markup', () => {
  test('#loc-cost input exists in location modal', () => {
    expect(indexHtml).toContain('id="loc-cost"');
  });

  test('#loc-cost is a number input', () => {
    const idx = indexHtml.indexOf('id="loc-cost"');
    const tag = indexHtml.slice(idx - 50, idx + 80);
    expect(tag).toContain('type="number"');
  });

  test('#transit-cost input exists in transit modal', () => {
    expect(indexHtml).toContain('id="transit-cost"');
  });

  test('#transit-cost is a number input', () => {
    const idx = indexHtml.indexOf('id="transit-cost"');
    const tag = indexHtml.slice(idx - 50, idx + 80);
    expect(tag).toContain('type="number"');
  });

  test('_tripTotalCost function defined', () => {
    expect(indexHtml).toContain('function _tripTotalCost(');
  });

  test('saveLocation includes cost in payload', () => {
    const fn = extractFunction('saveLocation');
    expect(fn).toContain('loc-cost');
    expect(fn).toContain('cost:');
  });

  test('saveTransit includes cost in payload', () => {
    const fn = extractFunction('saveTransit');
    expect(fn).toContain('transit-cost');
    expect(fn).toContain('cost:');
  });

  test('renderTripDetail calls _tripTotalCost', () => {
    const fn = extractFunction('renderTripDetail');
    expect(fn).toContain('_tripTotalCost');
  });

  test('renderTripDetail shows cost in stats grid', () => {
    const fn = extractFunction('renderTripDetail');
    expect(fn).toContain('Cost');
    expect(fn).toContain('costDisplay');
  });

  test('#stats-cost-section exists in stats view', () => {
    expect(indexHtml).toContain('id="stats-cost-section"');
  });

  test('#stats-cost-list exists', () => {
    expect(indexHtml).toContain('id="stats-cost-list"');
  });

  test('renderStats populates stats-cost-section', () => {
    const fn = extractFunction('renderStats');
    expect(fn).toContain('stats-cost-section');
    expect(fn).toContain('costByYear');
  });
});

// ── _tripTotalCost logic (vm) ─────────────────────────────────────────────
function runTripCost(tripId, locationsByTrip, transitsByTrip) {
  const code = [
    extractFunction('_tripTotalCost'),
    `__r = _tripTotalCost(${JSON.stringify(tripId)});`,
  ].join('\n');
  const ctx = vm.createContext({
    Number, Math,
    stateIndex: {
      locationsByTrip: new Map(Object.entries(locationsByTrip)),
      transitsByTrip: new Map(Object.entries(transitsByTrip)),
    },
    __r: null,
  });
  vm.runInContext(code, ctx);
  return ctx.__r;
}

describe('Trip cost — _tripTotalCost', () => {
  test('sums stop costs', () => {
    const r = runTripCost('t1',
      { t1: [{ cost: 20 }, { cost: 30 }] },
      { t1: [] });
    expect(r).toBe(50);
  });

  test('sums transit costs', () => {
    const r = runTripCost('t1',
      { t1: [] },
      { t1: [{ cost: 120 }, { cost: 80 }] });
    expect(r).toBe(200);
  });

  test('sums stops + transits together', () => {
    const r = runTripCost('t1',
      { t1: [{ cost: 45 }] },
      { t1: [{ cost: 120 }] });
    expect(r).toBe(165);
  });

  test('ignores null/undefined cost fields', () => {
    const r = runTripCost('t1',
      { t1: [{ cost: null }, { cost: 50 }, { name: 'no cost' }] },
      { t1: [{ cost: undefined }, { cost: 30 }] });
    expect(r).toBe(80);
  });

  test('returns 0 when no costs set', () => {
    const r = runTripCost('t1', { t1: [{ name: 'X' }] }, { t1: [] });
    expect(r).toBe(0);
  });

  test('returns 0 for unknown tripId', () => {
    const r = runTripCost('unknown', { t1: [{ cost: 50 }] }, {});
    expect(r).toBe(0);
  });

  test('ignores NaN cost values', () => {
    const r = runTripCost('t1',
      { t1: [{ cost: NaN }, { cost: 40 }] },
      { t1: [] });
    expect(r).toBe(40);
  });
});
