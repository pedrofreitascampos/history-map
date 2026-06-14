// Time-of-day / day-of-week / month-of-year visit timing charts.

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
describe('Timing charts — static markup', () => {
  test('#chart-dow canvas exists in stats view', () => {
    expect(indexHtml).toContain('id="chart-dow"');
  });

  test('#chart-month canvas exists in stats view', () => {
    expect(indexHtml).toContain('id="chart-month"');
  });

  test('#timing-cat-filter select exists', () => {
    expect(indexHtml).toContain('id="timing-cat-filter"');
  });

  test('timing-cat-filter wired to onTimingCatFilter', () => {
    expect(indexHtml).toMatch(/id="timing-cat-filter"[^>]*data-change="onTimingCatFilter"/);
  });

  test('renderTimingCharts function defined', () => {
    expect(indexHtml).toContain('function renderTimingCharts(');
  });

  test('onTimingCatFilter function defined', () => {
    expect(indexHtml).toContain('function onTimingCatFilter(');
  });

  test('chartDow and chartMonth declared', () => {
    expect(indexHtml).toMatch(/let chartRatings.*chartDow.*chartMonth/);
  });

  test('renderTimingCharts called from renderCharts', () => {
    const fn = extractFunction('renderCharts');
    expect(fn).toContain('renderTimingCharts');
  });

  test('"When Do You Visit?" heading present in stats view', () => {
    expect(indexHtml).toContain('When Do You Visit?');
  });

  test('"Day of week" and "Month of year" labels present', () => {
    expect(indexHtml).toContain('Day of week');
    expect(indexHtml).toContain('Month of year');
  });
});

// ── renderTimingCharts logic (vm) ─────────────────────────────────────────
function runTimingCharts(locations, catFilter) {
  // Minimal Chart stub that captures data passed to it
  const chartInstances = {};
  const ChartStub = function(el, config) {
    chartInstances[el] = config;
    this.data = config.data;
    this.update = () => {};
  };

  const code = [
    extractFunction('renderTimingCharts'),
    `__r = (function() {
      const DOW_ORDER = [1,2,3,4,5,6,0];
      const dow = new Array(7).fill(0);
      const mon = new Array(12).fill(0);
      for (const loc of __locs) {
        if (loc.needsApproval || loc.status !== 'been') continue;
        if (__cat && loc.category !== __cat) continue;
        for (const v of (loc.visits || [])) {
          if (!v.date) continue;
          const d = new Date(v.date + 'T12:00:00');
          if (isNaN(d.getTime())) continue;
          dow[d.getDay()]++;
          mon[d.getMonth()]++;
        }
      }
      return { dow, mon, dowData: DOW_ORDER.map(i => dow[i]) };
    })();`,
  ].join('\n');

  const ctx = vm.createContext({
    state: { locations },
    Chart: ChartStub,
    chartDow: null, chartMonth: null,
    document: { getElementById: () => null },
    isNaN, Date, Array, Number,
    __locs: locations, __cat: catFilter,
    __r: null,
  });
  vm.runInContext(code, ctx);
  return ctx.__r;
}

// Build test locations with known day-of-week visits
// 2024-01-01 = Monday (getDay=1), 2024-01-06 = Saturday (getDay=6), 2024-03-10 = Sunday (getDay=0)
const LOC_MONDAY = { status: 'been', category: 'restaurant', visits: [{ date: '2024-01-01' }] };
const LOC_SATURDAY = { status: 'been', category: 'restaurant', visits: [{ date: '2024-01-06' }] };
const LOC_SUNDAY = { status: 'been', category: 'museum', visits: [{ date: '2024-03-10' }] };
const LOC_BUCKET = { status: 'bucket', category: 'restaurant', visits: [{ date: '2024-01-01' }] };
const LOC_MARCH = { status: 'been', category: 'park', visits: [{ date: '2024-03-15' }] };

describe('Timing charts — day-of-week computation', () => {
  test('Monday visit increments index 1 (JS getDay=1)', () => {
    const { dow } = runTimingCharts([LOC_MONDAY], '');
    expect(dow[1]).toBe(1);
    expect(dow.reduce((a, b) => a + b, 0)).toBe(1);
  });

  test('Saturday visit increments index 6 (JS getDay=6)', () => {
    const { dow } = runTimingCharts([LOC_SATURDAY], '');
    expect(dow[6]).toBe(1);
  });

  test('Sunday visit increments index 0 (JS getDay=0)', () => {
    const { dow } = runTimingCharts([LOC_SUNDAY], '');
    expect(dow[0]).toBe(1);
  });

  test('bucket locations excluded', () => {
    const { dow } = runTimingCharts([LOC_BUCKET], '');
    expect(dow.reduce((a, b) => a + b, 0)).toBe(0);
  });

  test('dowData is Monday-first (Mon index 0, Sun index 6)', () => {
    // Monday visit → dowData[0] (Mon position) should be 1
    const { dowData } = runTimingCharts([LOC_MONDAY], '');
    expect(dowData[0]).toBe(1); // Mon
    // Sunday visit
    const { dowData: d2 } = runTimingCharts([LOC_SUNDAY], '');
    expect(d2[6]).toBe(1); // Sun is last
  });

  test('category filter restricts counts', () => {
    const { dow: all } = runTimingCharts([LOC_MONDAY, LOC_SUNDAY], '');
    const { dow: rest } = runTimingCharts([LOC_MONDAY, LOC_SUNDAY], 'restaurant');
    expect(all.reduce((a, b) => a + b, 0)).toBe(2);
    expect(rest.reduce((a, b) => a + b, 0)).toBe(1);
  });
});

describe('Timing charts — month-of-year computation', () => {
  test('January visit → mon[0]', () => {
    const { mon } = runTimingCharts([LOC_MONDAY], '');
    expect(mon[0]).toBe(1);
  });

  test('March visit → mon[2]', () => {
    const { mon } = runTimingCharts([LOC_MARCH], '');
    expect(mon[2]).toBe(1);
  });

  test('multiple months accumulated correctly', () => {
    const { mon } = runTimingCharts([LOC_MONDAY, LOC_SATURDAY, LOC_MARCH], '');
    expect(mon[0]).toBe(2); // Jan (LOC_MONDAY + LOC_SATURDAY)
    expect(mon[2]).toBe(1); // Mar (LOC_MARCH)
  });

  test('invalid date strings skipped without error', () => {
    const locBad = { status: 'been', category: 'restaurant', visits: [{ date: 'not-a-date' }] };
    const { mon } = runTimingCharts([locBad, LOC_MONDAY], '');
    expect(mon[0]).toBe(1); // only valid visit counted
  });
});
