// People lens in Chronology (#10).
// Static markup + _buildPeopleColorMap logic.

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
describe('People lens — static markup', () => {
  test('#chrono-person select exists', () => {
    expect(html).toContain('id="chrono-person"');
  });

  test('#chrono-people-toggle button exists', () => {
    expect(html).toContain('id="chrono-people-toggle"');
  });

  test('chrono-people-toggle wired to toggleChronoPeopleLens', () => {
    expect(html).toMatch(/id="chrono-people-toggle"[^>]*data-click="toggleChronoPeopleLens"/);
  });

  test('#people-legend container exists', () => {
    expect(html).toContain('id="people-legend"');
  });

  test('_buildPeopleColorMap function defined', () => {
    expect(html).toContain('function _buildPeopleColorMap(');
  });

  test('toggleChronoPeopleLens function defined', () => {
    expect(html).toContain('function toggleChronoPeopleLens(');
  });

  test('PEOPLE_COLORS palette defined', () => {
    expect(html).toMatch(/const PEOPLE_COLORS\s*=/);
    expect(html).toContain('#6366f1');
  });

  test('_chronoPeopleLens state variable declared', () => {
    expect(html).toMatch(/let _chronoPeopleLens\s*=\s*false/);
  });

  test('person filter applied in renderChronology', () => {
    const fn = extractFunction('renderChronology');
    expect(fn).toContain('chrono-person');
    expect(fn).toContain('personFilter');
  });

  test('peopleColorMap used in renderChronology', () => {
    const fn = extractFunction('renderChronology');
    expect(fn).toContain('peopleColorMap');
    expect(fn).toContain('_buildPeopleColorMap');
  });

  test('people-legend populated in renderChronology', () => {
    const fn = extractFunction('renderChronology');
    expect(fn).toContain('people-legend');
    expect(fn).toContain('people-legend-chip');
  });

  test('populateChronoFilters populates #chrono-person', () => {
    const fn = extractFunction('populateChronoFilters');
    expect(fn).toContain('chrono-person');
  });

  test('laneStyle applied to timeline items when lens active', () => {
    const fn = extractFunction('renderChronology');
    expect(fn).toContain('laneStyle');
    expect(fn).toContain('box-shadow');
  });
});

// ── _buildPeopleColorMap logic (vm) ──────────────────────────────────────
function runBuildColorMap(entries) {
  const colorsDecl = html.match(/const PEOPLE_COLORS\s*=\s*\[[^\]]+\]/)[0];
  const code = [
    colorsDecl + ';',
    extractFunction('_buildPeopleColorMap'),
    `__result = _buildPeopleColorMap(${JSON.stringify(entries)});`,
  ].join('\n');
  const ctx = vm.createContext({ Map, Array, JSON, __result: null });
  vm.runInContext(code, ctx);
  return ctx.__result;
}

describe('People lens — _buildPeopleColorMap', () => {
  test('returns empty map when no entries have people', () => {
    const entries = [
      { loc: { people: [] } },
      { loc: { people: null } },
      { loc: {} },
    ];
    const map = runBuildColorMap(entries);
    expect(map.size).toBe(0);
  });

  test('assigns distinct colors to different people', () => {
    const entries = [
      { loc: { people: ['Alice', 'Bob'] } },
      { loc: { people: ['Charlie'] } },
    ];
    const map = runBuildColorMap(entries);
    expect(map.size).toBe(3);
    const colors = [...map.values()];
    // All colors assigned
    colors.forEach(c => expect(c).toMatch(/^#[0-9a-f]{6}$/));
    // Alice and Bob get different colors (sorted: Alice < Bob < Charlie)
    expect(map.get('Alice')).not.toBe(map.get('Bob'));
  });

  test('names are sorted alphabetically so assignment is stable', () => {
    const entries1 = [{ loc: { people: ['Zara', 'Alice'] } }];
    const entries2 = [{ loc: { people: ['Alice', 'Zara'] } }];
    const map1 = runBuildColorMap(entries1);
    const map2 = runBuildColorMap(entries2);
    expect(map1.get('Alice')).toBe(map2.get('Alice'));
    expect(map1.get('Zara')).toBe(map2.get('Zara'));
  });

  test('wraps color assignment for more than 8 people', () => {
    const names = ['A','B','C','D','E','F','G','H','I'];
    const entries = [{ loc: { people: names } }];
    const map = runBuildColorMap(entries);
    expect(map.size).toBe(9);
    // 9th person (I) wraps to same color as 1st (A)
    expect(map.get('I')).toBe(map.get('A'));
  });

  test('deduplicates person names across entries', () => {
    const entries = [
      { loc: { people: ['Alice'] } },
      { loc: { people: ['Alice', 'Bob'] } },
    ];
    const map = runBuildColorMap(entries);
    expect(map.size).toBe(2);
  });
});
