// Isochrones (#8) — travel-time reachability rings.
// Static markup + panel state / time-toggle logic.

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
describe('Isochrones — static markup', () => {
  test('#iso-panel exists in map-view', () => {
    expect(html).toContain('id="iso-panel"');
  });

  test('#iso-mode-group exists', () => {
    expect(html).toContain('id="iso-mode-group"');
  });

  test('#iso-time-chips exists', () => {
    expect(html).toContain('id="iso-time-chips"');
  });

  test('#iso-status exists', () => {
    expect(html).toContain('id="iso-status"');
  });

  test('Walk / Bike / Drive buttons present', () => {
    expect(html).toMatch(/data-arg0="pedestrian"/);
    expect(html).toMatch(/data-arg0="bicycle"/);
    expect(html).toMatch(/data-arg0="auto"/);
  });

  test('15 / 30 / 45 time-chip buttons present', () => {
    expect(html).toMatch(/data-arg0="15"[\s\S]*?toggleIsoTime|toggleIsoTime[\s\S]*?data-arg0="15"/);
    expect(html).toMatch(/data-arg0="30"[\s\S]*?toggleIsoTime|toggleIsoTime[\s\S]*?data-arg0="30"/);
    expect(html).toMatch(/data-arg0="45"[\s\S]*?toggleIsoTime|toggleIsoTime[\s\S]*?data-arg0="45"/);
  });

  test('drawIsochrones button wired', () => {
    expect(html).toMatch(/data-click="drawIsochrones"/);
  });

  test('clearIsochrones button wired', () => {
    expect(html).toMatch(/data-click="clearIsochrones"/);
  });

  test('toggleIsoPanel button in MapToolsControl (iso-btn)', () => {
    expect(html).toContain('id="iso-btn"');
    expect(html).toMatch(/data-click="toggleIsoPanel"/);
  });

  test('all isochrone functions defined', () => {
    ['toggleIsoPanel', 'closeIsoPanel', 'setIsoMode', 'toggleIsoTime', 'drawIsochrones', 'clearIsochrones']
      .forEach(fn => expect(html).toContain(`function ${fn}(`));
  });

  test('Valhalla endpoint referenced in drawIsochrones', () => {
    const fn = extractFunction('drawIsochrones');
    expect(fn).toContain('valhalla1.openstreetmap.de');
  });

  test('_isoLayers state variable declared', () => {
    expect(html).toMatch(/let _isoLayers\s*=/);
  });

  test('_isoMode state variable declared', () => {
    expect(html).toMatch(/let _isoMode\s*=/);
  });

  test('_isoTimes state variable declared as Set', () => {
    expect(html).toMatch(/let _isoTimes\s*=\s*new Set/);
  });
});

// ── CSP ───────────────────────────────────────────────────────────────────
describe('Isochrones — CSP', () => {
  test('server/index.js connectSrc includes valhalla1.openstreetmap.de', () => {
    const serverJs = fs.readFileSync(path.join(__dirname, '..', 'server', 'index.js'), 'utf-8');
    expect(serverJs).toContain('valhalla1.openstreetmap.de');
  });
});

// ── toggleIsoTime logic (vm) ──────────────────────────────────────────────
function runToggleIsoTime(initialTimes, t) {
  const ctx = vm.createContext({ Number, Set, _isoTimes: new Set(initialTimes), btn: { classList: { add() {}, remove() {} } } });
  vm.runInContext(extractFunction('toggleIsoTime'), ctx);
  vm.runInContext(`toggleIsoTime(${t}, btn)`, ctx);
  return ctx._isoTimes;
}

describe('Isochrones — toggleIsoTime', () => {
  test('adds a new time', () => {
    const times = runToggleIsoTime([15, 30], 45);
    expect(times.has(45)).toBe(true);
    expect(times.has(15)).toBe(true);
    expect(times.has(30)).toBe(true);
  });

  test('removes a time when > 1 selected', () => {
    const times = runToggleIsoTime([15, 30], 30);
    expect(times.has(30)).toBe(false);
    expect(times.has(15)).toBe(true);
  });

  test('does NOT remove last remaining time', () => {
    const times = runToggleIsoTime([15], 15);
    expect(times.has(15)).toBe(true);
  });
});
