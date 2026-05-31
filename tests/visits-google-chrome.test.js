// Regression coverage for the 2026-05-31 batch:
//   1. Visit removal + expand/custom-date (previously the modal Visits section
//      was collapsed to a read-only summary — users could not remove visits).
//   2. Provider-respecting Google chrome (modal sync btn, bulk sync btn,
//      import auto-sync label all hide unless provider === 'google' AND key).
//   3. Discoverable Timeline import button on Import view.
//
// vm-sandbox pattern, mirrors tests/trips-v2.test.js / tests/photos-exif.test.js.

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
function extractAsyncFunction(name) {
  const start = indexHtml.indexOf(`async function ${name}(`);
  if (start === -1) throw new Error(`Async function ${name} not found`);
  let depth = 0, i = start, foundFirst = false;
  for (; i < indexHtml.length; i++) {
    if (indexHtml[i] === '{') { depth++; foundFirst = true; }
    if (indexHtml[i] === '}') depth--;
    if (foundFirst && depth === 0) break;
  }
  return indexHtml.substring(start, i + 1);
}

let JSDOM;
try { JSDOM = require('jsdom').JSDOM; } catch { JSDOM = null; }
const describeDom = JSDOM ? describe : describe.skip;

describeDom('Visits modal: expand / custom-date / remove (regression)', () => {
  function makeCtx() {
    const dom = new JSDOM(`<!DOCTYPE html><html><body>
      <div id="loc-visits-summary" data-click="toggleVisitsExpanded" aria-expanded="false">
        <span id="loc-visits-chevron">▶</span>
        <span id="loc-visits-summary-text"></span>
      </div>
      <div id="loc-visits-list" style="display:none;"></div>
      <input id="loc-visit-custom-date" type="date">
    </body></html>`);
    const ctx = vm.createContext({
      document: dom.window.document,
      console,
      Date, Array, Object, JSON, Math,
      state: { modalVisits: [] },
      showToast: () => {},
    });
    const code = [
      extractFunction('renderVisitFields'),
      extractFunction('toggleVisitsExpanded'),
      extractFunction('addTodayVisit'),
      extractFunction('addCustomVisit'),
      extractFunction('removeVisit'),
    ].join('\n');
    vm.runInContext(code, ctx);
    return { ctx, dom };
  }

  test('empty state shows "No visits logged yet"', () => {
    const { ctx, dom } = makeCtx();
    vm.runInContext('renderVisitFields()', ctx);
    expect(dom.window.document.getElementById('loc-visits-summary-text').textContent)
      .toMatch(/No visits logged yet/);
  });

  test('summary shows newest-first last-visited date and total count', () => {
    const { ctx, dom } = makeCtx();
    ctx.state.modalVisits = [
      { date: '2024-01-10', notes: '' },
      { date: '2024-06-22', notes: '' },
      { date: '2023-03-04', notes: '' },
    ];
    vm.runInContext('renderVisitFields()', ctx);
    const txt = dom.window.document.getElementById('loc-visits-summary-text').textContent;
    expect(txt).toContain('Last visited 2024-06-22');
    expect(txt).toContain('3 visits total');
  });

  test('toggleVisitsExpanded flips display + chevron rotation + aria-expanded', () => {
    const { ctx, dom } = makeCtx();
    const list = dom.window.document.getElementById('loc-visits-list');
    const chevron = dom.window.document.getElementById('loc-visits-chevron');
    const summary = dom.window.document.getElementById('loc-visits-summary');
    expect(list.style.display).toBe('none');
    vm.runInContext('toggleVisitsExpanded()', ctx);
    expect(list.style.display).toBe('flex');
    expect(chevron.style.transform).toContain('rotate(90deg)');
    expect(summary.getAttribute('aria-expanded')).toBe('true');
    vm.runInContext('toggleVisitsExpanded()', ctx);
    expect(list.style.display).toBe('none');
    expect(summary.getAttribute('aria-expanded')).toBe('false');
  });

  test('expanded list renders one row with × button + date input per visit', () => {
    const { ctx, dom } = makeCtx();
    ctx.state.modalVisits = [
      { date: '2024-01-10', notes: '' },
      { date: '2024-06-22', notes: '' },
    ];
    vm.runInContext('renderVisitFields()', ctx);
    const list = dom.window.document.getElementById('loc-visits-list');
    expect(list.querySelectorAll('input[type=date]').length).toBe(2);
    expect(list.querySelectorAll('button').length).toBe(2);
    // Sorted newest-first.
    expect(list.querySelectorAll('input[type=date]')[0].value).toBe('2024-06-22');
    expect(list.querySelectorAll('input[type=date]')[1].value).toBe('2024-01-10');
  });

  test('removeVisit drops the entry from state.modalVisits and re-renders', () => {
    const { ctx, dom } = makeCtx();
    ctx.state.modalVisits = [
      { date: '2024-01-10', notes: '' },
      { date: '2024-06-22', notes: '' },
      { date: '2023-03-04', notes: '' },
    ];
    vm.runInContext('removeVisit(1)', ctx);
    expect(ctx.state.modalVisits.map(v => v.date)).toEqual(['2024-01-10', '2023-03-04']);
    // Out-of-bounds is a safe no-op.
    vm.runInContext('removeVisit(99)', ctx);
    vm.runInContext('removeVisit(-1)', ctx);
    expect(ctx.state.modalVisits.length).toBe(2);
  });

  test('addCustomVisit pushes the picked date and clears the input', () => {
    const { ctx, dom } = makeCtx();
    const input = dom.window.document.getElementById('loc-visit-custom-date');
    input.value = '2022-05-15';
    vm.runInContext('addCustomVisit()', ctx);
    expect(ctx.state.modalVisits.map(v => v.date)).toEqual(['2022-05-15']);
    expect(input.value).toBe('');
  });

  test('addCustomVisit refuses duplicate dates', () => {
    const { ctx, dom } = makeCtx();
    ctx.state.modalVisits = [{ date: '2022-05-15', notes: '' }];
    const input = dom.window.document.getElementById('loc-visit-custom-date');
    input.value = '2022-05-15';
    vm.runInContext('addCustomVisit()', ctx);
    expect(ctx.state.modalVisits.length).toBe(1);
  });

  test('addTodayVisit pushes today and is idempotent on the same day', () => {
    const { ctx } = makeCtx();
    vm.runInContext('addTodayVisit()', ctx);
    vm.runInContext('addTodayVisit()', ctx);
    expect(ctx.state.modalVisits.length).toBe(1);
    const today = new Date().toISOString().slice(0, 10);
    expect(ctx.state.modalVisits[0].date).toBe(today);
  });
});

describeDom('_refreshGoogleChromeVisibility (regression)', () => {
  function makeCtx({ provider, placesEnabled }) {
    const dom = new JSDOM(`<!DOCTYPE html><html><body>
      <button id="loc-google-sync-btn" style="display:none;"></button>
      <button id="bulk-google-sync-btn" style="display:none;"></button>
      <label id="import-sync-label" style="display:none;"></label>
    </body></html>`);
    const ctx = vm.createContext({
      document: dom.window.document,
      console, Promise,
      getSearchProvider: () => provider,
      checkPlacesEnabled: async () => placesEnabled,
    });
    // shouldUseGoogle reads both — extract it too.
    const code = [
      extractAsyncFunction('shouldUseGoogle'),
      extractAsyncFunction('_refreshGoogleChromeVisibility'),
    ].join('\n');
    vm.runInContext(code, ctx);
    return { ctx, dom };
  }

  test('provider=google + placesEnabled → all three Google controls visible', async () => {
    const { ctx, dom } = makeCtx({ provider: 'google', placesEnabled: true });
    await vm.runInContext('_refreshGoogleChromeVisibility()', ctx);
    expect(dom.window.document.getElementById('loc-google-sync-btn').style.display).toBe('');
    expect(dom.window.document.getElementById('bulk-google-sync-btn').style.display).toBe('');
    expect(dom.window.document.getElementById('import-sync-label').style.display).toBe('flex');
  });

  test('provider=photon → all three Google controls hidden (even if key configured)', async () => {
    const { ctx, dom } = makeCtx({ provider: 'photon', placesEnabled: true });
    await vm.runInContext('_refreshGoogleChromeVisibility()', ctx);
    expect(dom.window.document.getElementById('loc-google-sync-btn').style.display).toBe('none');
    expect(dom.window.document.getElementById('bulk-google-sync-btn').style.display).toBe('none');
    expect(dom.window.document.getElementById('import-sync-label').style.display).toBe('none');
  });

  test('provider=nominatim → all three Google controls hidden', async () => {
    const { ctx, dom } = makeCtx({ provider: 'nominatim', placesEnabled: true });
    await vm.runInContext('_refreshGoogleChromeVisibility()', ctx);
    expect(dom.window.document.getElementById('loc-google-sync-btn').style.display).toBe('none');
    expect(dom.window.document.getElementById('bulk-google-sync-btn').style.display).toBe('none');
    expect(dom.window.document.getElementById('import-sync-label').style.display).toBe('none');
  });

  test('provider=google but no Places key → all three Google controls hidden', async () => {
    const { ctx, dom } = makeCtx({ provider: 'google', placesEnabled: false });
    await vm.runInContext('_refreshGoogleChromeVisibility()', ctx);
    expect(dom.window.document.getElementById('loc-google-sync-btn').style.display).toBe('none');
    expect(dom.window.document.getElementById('bulk-google-sync-btn').style.display).toBe('none');
    expect(dom.window.document.getElementById('import-sync-label').style.display).toBe('none');
  });
});

describe('Static markup (regression)', () => {
  test('bulk toolbar Google sync button is gated (id + initial display:none)', () => {
    expect(indexHtml).toMatch(/id="bulk-google-sync-btn"[\s\S]{0,300}display:none/);
  });

  test('edit-modal Google sync button visibility now reads shouldUseGoogle()', () => {
    // The "openEditModal" path should be gated by the provider-aware helper,
    // not the API-key-only checkPlacesEnabled.
    expect(indexHtml).toMatch(/loc-google-sync-btn[\s\S]{0,200}shouldUseGoogle\(\)/);
  });

  test('import-view Google sync label visibility now reads shouldUseGoogle()', () => {
    expect(indexHtml).toMatch(/shouldUseGoogle\(\)[\s\S]{0,300}import-sync-label/);
  });

  test('Timeline import button is present in Import view + wires the existing JSON path', () => {
    expect(indexHtml).toMatch(/data-click="openFileDialog"[\s\S]{0,100}data-target="timeline-json-input"/);
    expect(indexHtml).toMatch(/id="timeline-json-input"[\s\S]{0,200}data-change="onTimelineImport"/);
    expect(indexHtml).toMatch(/function onTimelineImport\(el\)[\s\S]{0,300}handleFiles\(files\)/);
  });

  test('_refreshGoogleChromeVisibility hooked into onSearchProviderChange + startApp', () => {
    expect(indexHtml).toMatch(/function onSearchProviderChange\(\)[\s\S]{0,600}_refreshGoogleChromeVisibility\(\)/);
    expect(indexHtml).toMatch(/initImport\(\)[\s\S]{0,400}_refreshGoogleChromeVisibility\(\)/);
  });
});
