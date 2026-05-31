// Regression coverage for the Trips-view empty-state CTA.
//
// Two empty states share the trip-detail panel:
//   - state.trips.length === 0 → "No Trips Yet" + 3 CTAs (create / Timeline / Narrate)
//   - state.trips.length > 0, no selection → "Select a Trip" (prior copy)
//
// _renderTripDetailEmpty picks between them; it's called by selectTrip(null),
// by the delete-trip flow (when the deleted trip was the one being viewed),
// and on view-switch to trips-view (so users with zero trips don't see the
// misleading "Choose a trip from the dropdown" when the dropdown is empty).

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

let JSDOM;
try { JSDOM = require('jsdom').JSDOM; } catch { JSDOM = null; }
const describeDom = JSDOM ? describe : describe.skip;

describeDom('_renderTripDetailEmpty', () => {
  function makeCtx(trips) {
    const dom = new JSDOM('<!DOCTYPE html><html><body><div id="trip-detail"></div></body></html>');
    const ctx = vm.createContext({
      document: dom.window.document,
      state: { trips },
    });
    vm.runInContext(extractFunction('_renderTripDetailEmpty'), ctx);
    return { ctx, dom };
  }

  test('zero trips → "No Trips Yet" + 3 CTAs (manual / Timeline / Narrate)', () => {
    const { ctx, dom } = makeCtx([]);
    vm.runInContext('_renderTripDetailEmpty()', ctx);
    const html = dom.window.document.getElementById('trip-detail').innerHTML;
    expect(html).toMatch(/No Trips Yet/);
    expect(html).toMatch(/data-click="promptNewTrip"/);
    expect(html).toMatch(/data-click="importTripFromTimeline"/);
    expect(html).toMatch(/data-click="openNarrateModal"/);
    // Three CTAs present.
    const ctas = dom.window.document.querySelectorAll('[data-click]');
    expect(ctas.length).toBe(3);
  });

  test('trips exist but none selected → "Select a Trip" copy (no CTAs)', () => {
    const { ctx, dom } = makeCtx([{ id: 't1', name: 'Trip 1' }]);
    vm.runInContext('_renderTripDetailEmpty()', ctx);
    const html = dom.window.document.getElementById('trip-detail').innerHTML;
    expect(html).toMatch(/Select a Trip/);
    expect(html).toMatch(/Choose a trip from the dropdown/);
    // No CTAs in this state — the dropdown above is the affordance.
    const ctas = dom.window.document.querySelectorAll('[data-click]');
    expect(ctas.length).toBe(0);
  });

  test('graceful no-op when #trip-detail is absent (off-view)', () => {
    const dom = new JSDOM('<!DOCTYPE html><html><body></body></html>');
    const ctx = vm.createContext({
      document: dom.window.document,
      state: { trips: [] },
    });
    vm.runInContext(extractFunction('_renderTripDetailEmpty'), ctx);
    expect(() => vm.runInContext('_renderTripDetailEmpty()', ctx)).not.toThrow();
  });
});

describe('Static markup (regression)', () => {
  test('selectTrip(null) delegates to _renderTripDetailEmpty (no inline HTML duplicate)', () => {
    const fn = extractFunction('selectTrip');
    expect(fn).toMatch(/if \(!tripId\)\s*\{[\s\S]{0,100}_renderTripDetailEmpty\(\);/);
    // Old inline "Select a Trip" markup at this site is gone (the empty-state
    // helper carries the copy now).
    expect(fn).not.toMatch(/Choose a trip from the dropdown/);
  });

  test('switchView hook refreshes the empty panel for trips-view (so zero-trip users see CTAs)', () => {
    // The view-switch path now calls _renderTripDetailEmpty when no trip is
    // selected, so the static fallback copy doesn't strand users with zero trips.
    expect(indexHtml).toMatch(/viewId === 'trips-view'[\s\S]{0,300}_renderTripDetailEmpty\(\)/);
  });
});
