// Regression coverage for the inline-onclick → dispatcher migration.
// Three split-onclick leftovers leaked into prod after the c9f7ec9 CSP refactor:
//   1. "+ New Trip" button: data-arg0=").then(()=>{populateTripSelector();}"
//      → promptNewTrip got a garbage string arg + the dropdown stayed stale
//      after creating a trip (the .then() composition was lost).
//   2. Collection-view card: data-arg0="'map-view');setTimeout(()=>openEditModal('<id>')"
//      → switchView received a bogus viewId; auto-open of the edit modal was lost.
//   3. Attach-transits picker checkbox: data-arg1="this.checked" literal
//      → toggleAttachSelect's "on" param was always the truthy string
//      "this.checked", so unchecking never removed from selection.
//
// Each lock-in: (a) the broken attribute is gone, (b) the new call shape is
// present, (c) the receiver does what the original .then()/setTimeout() did.

const path = require('path');
const fs = require('fs');
const indexHtml = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');

describe('Dispatcher arg-string leftovers (regression for c9f7ec9 CSP migration)', () => {
  test('+ New Trip button has no stray .then() string in data-arg0', () => {
    expect(indexHtml).not.toMatch(/data-arg0="\)\.then/);
    // Sanity: the button is still there, just with no positional args.
    expect(indexHtml).toMatch(/data-click="promptNewTrip"[^>]*>\+ New Trip</);
  });

  test('promptNewTrip refreshes the trip-selector dropdown after success', () => {
    // The original onclick chained .then(populateTripSelector). Now the call
    // lives at the tail of the try block so it runs on success only.
    expect(indexHtml).toMatch(/async function promptNewTrip\(\)[\s\S]{0,800}populateTripSelector\(\);[\s\S]{0,80}\} catch/);
  });

  test('Collection-view card: no inline setTimeout()/openEditModal() baked into data-arg0', () => {
    expect(indexHtml).not.toMatch(/data-arg0="'map-view'\);setTimeout/);
    expect(indexHtml).toMatch(/data-click="switchToMapAndEdit"/);
  });

  test('switchToMapAndEdit composes switchView + openEditModal (replaces the lost setTimeout)', () => {
    expect(indexHtml).toMatch(/function switchToMapAndEdit\(locId\)[\s\S]{0,200}switchView\('map-view'\)[\s\S]{0,120}setTimeout\(\(\) => openEditModal\(locId\), 300\)/);
  });

  test('Attach-transits checkbox no longer passes the literal string "this.checked"', () => {
    expect(indexHtml).not.toMatch(/data-arg1="this\.checked"/);
    // Uses the canonical "this" sentinel → dispatcher remaps to the element ref.
    expect(indexHtml).toMatch(/data-click="toggleAttachSelect"[^>]*data-arg1="this"/);
  });

  test('toggleAttachSelect reads el.checked from the sentinel-mapped element', () => {
    expect(indexHtml).toMatch(/function toggleAttachSelect\(id, el\)[\s\S]{0,300}el\.checked[\s\S]{0,200}_attachSelected/);
  });
});
