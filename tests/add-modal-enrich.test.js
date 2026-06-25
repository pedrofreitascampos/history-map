// Regression tests for add-modal enrich buttons + save-with-missing-coords fixes.
//
// Bug 1: fill-in buttons (🌍 Fast / 🗺️ Detailed) silently returned when
//   state.editingId was null, AND the enrich section was hidden in add mode.
//
// Bug 2: "add places never works first time" — user saves before the async
//   blur-triggered _autoGeocodeAddModalIfNeeded fetch completes → coords are
//   still NaN → save fails. Fix: saveLocation retries the geocode before giving
//   up when coords are missing in add mode.

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');

function sliceFunction(name) {
  const tag = `function ${name}(`;
  const start = html.indexOf(tag);
  if (start === -1) throw new Error(`${name} not found`);
  let depth = 0, i = start, found = false;
  for (; i < html.length; i++) {
    if (html[i] === '{') { depth++; found = true; }
    if (html[i] === '}') depth--;
    if (found && depth === 0) break;
  }
  return html.substring(start, i + 1);
}

// ── Static pins ──────────────────────────────────────────────────────────────

describe('Enrich section visibility in add mode', () => {
  test('openAddModal shows loc-enrich-section (not display:none)', () => {
    const fnStart = html.indexOf('function openAddModal(');
    const slice = html.slice(fnStart, fnStart + 1600);
    // Section must NOT be hidden in add mode — was the root cause of Bug 1
    expect(slice).not.toMatch(/loc-enrich-section[\s\S]{0,50}display\s*[=:]\s*['"]none['"]/);
  });
});

describe('syncPhotonFromEditModal — add-mode path', () => {
  test('has !locId early path that uses /api/geocode proxy', () => {
    const fn = sliceFunction('syncPhotonFromEditModal');
    expect(fn).toContain('!locId');
    expect(fn).toContain('/api/geocode');
    expect(fn).toContain('_unhideLocCoordsRow');
  });

  test('edit-mode path still uses photon.komoot.io (existing tests guard)', () => {
    const fn = sliceFunction('syncPhotonFromEditModal');
    expect(fn).toContain('photon.komoot.io');
    expect(fn).toContain('_photonSyncedAt');
    expect(fn).toContain('applyEnrichmentUpdates(');
  });

  test('button is re-enabled in finally even in add mode', () => {
    // btn.disabled + btn.textContent must be inside finally, not inside !locId guard
    const fn = sliceFunction('syncPhotonFromEditModal');
    const finallyIdx = fn.indexOf('finally');
    const btnIdx = fn.indexOf('loc-photon-sync-btn');
    // btn variable obtained before the !locId guard (so finally can reference it)
    expect(btnIdx).toBeGreaterThan(0);
    expect(finallyIdx).toBeGreaterThan(0);
    // btn.disabled = false inside finally
    const finallySlice = fn.slice(finallyIdx, finallyIdx + 100);
    expect(finallySlice).toContain('btn.disabled = false');
  });
});

describe('syncNominatimFromEditModal — add-mode path', () => {
  test('has !locId early path that fills form fields', () => {
    const fn = sliceFunction('syncNominatimFromEditModal');
    expect(fn).toContain('!locId');
    expect(fn).toContain('_unhideLocCoordsRow');
  });

  test('add-mode path uses /api/geocode/reverse when coords present', () => {
    const fn = sliceFunction('syncNominatimFromEditModal');
    // Both add-mode and edit-mode have reverse geocode branch
    const firstReverseIdx = fn.indexOf('/api/geocode/reverse');
    const secondReverseIdx = fn.indexOf('/api/geocode/reverse', firstReverseIdx + 1);
    // At least one occurrence before !locId add-mode branch AND one after for edit mode
    expect(firstReverseIdx).toBeGreaterThan(0);
    expect(secondReverseIdx).toBeGreaterThan(firstReverseIdx);
  });

  test('edit-mode path unchanged (nominatimSyncedAt + showEnrichmentConfirm)', () => {
    const fn = sliceFunction('syncNominatimFromEditModal');
    expect(fn).toContain('_nominatimSyncedAt');
    expect(fn).toContain("showEnrichmentConfirm('OpenStreetMap (Detailed)'");
  });
});

describe('saveLocation — auto-geocode fallback on missing coords (Bug 2)', () => {
  test('saveLocation calls _autoGeocodeAddModalIfNeeded before giving up on missing coords', () => {
    // Key fix: saves with name but no coords now trigger geocode before showing the
    // warning. Handles the race where the user clicks Save before blur-geocode completes.
    expect(html).toMatch(/async function saveLocation[\s\S]{0,600}_autoGeocodeAddModalIfNeeded\(\)/);
  });

  test('saveLocation still unhides coords row if geocode also fails', () => {
    // Belt-and-suspenders: if auto-geocode finds nothing, user still sees the row
    expect(html).toMatch(/async function saveLocation[\s\S]{0,700}_unhideLocCoordsRow\(\)/);
  });

  test('saveLocation re-reads lat/lng after geocode attempt', () => {
    const fnStart = html.indexOf('async function saveLocation(');
    const slice = html.slice(fnStart, fnStart + 900);
    // lat and lng must be re-read after _autoGeocodeAddModalIfNeeded
    const geocodeIdx = slice.indexOf('_autoGeocodeAddModalIfNeeded');
    const reLat = slice.indexOf("getElementById('loc-lat')", geocodeIdx);
    const reLng = slice.indexOf("getElementById('loc-lng')", geocodeIdx);
    expect(geocodeIdx).toBeGreaterThan(0);
    expect(reLat).toBeGreaterThan(geocodeIdx);
    expect(reLng).toBeGreaterThan(geocodeIdx);
  });

  test('lat and lng declared as let (not const) to allow reassignment after geocode', () => {
    const fnStart = html.indexOf('async function saveLocation(');
    const slice = html.slice(fnStart, fnStart + 300);
    expect(slice).toMatch(/let lat\s*=/);
    expect(slice).toMatch(/let lng\s*=/);
  });
});
