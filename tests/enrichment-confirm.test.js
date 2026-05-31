// Regression for the user-facing enrichment confirmation flow.
//
// Background: the prior modal-sync functions silently fill-only'd missing
// fields. User feedback: Photon "doesn't work" (because it skipped any field
// that already had a value, even a low-quality one) AND any provider may
// overwrite manually-curated data without warning. The new flow:
//   1. Fetch ALL fields from the provider (no current-value filter).
//   2. buildEnrichmentDiffs compares each proposed field to loc[field].
//   3. showEnrichmentConfirm renders a per-field checkbox modal:
//      - "fill" (current empty) → default CHECKED
//      - "overwrite" (current has value, different proposed) → default UNCHECKED
//   4. applyEnrichmentUpdates PUTs only the user-approved subset and stamps
//      the source-specific syncedAt.

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

describe('buildEnrichmentDiffs (pure)', () => {
  function makeCtx() {
    const ctx = vm.createContext({
      ENRICH_FIELD_LABELS: {
        address: 'Address', lat: 'Latitude', lng: 'Longitude',
        category: 'Category', googleRating: 'Google rating',
      },
    });
    vm.runInContext(extractFunction('buildEnrichmentDiffs'), ctx);
    return ctx;
  }

  test('returns empty when proposed is empty', () => {
    const ctx = makeCtx();
    const diffs = vm.runInContext('buildEnrichmentDiffs({}, {})', ctx);
    expect(diffs).toEqual([]);
  });

  test('skips fields where proposed value is null or empty string', () => {
    const ctx = makeCtx();
    const diffs = vm.runInContext(
      'buildEnrichmentDiffs({}, { address: "", lat: null, category: "restaurant" })',
      ctx,
    );
    expect(diffs.map(d => d.field)).toEqual(['category']);
  });

  test('skips fields whose proposed value matches the current (stringwise)', () => {
    const ctx = makeCtx();
    const diffs = vm.runInContext(
      'buildEnrichmentDiffs({ address: "Rua A", lat: 38.7 }, { address: "Rua A", lat: 38.7, category: "bar" })',
      ctx,
    );
    expect(diffs.map(d => d.field)).toEqual(['category']);
  });

  test('surfaces fills (empty current) AND overwrites (different current)', () => {
    const ctx = makeCtx();
    const diffs = vm.runInContext(
      'buildEnrichmentDiffs({ address: "", category: "restaurant" }, { address: "Rua A", category: "bar" })',
      ctx,
    );
    expect(diffs).toHaveLength(2);
    expect(diffs.find(d => d.field === 'address')).toMatchObject({ current: '', proposed: 'Rua A', label: 'Address' });
    expect(diffs.find(d => d.field === 'category')).toMatchObject({ current: 'restaurant', proposed: 'bar', label: 'Category' });
  });

  test('falls back to raw field name when no label map entry exists', () => {
    const ctx = makeCtx();
    const diffs = vm.runInContext(
      'buildEnrichmentDiffs({}, { _googleUrl: "https://maps.google.com/..." })',
      ctx,
    );
    expect(diffs[0].label).toBe('_googleUrl');
  });
});

describeDom('showEnrichmentConfirm (interactive)', () => {
  function makeCtx() {
    const dom = new JSDOM('<!DOCTYPE html><html><body></body></html>');
    const ctx = vm.createContext({
      document: dom.window.document,
      Promise, console, parseInt, String,
      esc: (s) => String(s).replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c])),
    });
    vm.runInContext(extractFunction('showEnrichmentConfirm'), ctx);
    return { ctx, dom };
  }

  test('returns empty appliedUpdates immediately when diffs is empty', async () => {
    const { ctx } = makeCtx();
    const result = await vm.runInContext('showEnrichmentConfirm("Photon", [])', ctx);
    expect(result).toEqual({ appliedUpdates: {} });
  });

  test('renders a checkbox per diff and tags fill vs overwrite', () => {
    const { ctx, dom } = makeCtx();
    vm.runInContext(`
      showEnrichmentConfirm("Photon", [
        { field: "address", label: "Address", current: "", proposed: "Rua A" },
        { field: "category", label: "Category", current: "restaurant", proposed: "bar" }
      ]);
    `, ctx);
    const overlay = dom.window.document.querySelector('.confirm-overlay');
    expect(overlay).not.toBeNull();
    const cbs = overlay.querySelectorAll('.enrich-field');
    expect(cbs.length).toBe(2);
    // Fill (empty current) → default checked.
    expect(cbs[0].checked).toBe(true);
    // Overwrite (current has value) → default unchecked.
    expect(cbs[1].checked).toBe(false);
    // Visual tags present.
    expect(overlay.innerHTML).toMatch(/fill/i);
    expect(overlay.innerHTML).toMatch(/overwrite/i);
  });

  test('Apply button resolves with only the checked subset', async () => {
    const { ctx, dom } = makeCtx();
    const p = vm.runInContext(`
      showEnrichmentConfirm("Photon", [
        { field: "address", label: "Address", current: "", proposed: "Rua A" },
        { field: "category", label: "Category", current: "restaurant", proposed: "bar" }
      ]);
    `, ctx);
    const overlay = dom.window.document.querySelector('.confirm-overlay');
    // User checks the overwrite as well.
    overlay.querySelectorAll('.enrich-field')[1].checked = true;
    overlay.querySelector('.btn-primary').click();
    const result = await p;
    expect(result).toEqual({ appliedUpdates: { address: 'Rua A', category: 'bar' } });
  });

  test('Cancel button resolves null', async () => {
    const { ctx, dom } = makeCtx();
    const p = vm.runInContext(`
      showEnrichmentConfirm("Photon", [
        { field: "address", label: "Address", current: "", proposed: "Rua A" }
      ]);
    `, ctx);
    dom.window.document.querySelector('.confirm-cancel').click();
    const result = await p;
    expect(result).toBeNull();
  });

  test('XSS: proposed values are escaped in the diff explainer (no script execution)', () => {
    const { ctx, dom } = makeCtx();
    vm.runInContext(`
      showEnrichmentConfirm("Photon", [
        { field: "address", label: "Address", current: "", proposed: "<img src=x onerror=window.X=1>" }
      ]);
    `, ctx);
    const overlay = dom.window.document.querySelector('.confirm-overlay');
    expect(overlay.innerHTML).toContain('&lt;img');
    expect(overlay.innerHTML).not.toContain('<img src=x');
    // Sanity: no DOM <img> got constructed from the user-controlled string.
    expect(overlay.querySelectorAll('img').length).toBe(0);
  });
});

describe('Static markup (regression)', () => {
  test('Edit modal has top-of-modal "Enrich data" section with three provider buttons', () => {
    expect(indexHtml).toMatch(/Enrich data[\s\S]{0,800}id="loc-photon-sync-btn"[\s\S]{0,500}id="loc-nominatim-sync-btn"[\s\S]{0,500}id="loc-google-sync-btn"/);
  });

  test('Old enrichment-button row under "Google Maps Rating" is gone (no duplicates)', () => {
    const photonMatches = indexHtml.match(/id="loc-photon-sync-btn"/g) || [];
    const nominatimMatches = indexHtml.match(/id="loc-nominatim-sync-btn"/g) || [];
    const googleMatches = indexHtml.match(/id="loc-google-sync-btn"/g) || [];
    expect(photonMatches.length).toBe(1);
    expect(nominatimMatches.length).toBe(1);
    expect(googleMatches.length).toBe(1);
  });

  test('Google Maps link is now labeled "🗺️ View on Maps" (not a bare icon)', () => {
    expect(indexHtml).toMatch(/id="loc-google-maps-link"[\s\S]{0,300}🗺️ View on Maps/);
    // And lives next to the Name label, not in the enrichment row.
    expect(indexHtml).toMatch(/<label>Name <a id="loc-google-maps-link"/);
  });

  test('Popup action row drops the redundant status-toggle (consolidated into ✅ Been)', () => {
    expect(indexHtml).not.toMatch(/data-click="toggleStatusFromPopup"/);
    expect(indexHtml).not.toMatch(/async function toggleStatusFromPopup/);
  });
});
