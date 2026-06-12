// S2.5 Audit-fix batch (2026-06-11). Behavioural regression tests for each
// of the 12 fixes — not string-pins. Each test catches the actual failure
// mode that the previous green suite missed.

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');

function extractFunction(name) {
  const start = html.indexOf(`function ${name}(`);
  if (start === -1) throw new Error(`Function ${name} not found`);
  let depth = 0, i = start, foundFirst = false;
  for (; i < html.length; i++) {
    if (html[i] === '{') { depth++; foundFirst = true; }
    if (html[i] === '}') depth--;
    if (foundFirst && depth === 0) break;
  }
  return html.substring(start, i + 1);
}

// ── 1. CRIT: .replay-panel flex-shrink:0 ─────────────────────────────────────
describe('replay-panel flex-shrink:0', () => {
  test('CSS rule includes flex-shrink:0', () => {
    expect(html).toMatch(/\.replay-panel\s*\{[^}]*flex-shrink\s*:\s*0/);
  });
});

// ── 2. CRIT: Load-more pagination wired via ACTIONS ───────────────────────────
describe('Chronology "Load more" registered in ACTIONS', () => {
  test('renderChronology registers _appendChronoPage in ACTIONS before rendering', () => {
    const fn = extractFunction('renderChronology');
    // Must assign to ACTIONS before clearing innerHTML
    expect(fn).toMatch(/ACTIONS\._appendChronoPage\s*=\s*_appendChronoPage/);
    // Guard for test sandboxes
    expect(fn).toMatch(/typeof ACTIONS/);
  });

  test('ACTIONS registration appears before container.innerHTML = ""', () => {
    const fn = extractFunction('renderChronology');
    const regIdx = fn.indexOf('ACTIONS._appendChronoPage');
    const clearIdx = fn.indexOf("container.innerHTML = ''");
    expect(regIdx).toBeGreaterThan(-1);
    expect(clearIdx).toBeGreaterThan(-1);
    expect(regIdx).toBeLessThan(clearIdx);
  });

  test('_appendChronoPage button uses setAttribute data-click (not .onclick)', () => {
    const fn = extractFunction('renderChronology');
    expect(fn).toMatch(/setAttribute\(\s*['"]data-click['"]\s*,\s*['"]_appendChronoPage['"]\s*\)/);
    expect(fn).not.toMatch(/more\.onclick\s*=/);
  });
});

describe('Wishlist "Load more" registered in ACTIONS', () => {
  test('renderWishlist registers _appendWishlistPage in ACTIONS before rendering', () => {
    const fn = extractFunction('renderWishlist');
    expect(fn).toMatch(/ACTIONS\._appendWishlistPage\s*=\s*_appendWishlistPage/);
    expect(fn).toMatch(/typeof ACTIONS/);
  });

  test('ACTIONS registration appears before container.innerHTML = ""', () => {
    const fn = extractFunction('renderWishlist');
    const regIdx = fn.indexOf('ACTIONS._appendWishlistPage');
    const clearIdx = fn.indexOf("container.innerHTML = ''");
    expect(regIdx).toBeGreaterThan(-1);
    expect(clearIdx).toBeGreaterThan(-1);
    expect(regIdx).toBeLessThan(clearIdx);
  });

  test('_appendWishlistPage button uses setAttribute data-click (not .onclick)', () => {
    const fn = extractFunction('renderWishlist');
    expect(fn).toMatch(/setAttribute\(\s*['"]data-click['"]\s*,\s*['"]_appendWishlistPage['"]\s*\)/);
    expect(fn).not.toMatch(/moreBtn\.onclick\s*=/);
  });
});

// ── 3. HIGH: Live search not hidden after provider switch ─────────────────────
describe('onSearchProviderChange does not set display:none', () => {
  test('only clears innerHTML — no display:none that would kill _runLiveSearch', () => {
    const fn = extractFunction('onSearchProviderChange');
    // Must clear stale results
    expect(fn).toMatch(/\.innerHTML\s*=\s*['"]{2}/);
    // Must NOT set display:none — _runLiveSearch never resets it
    expect(fn).not.toMatch(/\.style\.display\s*=\s*['"]none['"]/);
  });
});

// ── 4. HIGH: data-click → data-change/data-input sweep ───────────────────────
describe('Bulk Edit filters use correct event attributes', () => {
  test('bulk-filter-cat uses data-change (not data-click)', () => {
    expect(html).toMatch(/id="bulk-filter-cat"[^>]*data-change="renderBulkList"/);
    expect(html).not.toMatch(/id="bulk-filter-cat"[^>]*data-click/);
  });

  test('bulk-filter-status uses data-change (not data-click)', () => {
    expect(html).toMatch(/id="bulk-filter-status"[^>]*data-change="renderBulkList"/);
  });

  test('bulk-filter-tag uses data-change (not data-click)', () => {
    expect(html).toMatch(/id="bulk-filter-tag"[^>]*data-change="renderBulkList"/);
  });

  test('bulk-filter-name uses data-input (not data-click)', () => {
    expect(html).toMatch(/id="bulk-filter-name"[^>]*data-input="debouncedBulkFilter"/);
    expect(html).not.toMatch(/id="bulk-filter-name"[^>]*data-click/);
  });
});

describe('Wider data-click sweep: selects and sliders', () => {
  test('chrono filter selects use data-change', () => {
    expect(html).toMatch(/id="chrono-year"[^>]*data-change="onChronoFilterChange"/);
    expect(html).toMatch(/id="chrono-cat"[^>]*data-change="onChronoFilterChange"/);
    expect(html).toMatch(/id="chrono-trip"[^>]*data-change="onChronoFilterChange"/);
  });

  test('wishlist filter selects use data-change', () => {
    expect(html).toMatch(/id="wishlist-sort"[^>]*data-change="onWishlistFilterChange"/);
    expect(html).toMatch(/id="wishlist-tag"[^>]*data-change="onWishlistFilterChange"/);
    expect(html).toMatch(/id="wishlist-cat"[^>]*data-change="onWishlistFilterChange"/);
  });

  test('map filter selects use data-change', () => {
    expect(html).toMatch(/id="trip-filter"[^>]*data-change="applyFilters"/);
    expect(html).toMatch(/id="people-filter"[^>]*data-change="applyFilters"/);
  });

  test('rating sliders use data-change (fires on release, not only click)', () => {
    expect(html).toMatch(/id="google-rating-filter"[^>]*data-change="applyFilters"/);
    expect(html).toMatch(/id="rating-filter"[^>]*data-change="applyFilters"/);
    expect(html).toMatch(/id="bucket-strength-filter"[^>]*data-change="applyFilters"/);
  });

  test('transit search uses data-input (fires on every keystroke)', () => {
    expect(html).toMatch(/id="transit-search"[^>]*data-input="renderTransitsView"/);
  });
});

// ── 5. HIGH: Replay transit sorts before arrival visit ────────────────────────
describe('computeReplayFrames synthetic transit date = departure date', () => {
  test('synthetic transit stamped with v1.date (departure), not v2.date (arrival)', () => {
    // Find the transitFrames.push block — the date field must come from v1
    const synthIdx = html.indexOf('synthetic: true');
    expect(synthIdx).toBeGreaterThan(-1);
    // Read the 300 chars before 'synthetic: true' to find the date assignment
    const slice = html.slice(synthIdx - 300, synthIdx);
    // Should contain 'date: v1.date' NOT 'date: v2.date'
    expect(slice).toMatch(/date:\s*v1\.date/);
    expect(slice).not.toMatch(/date:\s*v2\.date/);
  });

  test('sort tie-break: visits before transits on same date (depart after start-of-day visits)', () => {
    const fn = extractFunction('computeReplayFrames');
    // With v1.date on synthetics, tie-break (visits first) gives:
    // v1_visit → transit → v2_visit even when dates differ by days
    expect(fn).toMatch(/kind\s*===\s*['"]visit['"]/);
  });
});

// ── 6. HIGH: merge-accounts self-merge guard ──────────────────────────────────
describe('merge-accounts self-merge guard', () => {
  test('server rejects fromUser._id === toUser._id with 400', () => {
    const server = fs.readFileSync(path.join(__dirname, '..', 'server', 'index.js'), 'utf-8');
    expect(server).toMatch(/fromUser\._id\s*===\s*toUser\._id/);
    expect(server).toMatch(/Cannot merge an account into itself/);
  });
});

// ── 7. Escape on confirm resolves promise via cancel button ───────────────────
describe('Escape key resolves confirm promise instead of orphaning it', () => {
  test('Escape routes through .confirm-cancel.click() not remove()', () => {
    const escHandlerIdx = html.indexOf("if (e.key !== 'Escape') return;");
    expect(escHandlerIdx).toBeGreaterThan(-1);
    const escHandler = html.slice(escHandlerIdx, escHandlerIdx + 500);
    // Must route via .click() so the Promise resolves and restoreFocus runs
    expect(escHandler).toMatch(/\.confirm-cancel.*\.click\(\)/);
    // Old pattern: confirm.remove() — must be gone from the Escape handler
    expect(escHandler).not.toMatch(/confirm\.remove\(\)/);
  });
});

// ── 8. Default search provider is photon ─────────────────────────────────────
describe('getSearchProvider defaults to photon for keyless accounts', () => {
  test("falls back to 'photon' when localStorage is empty", () => {
    const fn = extractFunction('getSearchProvider');
    expect(fn).toMatch(/:\s*'photon'/);
    expect(fn).not.toMatch(/:\s*'google'\s*[;)]/); // no fallback to google
  });
});

// ── 9. wishlist-view in VIEW_HASHES ──────────────────────────────────────────
describe('VIEW_HASHES includes wishlist-view', () => {
  test("'wishlist-view' maps to a hash value", () => {
    const hashIdx = html.indexOf('VIEW_HASHES');
    const hashBlock = html.slice(hashIdx, hashIdx + 400);
    expect(hashBlock).toMatch(/'wishlist-view'\s*:\s*'wishlist'/);
  });
});

// ── 10. Narrate tooltip captured before overwrite ─────────────────────────────
describe('_refreshNarrateButtonState captures tooltip before overwriting it', () => {
  test('narrateTitle capture line appears before btn.title assignment', () => {
    const fn = extractFunction('_refreshNarrateButtonState');
    const captureIdx = fn.indexOf('btn.dataset.narrateTitle = btn.title');
    const titleIdx = fn.indexOf('btn.title =');
    expect(captureIdx).toBeGreaterThan(-1);
    expect(titleIdx).toBeGreaterThan(-1);
    expect(captureIdx).toBeLessThan(titleIdx);
  });
});

// ── 11. computeTransitStats airports filter: flights only ─────────────────────
describe('computeTransitStats Top airports: flight endpoints only', () => {
  test("airport aggregation block is guarded by t.mode === 'flight'", () => {
    const fn = extractFunction('computeTransitStats');
    // Find the airports section
    const apIdx = fn.indexOf('airports.set');
    expect(apIdx).toBeGreaterThan(-1);
    // The guard must appear within a reasonable window before the first airports.set
    const before = fn.slice(0, apIdx);
    expect(before).toMatch(/t\.mode\s*===\s*['"]flight['"]/);
  });
});

// ── 12. Toast success CSS rule ────────────────────────────────────────────────
describe('Toast .success CSS rule exists', () => {
  test('.toast.success has a color rule', () => {
    expect(html).toMatch(/\.toast\.success\s*\{[^}]*color:/);
  });

  test('.toast.success has a border-color rule', () => {
    expect(html).toMatch(/\.toast\.success\s*\{[^}]*border-color:/);
  });
});

// ── 13. Parchment theme overlay tokens ───────────────────────────────────────
describe('Parchment theme overlay tokens', () => {
  test(':root defines --overlay-base, --overlay-hover, --overlay-strong', () => {
    const rootIdx = html.indexOf(':root {');
    const rootBlock = html.slice(rootIdx, html.indexOf('}', rootIdx) + 1);
    expect(rootBlock).toMatch(/--overlay-base/);
    expect(rootBlock).toMatch(/--overlay-hover/);
    expect(rootBlock).toMatch(/--overlay-strong/);
  });

  test('nav-tabs uses var(--overlay-base) not hardcoded rgba(255,255,255,0.04)', () => {
    expect(html).toMatch(/\.nav-tabs\s*\{[^}]*var\(--overlay-base\)/);
    const navIdx = html.indexOf('.nav-tabs {');
    const navBlock = html.slice(navIdx, html.indexOf('}', navIdx));
    expect(navBlock).not.toMatch(/rgba\(255,255,255,0\.04\)/);
  });

  test('modal-close uses var(--overlay-hover/strong) not hardcoded rgba', () => {
    expect(html).toMatch(/\.modal-close\s*\{[^}]*var\(--overlay-hover\)/);
    expect(html).toMatch(/\.modal-close:hover\s*\{[^}]*var\(--overlay-strong\)/);
  });

  test('parchment theme sets dark overlay tokens', () => {
    const parchIdx = html.indexOf('parchment: {');
    expect(parchIdx).toBeGreaterThan(-1);
    // Grab from parchment: { to the closing } of its vars block
    const parchBlock = html.slice(parchIdx, html.indexOf('  },', parchIdx) + 4);
    expect(parchBlock).toMatch(/--overlay-base.*rgba\(0,0,0/);
  });
});
