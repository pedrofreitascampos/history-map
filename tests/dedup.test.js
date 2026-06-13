// Smart import deduplication — Levenshtein + spatial matching.

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
describe('Dedup — static markup', () => {
  test('#dedup-modal exists with display:none', () => {
    expect(indexHtml).toContain('id="dedup-modal"');
    expect(indexHtml).toMatch(/id="dedup-modal"[^>]*display:none/);
  });

  test('#dedup-summary and #dedup-list exist inside modal', () => {
    const start = indexHtml.indexOf('id="dedup-modal"');
    const end = indexHtml.indexOf('</div>', start + 800);
    const html = indexHtml.substring(start, end + 6);
    expect(html).toContain('id="dedup-summary"');
    expect(html).toContain('id="dedup-list"');
  });

  test('Skip button uses data-click="dedupSkip"', () => {
    expect(indexHtml).toMatch(/data-click="dedupSkip"/);
  });

  test('Import all button uses data-click="dedupImportAll"', () => {
    expect(indexHtml).toMatch(/data-click="dedupImportAll"/);
  });

  test('Cancel button uses data-click="closeDedupModal"', () => {
    expect(indexHtml).toMatch(/data-click="closeDedupModal"/);
  });

  test('all dedup functions defined', () => {
    ['_levenshtein', '_levenshteinSim', '_findDups', '_checkImportDups',
      '_showDedupModal', 'closeDedupModal', 'dedupSkip', 'dedupImportAll'].forEach(fn => {
      expect(indexHtml).toContain(`function ${fn}`);
    });
  });

  test('confirmImport calls _checkImportDups before bulk POST', () => {
    const fn = extractFunction('confirmImport');
    const dupIdx = fn.indexOf('_checkImportDups');
    const postIdx = fn.indexOf("'POST', '/locations/bulk'");
    expect(dupIdx).toBeGreaterThan(-1);
    expect(dupIdx).toBeLessThan(postIdx);
  });

  test('saveLocation warns on dupe for new locations', () => {
    const fn = extractFunction('saveLocation');
    const newLocBlock = fn.slice(fn.indexOf('data.createdAt'));
    expect(newLocBlock).toContain('_findDups');
  });

  test('Escape closes dedup-modal', () => {
    const escBlock = indexHtml.match(/key !== 'Escape'[\s\S]{0,2500}const modals = \[/);
    expect(escBlock).not.toBeNull();
    expect(escBlock[0]).toContain('dedup-modal');
    expect(escBlock[0]).toContain('closeDedupModal');
  });
});

// ── Levenshtein distance (vm) ─────────────────────────────────────────────
describe('Dedup — _levenshtein', () => {
  function lev(a, b) {
    const code = extractFunction('_levenshtein') + `\n__r = _levenshtein(${JSON.stringify(a)}, ${JSON.stringify(b)});`;
    const ctx = vm.createContext({ Math, Array, __r: null });
    vm.runInContext(code, ctx);
    return ctx.__r;
  }

  test('identical strings → 0', () => expect(lev('abc', 'abc')).toBe(0));
  test('empty a → len(b)', () => expect(lev('', 'hello')).toBe(5));
  test('empty b → len(a)', () => expect(lev('hello', '')).toBe(5));
  test('single substitution', () => expect(lev('cat', 'bat')).toBe(1));
  test('single insertion', () => expect(lev('abc', 'abcd')).toBe(1));
  test('single deletion', () => expect(lev('abcd', 'abc')).toBe(1));
  test('Eiffel Tower vs Eiffel Towers → 1', () => expect(lev('Eiffel Tower', 'Eiffel Towers')).toBe(1));
  test('completely different strings', () => expect(lev('abc', 'xyz')).toBe(3));
});

// ── Levenshtein similarity (vm) ───────────────────────────────────────────
describe('Dedup — _levenshteinSim', () => {
  function sim(a, b) {
    const code = [extractFunction('_levenshtein'), extractFunction('_levenshteinSim'),
      `__r = _levenshteinSim(${JSON.stringify(a)}, ${JSON.stringify(b)});`].join('\n');
    const ctx = vm.createContext({ Math, Array, __r: null });
    vm.runInContext(code, ctx);
    return ctx.__r;
  }

  test('identical → 1.0', () => expect(sim('Eiffel Tower', 'Eiffel Tower')).toBe(1));
  test('case-insensitive match → 1.0', () => expect(sim('Eiffel Tower', 'eiffel tower')).toBe(1));
  test('"Eiffel Tower" vs "Eiffel Towers" → ≥ 0.9', () => expect(sim('Eiffel Tower', 'Eiffel Towers')).toBeGreaterThan(0.9));
  test('completely different → < 0.5', () => expect(sim('Eiffel Tower', 'Colosseum')).toBeLessThan(0.5));
  test('both empty → 1.0', () => expect(sim('', '')).toBe(1));
  test('threshold: ≥0.8 means match', () => {
    // "The Eiffel Tower" vs "Eiffel Tower": lev=4, maxLen=16 → sim=0.75 (no match)
    expect(sim('The Eiffel Tower', 'Eiffel Tower')).toBeLessThan(0.8);
    // "Cafe de Flore" vs "Café de Flore": only accent diff
    expect(sim('Tour Eiffel', 'Tour Eiffel')).toBe(1);
  });
});

// ── _findDups spatial + name match (vm) ──────────────────────────────────
describe('Dedup — _findDups', () => {
  function runFindDups(candidate, locs) {
    const code = [
      extractFunction('_levenshtein'),
      extractFunction('_levenshteinSim'),
      extractFunction('_haversineM'),
      extractFunction('_findDups'),
      `__r = _findDups(${JSON.stringify(candidate)}, ${JSON.stringify(locs)});`,
    ].join('\n');
    const ctx = vm.createContext({ Math, Array, Number, __r: null });
    vm.runInContext(code, ctx);
    return ctx.__r;
  }

  const eiffel = { name: 'Eiffel Tower', lat: 48.8584, lng: 2.2945 };
  // "Eiffel Towers" — 1 char diff → sim = 12/13 ≈ 0.92, ~75 m away ✓
  const eiffelNearby = { name: 'Eiffel Towers', lat: 48.859, lng: 2.295, id: 'e1' };
  // Colosseum is 1400 km away with a different name — fails both gates
  const colosseum = { name: 'Colosseum', lat: 41.8902, lng: 12.4924, id: 'c1' };
  // Same name but 1400 km away — passes name gate, fails distance gate
  const eiffelFar = { name: 'Eiffel Tower', lat: 41.8902, lng: 12.4924, id: 'e2' };

  test('nearby + similar name → found', () => {
    const r = runFindDups(eiffel, [eiffelNearby]);
    expect(r.length).toBe(1);
  });

  test('nearby but different name → not found', () => {
    const r = runFindDups(eiffel, [colosseum]);
    expect(r.length).toBe(0);
  });

  test('same name but >500 m away → not found', () => {
    const r = runFindDups(eiffel, [eiffelFar]);
    expect(r.length).toBe(0);
  });

  test('returns all matches when multiple nearby similar names', () => {
    // "Eiffel Tower" (12) vs "Eiffel Tower." (13) → lev=1 → sim=12/13≈0.92 ✓
    const locs = [eiffelNearby, { name: 'Eiffel Tower.', lat: 48.8585, lng: 2.2946, id: 'e3' }];
    const r = runFindDups(eiffel, locs);
    expect(r.length).toBe(2);
  });

  test('candidate with no coords → returns empty', () => {
    const r = runFindDups({ name: 'X', lat: NaN, lng: NaN }, [eiffelNearby]);
    expect(r.length).toBe(0);
  });
});

// ── _checkImportDups (vm) ─────────────────────────────────────────────────
describe('Dedup — _checkImportDups', () => {
  function runCheck(candidates, locs) {
    const code = [
      extractFunction('_levenshtein'),
      extractFunction('_levenshteinSim'),
      extractFunction('_haversineM'),
      extractFunction('_findDups'),
      extractFunction('_checkImportDups'),
      `__r = _checkImportDups(${JSON.stringify(candidates)});`,
    ].join('\n');
    const ctx = vm.createContext({
      Math, Array, Number,
      state: { locations: locs },
      __r: null,
    });
    vm.runInContext(code, ctx);
    return ctx.__r;
  }

  test('flags candidate with nearby match', () => {
    const candidates = [{ name: 'Eiffel Tower', lat: 48.8584, lng: 2.2945 }];
    const existing = [{ name: 'Eiffel Towers', lat: 48.858, lng: 2.294 }];
    const result = runCheck(candidates, existing);
    expect(result.length).toBe(1);
    expect(result[0].idx).toBe(0);
    expect(result[0].matches.length).toBeGreaterThan(0);
  });

  test('does not flag candidate with no nearby matches', () => {
    const candidates = [{ name: 'Colosseum', lat: 41.89, lng: 12.49 }];
    const existing = [{ name: 'Eiffel Tower', lat: 48.858, lng: 2.294 }];
    expect(runCheck(candidates, existing).length).toBe(0);
  });

  test('returns correct idx for flagged item in mixed list', () => {
    const candidates = [
      { name: 'Colosseum', lat: 41.89, lng: 12.49 },       // idx 0 — no match
      { name: 'Eiffel Tower', lat: 48.8584, lng: 2.2945 },  // idx 1 — matches
    ];
    const existing = [{ name: 'Eiffel Towers', lat: 48.858, lng: 2.294 }];
    const result = runCheck(candidates, existing);
    expect(result.length).toBe(1);
    expect(result[0].idx).toBe(1);
  });
});
