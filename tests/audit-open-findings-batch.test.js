// Regression tests for the second batch of fixes from the 2026-06-26 audit's
// "Open findings" register — items that were confirmed but deferred at the
// time because the fix was larger than a one-line bug.
//
// 1. Restore button pointed at the admin-only endpoint for every user.
// 2. Bulk enrich/sync paths mutated category/address in place without
//    bumping stateIndex.generation, leaving Stats/Regions stale.
// 3. Bulk edit/delete/attach/collection ops fanned out unthrottled and could
//    trip the global 200 req/min rate limiter.
// 4. Neighborhood clustering ran an unbounded O(n^2) pass over ALL locations
//    on every zoom event with no memoisation and no viewport bound.
// 5. Session expiry silently reappeared the login screen with no toast.

const fs = require('fs');
const path = require('path');

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

describe('Restore backup points at the user-scoped endpoint', () => {
  test('restoreBackup fetches /api/my-backup, not /api/admin/backups', () => {
    const fn = sliceFunction('restoreBackup');
    expect(fn).toContain('/api/my-backup/');
    expect(fn).not.toContain('/api/admin/backups/');
  });

  test('restoreBackup sends credentials and checks res.ok before parsing JSON', () => {
    const fn = sliceFunction('restoreBackup');
    expect(fn).toContain("credentials: 'same-origin'");
    expect(fn).toMatch(/if\s*\(!res\.ok\)/);
  });
});

describe('Bulk enrich/sync paths bump stateIndex.generation', () => {
  test('bulkEnrichPhoton bumps generation and recomputes _region on address change', () => {
    const fn = sliceFunction('bulkEnrichPhoton');
    expect(fn).toMatch(/_region\s*=\s*\(loc\.address/);
    expect(fn).toContain('stateIndex.generation++');
  });

  test('enrichInBackground bumps generation and recomputes _region', () => {
    // sliceFunction's brace-depth scan gets thrown off by the destructured
    // `{ onProgress } = {}` default param, so use a fixed window instead.
    const start = html.indexOf('async function enrichInBackground(');
    const fn = html.slice(start, start + 2400);
    expect(fn).toMatch(/_region\s*=/);
    expect(fn).toContain('stateIndex.generation++');
  });

  test('syncImportedLocations and bulkGoogleSync bump generation when addresses fill in', () => {
    const fn1 = sliceFunction('syncImportedLocations');
    const fn2 = sliceFunction('bulkGoogleSync');
    for (const fn of [fn1, fn2]) {
      expect(fn).toMatch(/_region\s*=/);
      expect(fn).toContain('stateIndex.generation++');
    }
  });
});

describe('Bulk fan-out is chunked against the rate limiter', () => {
  test('chunkedAllSettled exists, chunks at 50, and is used by every bulk op', () => {
    const fn = sliceFunction('chunkedAllSettled');
    expect(fn).toMatch(/chunkSize\s*=\s*50/);
    expect(fn).toContain('Promise.allSettled');
    const usages = html.match(/chunkedAllSettled\(/g) || [];
    expect(usages.length).toBeGreaterThanOrEqual(6); // 1 def + 5 call sites
  });

  test('api() surfaces a clear message on 429 instead of a generic API error', () => {
    const fn = sliceFunction('api');
    expect(fn).toMatch(/res\.status === 429/);
    expect(fn).toMatch(/Rate limited/i);
  });

  test('selectAllBulk warns when a very large selection is made', () => {
    const fn = sliceFunction('selectAllBulk');
    expect(fn).toMatch(/bulkSelected\.size > 200/);
  });
});

describe('Neighborhood clustering is bounded and memoised', () => {
  test('_updateNeighborhoodLayer bounds input to the viewport via getBounds/contains', () => {
    const fn = sliceFunction('_updateNeighborhoodLayer');
    expect(fn).toContain('map.getBounds()');
    expect(fn).toContain('.contains(');
  });

  test('_updateNeighborhoodLayer memoises on generation + zoom + bounds', () => {
    const fn = sliceFunction('_updateNeighborhoodLayer');
    expect(fn).toContain('stateIndex.generation');
    expect(fn).toMatch(/_nhCacheKey/);
  });

  test('_updateNeighborhoodLayer respects active filters via getFilteredLocations', () => {
    const fn = sliceFunction('_updateNeighborhoodLayer');
    expect(fn).toContain('getFilteredLocations()');
  });
});

describe('Session expiry is no longer silent', () => {
  test('api() shows a toast before logging out on an expired session', () => {
    const fn = sliceFunction('api');
    const logoutIdx = fn.indexOf('logout();');
    expect(logoutIdx).toBeGreaterThan(0);
    const before = fn.slice(0, logoutIdx);
    expect(before).toMatch(/showToast\([^)]*[Ss]ession expired/);
  });
});
