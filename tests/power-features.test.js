// Power features regression tests — S4 batch.
// Static markup + vm-sandbox coverage for On This Day, Year in Review, Neighborhoods, Photo Timeline, and future power features.

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

// ──────────────────────────────────────────────────────────────────────────────
// 1. On This Day — static markup
// ──────────────────────────────────────────────────────────────────────────────
describe('On This Day — static markup', () => {
  test('#on-this-day-banner exists with display:none initially', () => {
    expect(indexHtml).toContain('id="on-this-day-banner"');
    expect(indexHtml).toMatch(/id="on-this-day-banner"[\s\S]{0,200}display:none/);
  });

  test('#on-this-day-text span exists inside banner', () => {
    const bannerStart = indexHtml.indexOf('id="on-this-day-banner"');
    const bannerEnd = indexHtml.indexOf('</div>', bannerStart);
    const bannerHtml = indexHtml.substring(bannerStart, bannerEnd + 6);
    expect(bannerHtml).toContain('id="on-this-day-text"');
  });

  test('dismiss button uses data-click dispatcher (no inline handler)', () => {
    expect(indexHtml).toMatch(/id="on-this-day-banner"[\s\S]{0,300}data-click="dismissOnThisDay"/);
    expect(indexHtml).not.toMatch(/id="on-this-day-banner"[\s\S]{0,300}onclick=/);
  });

  test('checkOnThisDay function defined', () => {
    expect(indexHtml).toContain('function checkOnThisDay()');
  });

  test('dismissOnThisDay function defined', () => {
    expect(indexHtml).toContain('function dismissOnThisDay()');
  });

  test('checkOnThisDay called in startApp after loadFromServer', () => {
    const startAppFn = extractFunction('startApp');
    const loadPos = startAppFn.indexOf('loadFromServer');
    const checkPos = startAppFn.indexOf('checkOnThisDay');
    expect(loadPos).toBeGreaterThan(-1);
    expect(checkPos).toBeGreaterThan(loadPos);
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// 2. On This Day — logic (vm sandbox)
// ──────────────────────────────────────────────────────────────────────────────
describe('On This Day — logic', () => {
  function makeCtx({ locations = [], dismissedDate = null, todayOverride = null } = {}) {
    const ls = {};
    if (dismissedDate) ls['hm_otd_dismissed'] = dismissedDate;
    const bannerEl = { style: { display: 'none' }, _text: '' };
    const textEl = { get textContent() { return this._text; }, set textContent(v) { this._text = v; } };
    const docStub = {
      getElementById(id) {
        if (id === 'on-this-day-banner') return bannerEl;
        if (id === 'on-this-day-text') return textEl;
        return null;
      },
    };
    const DateClass = todayOverride
      ? class FakeDate extends Date { constructor(...a) { super(...a.length ? a : [todayOverride]); } }
      : Date;
    const ctx = vm.createContext({
      document: docStub,
      localStorage: { getItem: (k) => ls[k] || null, setItem: (k, v) => { ls[k] = v; } },
      Date: DateClass,
      String, Number, Object, Array, Math, JSON, parseInt, parseFloat,
      state: { locations },
    });
    vm.runInContext(extractFunction('checkOnThisDay'), ctx);
    vm.runInContext(extractFunction('dismissOnThisDay'), ctx);
    return { ctx, bannerEl, textEl, ls };
  }

  test('shows banner when a been location has a prior-year visit matching today MM-DD', () => {
    const today = new Date();
    const mm = String(today.getMonth() + 1).padStart(2, '0');
    const dd = String(today.getDate()).padStart(2, '0');
    const priorYear = today.getFullYear() - 2;
    const matchDate = `${priorYear}-${mm}-${dd}`;
    const locations = [
      { status: 'been', name: 'Kyoto', visits: [{ date: matchDate }] },
    ];
    const { ctx, bannerEl, textEl } = makeCtx({ locations });
    vm.runInContext('checkOnThisDay()', ctx);
    expect(bannerEl.style.display).toBe('flex');
    expect(textEl.textContent).toContain('Kyoto');
    expect(textEl.textContent).toContain('years ago');
  });

  test('does not show banner when dismissed today', () => {
    const today = new Date();
    const mm = String(today.getMonth() + 1).padStart(2, '0');
    const dd = String(today.getDate()).padStart(2, '0');
    const priorYear = today.getFullYear() - 1;
    const matchDate = `${priorYear}-${mm}-${dd}`;
    const locations = [{ status: 'been', name: 'Paris', visits: [{ date: matchDate }] }];
    const todayStr = today.toISOString().split('T')[0];
    const { ctx, bannerEl } = makeCtx({ locations, dismissedDate: todayStr });
    vm.runInContext('checkOnThisDay()', ctx);
    expect(bannerEl.style.display).toBe('none');
  });

  test('does not show banner when no visit matches today MM-DD', () => {
    // Use a date that definitely won't match today: far past with different MM-DD
    const locations = [{ status: 'been', name: 'Tokyo', visits: [{ date: '2020-01-01' }] }];
    // Override today to 2026-06-15 so 01-01 won't match
    const { ctx, bannerEl } = makeCtx({ locations, todayOverride: '2026-06-15' });
    vm.runInContext('checkOnThisDay()', ctx);
    expect(bannerEl.style.display).toBe('none');
  });

  test('does not show banner for bucket/wishlist locations', () => {
    const today = new Date();
    const mm = String(today.getMonth() + 1).padStart(2, '0');
    const dd = String(today.getDate()).padStart(2, '0');
    const priorYear = today.getFullYear() - 1;
    const matchDate = `${priorYear}-${mm}-${dd}`;
    const locations = [{ status: 'bucket', name: 'Bucket Place', visits: [{ date: matchDate }] }];
    const { ctx, bannerEl } = makeCtx({ locations });
    vm.runInContext('checkOnThisDay()', ctx);
    expect(bannerEl.style.display).toBe('none');
  });

  test('dismissOnThisDay hides banner and stores today in localStorage', () => {
    const { ctx, bannerEl, ls } = makeCtx();
    bannerEl.style.display = 'flex';
    vm.runInContext('dismissOnThisDay()', ctx);
    expect(bannerEl.style.display).toBe('none');
    expect(ls['hm_otd_dismissed']).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// 3. Year in Review — static markup
// ──────────────────────────────────────────────────────────────────────────────
describe('Year in Review — static markup', () => {
  test('#year-review-overlay exists with display:none', () => {
    expect(indexHtml).toContain('id="year-review-overlay"');
    expect(indexHtml).toMatch(/id="year-review-overlay"[^>]*style="[^"]*display:none/);
  });

  test('#yr-card and #yr-dots exist inside overlay', () => {
    const ovStart = indexHtml.indexOf('id="year-review-overlay"');
    const ovEnd = indexHtml.indexOf('</div>', ovStart + 500);
    const ovHtml = indexHtml.substring(ovStart, ovEnd + 6);
    expect(ovHtml).toContain('id="yr-card"');
    expect(ovHtml).toContain('id="yr-dots"');
  });

  test('prev/next buttons use data-click dispatcher', () => {
    expect(indexHtml).toMatch(/id="yr-prev"[\s\S]{0,100}data-click="yearReviewNav"[\s\S]{0,50}data-arg0="-1"/);
    expect(indexHtml).toMatch(/id="yr-next"[\s\S]{0,100}data-click="yearReviewNav"[\s\S]{0,50}data-arg0="1"/);
  });

  test('close button uses data-click="closeYearReview"', () => {
    expect(indexHtml).toMatch(/data-click="closeYearReview"/);
  });

  test('stats-view has Year in Review trigger button', () => {
    expect(indexHtml).toMatch(/data-click="showYearReview"[\s\S]{0,100}Year in Review/);
  });

  test('all yr functions defined', () => {
    ['showYearReview', '_showYearReviewForYear', '_renderYrCard', 'yearReviewNav', 'yearReviewGoTo', 'closeYearReview'].forEach(fn => {
      expect(indexHtml).toContain(`function ${fn}`);
    });
  });

  test('Escape handler closes yr-overlay before modals', () => {
    const escBlock = indexHtml.match(/key !== 'Escape'[\s\S]{0,1200}const modals = \[/);
    expect(escBlock).not.toBeNull();
    const block = escBlock[0];
    const yrPos = block.indexOf('year-review-overlay');
    const modalsPos = block.indexOf('const modals = [');
    expect(yrPos).toBeGreaterThan(-1);
    expect(yrPos).toBeLessThan(modalsPos);
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// 4. Neighborhoods — static + unit
// ──────────────────────────────────────────────────────────────────────────────
describe('Neighborhoods — static markup', () => {
  test('.neighborhood-label CSS rule exists at ≥12px', () => {
    expect(indexHtml).toMatch(/\.neighborhood-label\s*\{[^}]*font-size:\s*1[2-9]px/);
  });

  test('_nhLayer variable declared', () => {
    expect(indexHtml).toContain('_nhLayer');
  });

  test('all neighborhood functions defined', () => {
    ['_haversineM', '_clusterLocations', '_clusterLabel', '_updateNeighborhoodLayer'].forEach(fn => {
      expect(indexHtml).toContain(`function ${fn}`);
    });
  });

  test('_updateNeighborhoodLayer wired to zoomend in initMap', () => {
    const initMap = extractFunction('initMap');
    expect(initMap).toContain('_updateNeighborhoodLayer');
    expect(initMap).toMatch(/zoomend.*_updateNeighborhoodLayer|_updateNeighborhoodLayer.*zoomend/);
  });

  test('_updateNeighborhoodLayer called in startApp after renderMarkers', () => {
    const startApp = extractFunction('startApp');
    const renderPos = startApp.indexOf('renderMarkers()');
    const nhPos = startApp.indexOf('_updateNeighborhoodLayer()');
    expect(renderPos).toBeGreaterThan(-1);
    expect(nhPos).toBeGreaterThan(renderPos);
  });
});

describe('Neighborhoods — clustering logic', () => {
  function runCluster(locs, radiusM) {
    const code = [
      extractFunction('_haversineM'),
      extractFunction('_clusterLocations'),
      `__result = _clusterLocations(${JSON.stringify(locs)}, ${radiusM || 400});`,
    ].join('\n');
    const ctx = vm.createContext({ Math, Number, Array, Object, Uint8Array, __result: null });
    vm.runInContext(code, ctx);
    return ctx.__result;
  }

  test('two places within 400m cluster together', () => {
    const locs = [
      { status: 'been', lat: 38.7167, lng: -9.1395, address: 'Bairro Alto, Lisbon, Portugal' },
      { status: 'been', lat: 38.7185, lng: -9.1421, address: 'Bairro Alto Bar, Lisbon, Portugal' },
    ];
    const clusters = runCluster(locs, 400);
    expect(clusters.length).toBe(1);
    expect(clusters[0].length).toBe(2);
  });

  test('two places >400m apart do not cluster', () => {
    const locs = [
      { status: 'been', lat: 38.7167, lng: -9.1395, address: 'Bairro Alto, Lisbon, Portugal' },
      { status: 'been', lat: 38.6916, lng: -9.2160, address: 'Belém Tower, Lisbon, Portugal' },
    ];
    const clusters = runCluster(locs, 400);
    expect(clusters.length).toBe(0); // neither pair meets minPts=2 on its own
  });

  test('bucket/wishlist places are excluded from clusters', () => {
    const locs = [
      { status: 'been', lat: 38.7167, lng: -9.1395, address: 'Place A, Lisbon, Portugal' },
      { status: 'bucket', lat: 38.7185, lng: -9.1421, address: 'Wish B, Lisbon, Portugal' },
    ];
    const clusters = runCluster(locs, 400);
    expect(clusters.length).toBe(0);
  });

  test('_clusterLabel returns common first-segment when ≥2 share it', () => {
    const code = [
      extractFunction('_clusterLabel'),
      `__r = _clusterLabel([
        { address: 'Bairro Alto, Lisbon, Portugal' },
        { address: 'Bairro Alto, Lisbon, Portugal' },
        { address: 'Other Place, Lisbon, Portugal' },
      ]);`,
    ].join('\n');
    const ctx = vm.createContext({ Object, Array, String, __r: null });
    vm.runInContext(code, ctx);
    expect(ctx.__r).toContain('Bairro Alto');
    expect(ctx.__r).toContain('3');
  });

  test('_clusterLabel falls back to "N places" when no common segment', () => {
    const code = [
      extractFunction('_clusterLabel'),
      `__r = _clusterLabel([
        { address: 'Place A, Lisbon' },
        { address: 'Place B, Lisbon' },
        { address: 'Place C, Lisbon' },
      ]);`,
    ].join('\n');
    const ctx = vm.createContext({ Object, Array, String, __r: null });
    vm.runInContext(code, ctx);
    expect(ctx.__r).toBe('3 places');
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// 5. Photo Timeline — static markup
// ──────────────────────────────────────────────────────────────────────────────
describe('Photo Timeline — static markup', () => {
  test('#chrono-photo-toggle button exists with data-click="toggleChronoPhotos"', () => {
    expect(indexHtml).toMatch(/id="chrono-photo-toggle"[\s\S]{0,100}data-click="toggleChronoPhotos"/);
  });

  test('_chronoShowPhotos variable declared', () => {
    expect(indexHtml).toContain('_chronoShowPhotos');
  });

  test('toggleChronoPhotos function defined', () => {
    expect(indexHtml).toContain('function toggleChronoPhotos()');
  });

  test('renderChronology reads _chronoShowPhotos and accesses loc.media', () => {
    const fn = extractFunction('renderChronology');
    expect(fn).toContain('_chronoShowPhotos');
    expect(fn).toContain('loc.media');
    expect(fn).toContain('takenAt');
  });

  test('photo entries render with ti-photo class and 📷 emoji', () => {
    const fn = extractFunction('renderChronology');
    expect(fn).toContain('ti-photo');
    expect(fn).toContain('📷');
  });

  test('.ti-photo CSS rule exists', () => {
    expect(indexHtml).toMatch(/\.timeline-item\.ti-photo\s*\{/);
  });

  test('photo entries respect year/cat/trip filters (same guards as visits)', () => {
    const fn = extractFunction('renderChronology');
    const photoBlock = fn.slice(fn.indexOf('_chronoShowPhotos'));
    expect(photoBlock).toContain('yearFilter');
    expect(photoBlock).toContain('catFilter');
    expect(photoBlock).toContain('tripFilter');
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// 6+7. Plan view — covered in tests/wishlist-view.test.js (file renamed)

// ──────────────────────────────────────────────────────────────────────────────
// 8. Share Trip — static markup
// ──────────────────────────────────────────────────────────────────────────────
describe('Share Trip — static markup', () => {
  test('#share-link-modal exists with display:none', () => {
    expect(indexHtml).toContain('id="share-link-modal"');
    expect(indexHtml).toMatch(/id="share-link-modal"[^>]*display:none/);
  });

  test('#share-link-url input inside modal', () => {
    const start = indexHtml.indexOf('id="share-link-modal"');
    const end = indexHtml.indexOf('</div>', start + 400);
    const html = indexHtml.substring(start, end + 6);
    expect(html).toContain('id="share-link-url"');
  });

  test('Copy button uses data-click="copyShareLink"', () => {
    expect(indexHtml).toMatch(/data-click="copyShareLink"/);
  });

  test('Revoke button uses data-click="revokeShareLink"', () => {
    expect(indexHtml).toMatch(/data-click="revokeShareLink"/);
  });

  test('Close button uses data-click="closeShareLinkModal"', () => {
    expect(indexHtml).toMatch(/data-click="closeShareLinkModal"/);
  });

  test('🔗 Share button in trips view uses data-click="shareTripLink"', () => {
    expect(indexHtml).toMatch(/data-click="shareTripLink"/);
    expect(indexHtml).toMatch(/id="share-trip-btn"[\s\S]{0,100}data-click="shareTripLink"/);
  });

  test('all share functions defined', () => {
    ['shareTripLink', 'closeShareLinkModal', 'copyShareLink', 'revokeShareLink'].forEach(fn => {
      expect(indexHtml).toContain(`function ${fn}`);
    });
  });

  test('Escape closes share-link-modal', () => {
    const escBlock = indexHtml.match(/key !== 'Escape'[\s\S]{0,2000}const modals = \[/);
    expect(escBlock).not.toBeNull();
    expect(escBlock[0]).toContain('share-link-modal');
    expect(escBlock[0]).toContain('closeShareLinkModal');
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// 9. Share Trip — server routes
// ──────────────────────────────────────────────────────────────────────────────
describe('Share Trip — server routes', () => {
  const serverJs = require('fs').readFileSync(
    require('path').join(__dirname, '..', 'server', 'index.js'), 'utf-8'
  );

  test('POST /api/trips/:id/share route exists', () => {
    expect(serverJs).toMatch(/app\.post\(['"]\/api\/trips\/:id\/share['"]/);
  });

  test('DELETE /api/trips/:id/share route exists', () => {
    expect(serverJs).toMatch(/app\.delete\(['"]\/api\/trips\/:id\/share['"]/);
  });

  test('GET /api/share/:token route exists (no auth)', () => {
    expect(serverJs).toMatch(/app\.get\(['"]\/api\/share\/:token['"]/);
    // Must NOT have auth middleware in the share route
    const shareRouteIdx = serverJs.indexOf("app.get('/api/share/:token'");
    const routeBlock = serverJs.slice(shareRouteIdx, shareRouteIdx + 200);
    expect(routeBlock).not.toContain(', auth,');
  });

  test('share token uses crypto.randomBytes(20)', () => {
    expect(serverJs).toMatch(/randomBytes\(20\)\.toString\(['"]hex['"]\)/);
  });

  test('token format validated with regex before DB query', () => {
    expect(serverJs).toContain('SHARE_TOKEN_RE');
    expect(serverJs).toMatch(/SHARE_TOKEN_RE\s*=\s*\/\^/);
  });

  test('GET /s/:token route serves share.html', () => {
    expect(serverJs).toMatch(/app\.get\(['"]\/s\/:token['"]/);
    expect(serverJs).toContain('share.html');
    expect(serverJs).toContain('__CSP_NONCE__');
  });

  test('share data endpoint strips userId and shareToken from response', () => {
    const shareRouteIdx = serverJs.indexOf("app.get('/api/share/:token'");
    const routeEnd = serverJs.indexOf('});', shareRouteIdx);
    const routeBlock = serverJs.slice(shareRouteIdx, routeEnd + 3);
    expect(routeBlock).not.toContain("'userId'");
    expect(routeBlock).not.toContain("'shareToken'");
    expect(routeBlock).not.toContain('"userId"');
    expect(routeBlock).not.toContain('"shareToken"');
  });
});
