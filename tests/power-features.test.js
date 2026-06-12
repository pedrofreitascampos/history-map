// Power features regression tests — S4 batch.
// Static markup + vm-sandbox coverage for On This Day, Year in Review, and future power features.

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
