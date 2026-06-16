// Stats KPI ribbon + tabs: 4-tab stats view replacing the scroll dump.

const fs = require('fs');
const path = require('path');
const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');

describe('Stats tabs — markup', () => {
  test('stats-tabs container exists', () => {
    expect(html).toContain('class="stats-tabs"');
  });

  test('4 tab buttons exist', () => {
    const matches = html.match(/class="stats-tab\b/g) || [];
    expect(matches.length).toBeGreaterThanOrEqual(4);
  });

  test('overview tab is active by default', () => {
    expect(html).toMatch(/class="stats-tab active"[^>]*data-arg0="overview"/);
  });

  test('overview tab wired to switchStatsTab', () => {
    expect(html).toMatch(/data-click="switchStatsTab"[^>]*data-arg0="overview"/);
  });

  test('countries tab wired to switchStatsTab', () => {
    expect(html).toMatch(/data-click="switchStatsTab"[^>]*data-arg0="countries"/);
  });

  test('categories tab wired to switchStatsTab', () => {
    expect(html).toMatch(/data-click="switchStatsTab"[^>]*data-arg0="categories"/);
  });

  test('timing tab wired to switchStatsTab', () => {
    expect(html).toMatch(/data-click="switchStatsTab"[^>]*data-arg0="timing"/);
  });
});

describe('Stats tabs — panels', () => {
  test('stats-tab-overview panel exists and is active by default', () => {
    expect(html).toMatch(/id="stats-tab-overview"[^>]*class="stats-tab-panel active"|class="stats-tab-panel active"[^>]*id="stats-tab-overview"/);
  });

  test('stats-tab-countries panel exists', () => {
    expect(html).toContain('id="stats-tab-countries"');
  });

  test('stats-tab-categories panel exists', () => {
    expect(html).toContain('id="stats-tab-categories"');
  });

  test('stats-tab-timing panel exists', () => {
    expect(html).toContain('id="stats-tab-timing"');
  });

  test('chart-ratings canvas in overview panel', () => {
    const overviewStart = html.indexOf('id="stats-tab-overview"');
    const overviewEnd = html.indexOf('id="stats-tab-countries"');
    const slice = html.substring(overviewStart, overviewEnd);
    expect(slice).toContain('id="chart-ratings"');
    expect(slice).toContain('id="chart-activity"');
  });

  test('nights-list and people-leaderboard in overview panel', () => {
    const overviewStart = html.indexOf('id="stats-tab-overview"');
    const overviewEnd = html.indexOf('id="stats-tab-countries"');
    const slice = html.substring(overviewStart, overviewEnd);
    expect(slice).toContain('id="nights-list"');
    expect(slice).toContain('id="people-leaderboard"');
  });

  test('achievements-grid in overview panel', () => {
    const overviewStart = html.indexOf('id="stats-tab-overview"');
    const overviewEnd = html.indexOf('id="stats-tab-countries"');
    const slice = html.substring(overviewStart, overviewEnd);
    expect(slice).toContain('id="achievements-grid"');
  });

  test('countries-flags in countries panel', () => {
    const start = html.indexOf('id="stats-tab-countries"');
    const end = html.indexOf('id="stats-tab-categories"');
    const slice = html.substring(start, end);
    expect(slice).toContain('id="countries-flags"');
    expect(slice).toContain('id="stats-currency-toggle"');
  });

  test('category-stats in categories panel', () => {
    const start = html.indexOf('id="stats-tab-categories"');
    const end = html.indexOf('id="stats-tab-timing"');
    const slice = html.substring(start, end);
    expect(slice).toContain('id="category-stats"');
  });

  test('timing charts in timing panel', () => {
    const start = html.indexOf('id="stats-tab-timing"');
    const slice = html.substring(start, start + 2000);
    expect(slice).toContain('id="chart-dow"');
    expect(slice).toContain('id="chart-month"');
    expect(slice).toContain('id="timing-cat-filter"');
  });

  test('KPI ribbon still present outside tabs', () => {
    expect(html).toContain('id="stats-top-cards"');
    // Verify stats-top-cards comes BEFORE stats-tabs (it's outside the panels)
    const ribbonIdx = html.indexOf('id="stats-top-cards"');
    const tabsIdx = html.indexOf('class="stats-tabs"');
    expect(ribbonIdx).toBeLessThan(tabsIdx);
  });
});

describe('Stats tabs — switchStatsTab function', () => {
  test('switchStatsTab is defined', () => {
    expect(html).toContain('function switchStatsTab(');
  });

  test('switchStatsTab toggles active class on tab panels', () => {
    expect(html).toMatch(/switchStatsTab[\s\S]{0,200}stats-tab-panel/);
  });

  test('switchStatsTab handles timing tab resize', () => {
    const fnStart = html.indexOf('function switchStatsTab(');
    const fnSlice = html.substring(fnStart, fnStart + 600);
    expect(fnSlice).toContain("'timing'");
    expect(fnSlice).toContain('chartDow');
    expect(fnSlice).toContain('chartMonth');
  });

  test('switchStatsTab handles overview tab resize', () => {
    const fnStart = html.indexOf('function switchStatsTab(');
    const fnSlice = html.substring(fnStart, fnStart + 800);
    expect(fnSlice).toContain("'overview'");
    expect(fnSlice).toContain('chartRatings');
    expect(fnSlice).toContain('chartActivity');
  });
});

describe('ARIA — nav tabs', () => {
  test('nav has role="tablist" and aria-label', () => {
    expect(html).toMatch(/class="nav-tabs"\s+role="tablist"/);
    expect(html).toContain('aria-label="Views"');
  });

  test('every nav-tab button has role="tab"', () => {
    const matches = html.match(/class="nav-tab[^"]*"\s+role="tab"/g) || [];
    expect(matches.length).toBeGreaterThanOrEqual(10);
  });

  test('initial Map tab has aria-selected="true", others have false', () => {
    const mapBtn = html.match(/class="nav-tab active"[^>]*>/)?.[0] || '';
    expect(mapBtn).toContain('aria-selected="true"');
    // Count false — should be at least 9
    const falseCount = (html.match(/aria-selected="false"/g) || []).length;
    expect(falseCount).toBeGreaterThanOrEqual(9);
  });

  test('switchView sets aria-selected on the active tab', () => {
    const fnStart = html.indexOf('function switchView(');
    const fnSlice = html.substring(fnStart, fnStart + 600);
    expect(fnSlice).toContain('aria-selected');
    expect(fnSlice).toContain("setAttribute('aria-selected', 'true')");
  });
});

describe('ARIA — stats tabs', () => {
  test('stats-tabs div has aria-label', () => {
    expect(html).toContain('aria-label="Statistics views"');
  });

  test('initial Overview stats-tab has aria-selected="true"', () => {
    expect(html).toMatch(/class="stats-tab active"\s+role="tab"\s+aria-selected="true"/);
  });

  test('switchStatsTab sets aria-selected', () => {
    const fnStart = html.indexOf('function switchStatsTab(');
    const fnSlice = html.substring(fnStart, fnStart + 400);
    expect(fnSlice).toContain("setAttribute('aria-selected'");
  });
});

describe('ARIA — dialog overlays', () => {
  test('_trapFocus helper is defined', () => {
    expect(html).toContain('function _trapFocus(');
  });

  test('showConfirm box has role="dialog" and aria-modal="true"', () => {
    const fnStart = html.indexOf('function showConfirm(');
    const fnSlice = html.substring(fnStart, fnStart + 500);
    expect(fnSlice).toContain('role="dialog"');
    expect(fnSlice).toContain('aria-modal="true"');
    expect(fnSlice).toContain('aria-labelledby=');
  });

  test('showPrompt box has role="dialog" and aria-modal="true"', () => {
    const fnStart = html.indexOf('function showPrompt(');
    const fnSlice = html.substring(fnStart, fnStart + 500);
    expect(fnSlice).toContain('role="dialog"');
    expect(fnSlice).toContain('aria-modal="true"');
  });

  test('showMultiPrompt box has role="dialog" and aria-modal="true"', () => {
    const fnStart = html.indexOf('function showMultiPrompt(');
    const fnSlice = html.substring(fnStart, fnStart + 1500);
    expect(fnSlice).toContain('role="dialog"');
    expect(fnSlice).toContain('aria-modal="true"');
  });

  test('showConfirm restores focus on close', () => {
    const fnStart = html.indexOf('function showConfirm(');
    const fnSlice = html.substring(fnStart, fnStart + 1200);
    expect(fnSlice).toContain('prevFocus');
    expect(fnSlice).toContain('prevFocus?.focus()');
  });

  test('showConfirm closes on Escape', () => {
    const fnStart = html.indexOf('function showConfirm(');
    const fnSlice = html.substring(fnStart, fnStart + 2000);
    expect(fnSlice).toContain("'Escape'");
  });
});

describe('computeStats() memoization', () => {
  test('_statsCache and _statsCacheGen variables declared', () => {
    expect(html).toContain('let _statsCache = null');
    expect(html).toContain('let _statsCacheGen = -1');
  });

  test('computeStats() checks generation before recomputing', () => {
    const fnStart = html.indexOf('function computeStats()');
    const fnSlice = html.substring(fnStart, fnStart + 200);
    expect(fnSlice).toMatch(/_statsCacheGen === stateIndex\.generation/);
    expect(fnSlice).toContain('return _statsCache');
  });

  test('computeStats() writes _statsCache before returning', () => {
    const fnStart = html.indexOf('function computeStats()');
    const fnEnd = html.indexOf('\n}', fnStart + 100);
    const fnSlice = html.substring(fnStart, fnEnd + 2);
    expect(fnSlice).toContain('_statsCache = s');
  });

  test('computeStats() stamps the generation after miss', () => {
    const fnStart = html.indexOf('function computeStats()');
    const fnSlice = html.substring(fnStart, fnStart + 200);
    expect(fnSlice).toContain('_statsCacheGen = stateIndex.generation');
  });
});

describe('Stats tabs — CSS', () => {
  test('.stats-tabs CSS exists', () => {
    expect(html).toContain('.stats-tabs');
  });

  test('.stats-tab CSS exists', () => {
    expect(html).toContain('.stats-tab {');
  });

  test('.stats-tab.active CSS exists', () => {
    expect(html).toContain('.stats-tab.active');
  });

  test('.stats-tab-panel default is display:none', () => {
    expect(html).toMatch(/\.stats-tab-panel\s*\{[^}]*display\s*:\s*none/);
  });

  test('.stats-tab-panel.active is display:block', () => {
    expect(html).toMatch(/\.stats-tab-panel\.active\s*\{[^}]*display\s*:\s*block/);
  });
});
