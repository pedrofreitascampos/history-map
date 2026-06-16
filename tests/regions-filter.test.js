// Regions view: filter Atlas map by region click (filter chip + View on Atlas button).

const fs = require('fs');
const path = require('path');
const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');

describe('Regions filter — state.filters', () => {
  test('state.filters has regionLocs: null initial value', () => {
    expect(html).toMatch(/regionLocs\s*:\s*null/);
  });

  test('state.filters has regionLabel initial value', () => {
    expect(html).toMatch(/regionLabel\s*:\s*['"]{2}/);
  });
});

describe('Regions filter — getFilteredLocations cache key', () => {
  test('filtersKey includes regionLabel', () => {
    const fnStart = html.indexOf('function getFilteredLocations(');
    const fnSlice = html.substring(fnStart, fnStart + 800);
    expect(fnSlice).toContain('regionLabel');
  });

  test('getFilteredLocations checks regionLocs', () => {
    const fnStart = html.indexOf('function getFilteredLocations(');
    const fnSlice = html.substring(fnStart, fnStart + 1000);
    expect(fnSlice).toContain('regionLocs');
    expect(fnSlice).toContain('regionLocs.has');
  });
});

describe('Regions filter — JS functions', () => {
  test('filterAtlasByLocs is defined', () => {
    expect(html).toContain('function filterAtlasByLocs(');
  });

  test('filterAtlasByLocs sets regionLocs and regionLabel', () => {
    const fnStart = html.indexOf('function filterAtlasByLocs(');
    const fnSlice = html.substring(fnStart, fnStart + 400);
    expect(fnSlice).toContain('regionLocs');
    expect(fnSlice).toContain('regionLabel');
  });

  test('filterAtlasByLocs calls switchView map-view', () => {
    const fnStart = html.indexOf('function filterAtlasByLocs(');
    const fnSlice = html.substring(fnStart, fnStart + 400);
    expect(fnSlice).toContain("switchView('map-view')");
  });

  test('clearRegionFilter is defined', () => {
    expect(html).toContain('function clearRegionFilter(');
  });

  test('clearRegionFilter nulls regionLocs', () => {
    const fnStart = html.indexOf('function clearRegionFilter(');
    const fnSlice = html.substring(fnStart, fnStart + 300);
    expect(fnSlice).toContain('regionLocs = null');
  });

  test('_applyRegionPopupFilter is defined', () => {
    expect(html).toContain('function _applyRegionPopupFilter(');
  });

  test('_updateRegionFilterChip is defined', () => {
    expect(html).toContain('function _updateRegionFilterChip(');
  });

  test('_regionPopupData variable declared', () => {
    expect(html).toContain('_regionPopupData');
    expect(html).toMatch(/let\s+_regionPopupData\s*=/);
  });
});

describe('Regions filter — sidebar chip', () => {
  test('region-filter-chip exists in sidebar', () => {
    const sidebarStart = html.indexOf('<aside id="sidebar">');
    const sidebarEnd = html.indexOf('</aside>', sidebarStart);
    const sidebar = html.substring(sidebarStart, sidebarEnd);
    expect(sidebar).toContain('id="region-filter-chip"');
  });

  test('region-filter-chip starts hidden', () => {
    expect(html).toMatch(/id="region-filter-chip"[^>]*display:none|id="region-filter-chip"[^>]*style="[^"]*display\s*:\s*none/);
  });

  test('region-filter-label element exists', () => {
    expect(html).toContain('id="region-filter-label"');
  });

  test('clear button calls clearRegionFilter', () => {
    const chipStart = html.indexOf('id="region-filter-chip"');
    const chipSlice = html.substring(chipStart, chipStart + 500);
    expect(chipSlice).toContain('data-click="clearRegionFilter"');
  });
});

describe('Regions filter — popup View on Atlas buttons', () => {
  test('showRegionLocations sets _regionPopupData', () => {
    const fnStart = html.indexOf('function showRegionLocations(');
    const fnSlice = html.substring(fnStart, fnStart + 500);
    expect(fnSlice).toContain('_regionPopupData');
  });

  test('showRegionLocations popup has View on Atlas button', () => {
    const fnStart = html.indexOf('function showRegionLocations(');
    const fnSlice = html.substring(fnStart, fnStart + 800);
    expect(fnSlice).toContain('View on Atlas');
    expect(fnSlice).toContain('data-click="_applyRegionPopupFilter"');
  });

  test('showCountryLocations sets _regionPopupData', () => {
    const fnStart = html.indexOf('function showCountryLocations(');
    const fnSlice = html.substring(fnStart, fnStart + 500);
    expect(fnSlice).toContain('_regionPopupData');
  });

  test('showCountryLocations popup has View on Atlas button', () => {
    const fnStart = html.indexOf('function showCountryLocations(');
    const fnSlice = html.substring(fnStart, fnStart + 700);
    expect(fnSlice).toContain('View on Atlas');
    expect(fnSlice).toContain('data-click="_applyRegionPopupFilter"');
  });

  test('showCityLocations sets _regionPopupData', () => {
    const fnStart = html.indexOf('function showCityLocations(');
    const fnSlice = html.substring(fnStart, fnStart + 600);
    expect(fnSlice).toContain('_regionPopupData');
  });

  test('showCityLocations popup has View on Atlas button', () => {
    const fnStart = html.indexOf('function showCityLocations(');
    const fnSlice = html.substring(fnStart, fnStart + 800);
    expect(fnSlice).toContain('View on Atlas');
    expect(fnSlice).toContain('data-click="_applyRegionPopupFilter"');
  });
});

describe('Regions filter — drill-down zoom', () => {
  test('region mode click calls fitBounds', () => {
    const fnStart = html.indexOf('function _renderRegionMode_region(');
    const fnSlice = html.substring(fnStart, fnStart + 1000);
    expect(fnSlice).toContain('fitBounds');
    expect(fnSlice).toContain('getBounds');
  });

  test('country mode click calls fitBounds', () => {
    const fnStart = html.indexOf('function _renderRegionMode_country(');
    const fnSlice = html.substring(fnStart, fnStart + 1000);
    expect(fnSlice).toContain('fitBounds');
    expect(fnSlice).toContain('countryFeatures');
  });
});
