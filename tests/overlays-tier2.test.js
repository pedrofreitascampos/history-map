// Dynamic overlays Tier 2+ (#15): USGS earthquakes + ISS live position.

const path = require('path');
const fs = require('fs');
const vm = require('vm');

const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');
const serverSrc = fs.readFileSync(path.join(__dirname, '..', 'server', 'index.js'), 'utf-8');

// ── Static markup ─────────────────────────────────────────────────────────
describe('Tier 2 overlays — static markup', () => {
  test('#overlay-usgs_eq-btn exists', () => {
    expect(html).toContain('id="overlay-usgs_eq-btn"');
  });

  test('usgs_eq button wired to toggleOverlay', () => {
    expect(html).toMatch(/id="overlay-usgs_eq-btn"[^>]*data-click="toggleOverlay"/);
  });

  test('usgs_eq button passes correct arg', () => {
    expect(html).toMatch(/id="overlay-usgs_eq-btn"[^>]*data-arg0="usgs_eq"/);
  });

  test('#overlay-iss-btn exists', () => {
    expect(html).toContain('id="overlay-iss-btn"');
  });

  test('iss button wired to toggleOverlay', () => {
    expect(html).toMatch(/id="overlay-iss-btn"[^>]*data-click="toggleOverlay"/);
  });

  test('iss button passes correct arg', () => {
    expect(html).toMatch(/id="overlay-iss-btn"[^>]*data-arg0="iss"/);
  });
});

// ── DYNAMIC_OVERLAYS definitions ─────────────────────────────────────────
describe('Tier 2 overlays — DYNAMIC_OVERLAYS entries', () => {
  function extractOverlaysBlock() {
    const start = html.indexOf('const DYNAMIC_OVERLAYS');
    if (start === -1) throw new Error('DYNAMIC_OVERLAYS not found');
    let depth = 0, i = start, found = false;
    for (; i < html.length; i++) {
      if (html[i] === '{') { depth++; found = true; }
      if (html[i] === '}') depth--;
      if (found && depth === 0) break;
    }
    return html.substring(start, i + 1);
  }

  let block;
  beforeAll(() => { block = extractOverlaysBlock(); });

  test('DYNAMIC_OVERLAYS contains usgs_eq key', () => {
    expect(block).toContain('usgs_eq');
  });

  test('DYNAMIC_OVERLAYS contains iss key', () => {
    expect(block).toContain('iss');
  });

  test('usgs_eq has attach and detach functions', () => {
    const usgsStart = block.indexOf('usgs_eq');
    const usgsSection = block.substring(usgsStart, usgsStart + 1800);
    expect(usgsSection).toContain('attach');
    expect(usgsSection).toContain('detach');
  });

  test('iss has attach and detach functions', () => {
    // Search the block for the iss overlay key — use the label as anchor since
    // 'iss:' can appear in other contexts (e.g. inside URL strings).
    expect(block).toContain("'ISS position'");
    expect(block).toContain('wheretheiss.at');
    // attach and detach must both appear after the iss label
    const issLabelIdx = block.indexOf("'ISS position'");
    const afterIss = block.substring(issLabelIdx, issLabelIdx + 2000);
    expect(afterIss).toContain('attach');
    expect(afterIss).toContain('detach');
  });

  test('usgs_eq uses USGS GeoJSON feed URL', () => {
    expect(block).toContain('earthquake.usgs.gov');
    expect(block).toContain('2.5_week.geojson');
  });

  test('iss uses wheretheiss.at API', () => {
    expect(block).toContain('wheretheiss.at');
    expect(block).toContain('25544');
  });

  test('usgs_eq circles scale by magnitude', () => {
    const usgsStart = block.indexOf('usgs_eq');
    const usgsSection = block.substring(usgsStart, usgsStart + 1500);
    expect(usgsSection).toContain('mag');
    expect(usgsSection).toContain('circleMarker');
  });

  test('iss auto-updates via setInterval', () => {
    const issLabelIdx = block.indexOf("'ISS position'");
    const afterIss = block.substring(issLabelIdx, issLabelIdx + 2000);
    expect(afterIss).toContain('setInterval');
    expect(afterIss).toContain('10000');
  });

  test('iss detach clears the interval', () => {
    const issLabelIdx = block.indexOf("'ISS position'");
    const afterIss = block.substring(issLabelIdx, issLabelIdx + 2000);
    expect(afterIss).toContain('clearInterval');
    expect(afterIss).toContain('_issTimer');
  });

  test('usgs_eq shows magnitude in tooltip', () => {
    const usgsStart = block.indexOf('usgs_eq');
    const usgsSection = block.substring(usgsStart, usgsStart + 1500);
    expect(usgsSection).toContain('bindTooltip');
    expect(usgsSection).toContain('p.mag');
  });

  test('usgs_eq color-codes by magnitude (red ≥6, amber ≥4, indigo lower)', () => {
    const usgsStart = block.indexOf('usgs_eq');
    const usgsSection = block.substring(usgsStart, usgsStart + 1500);
    expect(usgsSection).toContain('#ef4444');
    expect(usgsSection).toContain('#f59e0b');
    expect(usgsSection).toContain('#6366f1');
  });
});

// ── CSP whitelisting ───────────────────────────────────────────────────────
describe('Tier 2 overlays — CSP', () => {
  test('CSP connectSrc includes earthquake.usgs.gov', () => {
    expect(serverSrc).toContain('earthquake.usgs.gov');
  });

  test('CSP connectSrc includes api.wheretheiss.at', () => {
    expect(serverSrc).toContain('api.wheretheiss.at');
  });
});
