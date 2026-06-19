// Per-category marker style: each category can specify a default shape used
// when the global markerStyle is 'circle' (the default/unset state).

const fs = require('fs');
const path = require('path');
const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');

const VALID_SHAPES = ['circle', 'squircle', 'teardrop', 'glyph', 'pill'];

// Parse CATEGORIES from source to test structure
function parseCategories(src) {
  const start = src.indexOf('const CATEGORIES = {');
  const end = src.indexOf('};', start) + 2;
  const block = src.slice(start, end);
  const result = {};
  // Extract each key: { ...shape: '...'... }
  const keyRe = /(\w+)\s*:\s*\{([^}]+)\}/g;
  let m;
  while ((m = keyRe.exec(block)) !== null) {
    const key = m[1];
    const shapeM = /shape:\s*'([^']+)'/.exec(m[2]);
    result[key] = { shape: shapeM ? shapeM[1] : 'circle' };
  }
  return result;
}

describe('Per-category marker style — CATEGORIES shape property', () => {
  const cats = parseCategories(html);

  test('CATEGORIES is defined in source', () => {
    expect(html).toContain('const CATEGORIES = {');
  });

  test('all shape values are valid marker style names', () => {
    for (const [key, cat] of Object.entries(cats)) {
      if (cat.shape !== 'circle') {
        expect(VALID_SHAPES).toContain(cat.shape);
      }
    }
  });

  test('monument has shape teardrop', () => {
    expect(cats.monument.shape).toBe('teardrop');
  });

  test('museum has shape teardrop', () => {
    expect(cats.museum.shape).toBe('teardrop');
  });

  test('airport has shape teardrop', () => {
    expect(cats.airport.shape).toBe('teardrop');
  });

  test('location has shape teardrop', () => {
    expect(cats.location.shape).toBe('teardrop');
  });

  test('park has shape glyph', () => {
    expect(cats.park.shape).toBe('glyph');
  });

  test('restaurant has shape squircle', () => {
    expect(cats.restaurant.shape).toBe('squircle');
  });

  test('hotel has shape squircle', () => {
    expect(cats.hotel.shape).toBe('squircle');
  });

  test('cafe has shape squircle', () => {
    expect(cats.cafe.shape).toBe('squircle');
  });

  test('shopping has shape squircle', () => {
    expect(cats.shopping.shape).toBe('squircle');
  });
});

describe('Per-category marker style — marker building code', () => {
  test('globalStyle variable resolves from state.markerStyle', () => {
    const fnStart = html.indexOf('const globalStyle = (state && state.markerStyle)');
    expect(fnStart).toBeGreaterThan(0);
    const slice = html.slice(fnStart, fnStart + 200);
    expect(slice).toContain("|| 'circle'");
  });

  test('catShape resolves from CATEGORIES[loc.category].shape', () => {
    const idx = html.indexOf('const catShape = ');
    expect(idx).toBeGreaterThan(0);
    const slice = html.slice(idx, idx + 120);
    expect(slice).toContain('CATEGORIES[loc.category]');
    expect(slice).toContain('.shape');
  });

  test('catShape falls back to circle when category has no shape', () => {
    const idx = html.indexOf('const catShape = ');
    const slice = html.slice(idx, idx + 120);
    expect(slice).toContain("|| 'circle'");
  });

  test('style resolves to catShape when globalStyle is circle', () => {
    const idx = html.indexOf('const style = globalStyle === ');
    expect(idx).toBeGreaterThan(0);
    const slice = html.slice(idx, idx + 80);
    expect(slice).toContain('catShape');
    expect(slice).toContain('globalStyle');
  });

  test('global style override takes precedence over category shape', () => {
    const idx = html.indexOf('const style = globalStyle === ');
    const slice = html.slice(idx, idx + 80);
    // When globalStyle !== 'circle', we use globalStyle directly
    expect(slice).toMatch(/globalStyle\s*===\s*'circle'\s*\?\s*catShape\s*:\s*globalStyle/);
  });

  test('styleClass uses resolved style variable', () => {
    const idx = html.indexOf('const styleClass = style === ');
    expect(idx).toBeGreaterThan(0);
    const slice = html.slice(idx, idx + 80);
    expect(slice).toContain("' style-' + style");
  });
});
