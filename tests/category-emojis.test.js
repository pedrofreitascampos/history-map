// Category emoji uniqueness — regression for Monument/Museum collision.

const fs = require('fs');
const path = require('path');
const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');

describe('Category emoji uniqueness', () => {
  // Extract the CATEGORIES object text
  const catStart = html.indexOf('const CATEGORIES = {');
  const catSlice = html.substring(catStart, catStart + 1500);

  test('museum emoji is 🏺', () => {
    expect(catSlice).toMatch(/museum\s*:\s*\{[^}]*emoji\s*:\s*'🏺'/);
  });

  test('monument emoji is 🏛️', () => {
    expect(catSlice).toMatch(/monument\s*:\s*\{[^}]*emoji\s*:\s*'🏛️'/);
  });

  test('museum and monument have different emojis', () => {
    const museumMatch = catSlice.match(/museum\s*:\s*\{[^}]*emoji\s*:\s*'([^']+)'/);
    const monumentMatch = catSlice.match(/monument\s*:\s*\{[^}]*emoji\s*:\s*'([^']+)'/);
    expect(museumMatch).toBeTruthy();
    expect(monumentMatch).toBeTruthy();
    expect(museumMatch[1]).not.toBe(monumentMatch[1]);
  });

  test('discover modal museum option shows 🏺', () => {
    expect(html).toContain('value="museum">🏺 Museum');
  });

  test('discover modal monument option shows 🏛️', () => {
    expect(html).toContain('value="monument">🏛️ Monument');
  });
});
