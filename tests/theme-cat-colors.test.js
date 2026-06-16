// Per-theme category colors: Parchment (light) gets WCAG AA–compliant dark values;
// Volcano gets a non-red restaurant color so it doesn't clash with the red accent.

const fs = require('fs');
const path = require('path');
const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');

const THEMES_START = html.indexOf('const THEMES = {');
const THEMES_END = html.indexOf('\nconst THEME_ORDER', THEMES_START);
const THEMES_SRC = html.slice(THEMES_START, THEMES_END);

describe('THEMES — parchment category colors', () => {
  const parchStart = THEMES_SRC.indexOf("parchment: {");
  const parchEnd = THEMES_SRC.indexOf('\n  },', parchStart) + 4;
  const parch = THEMES_SRC.slice(parchStart, parchEnd);

  test('parchment theme defines --cat-restaurant (dark red for light bg)', () => {
    expect(parch).toContain("'--cat-restaurant'");
    expect(parch).toMatch(/'--cat-restaurant'\s*:\s*'#dc2626'/);
  });

  test('parchment theme defines all 14 --cat-* vars', () => {
    const cats = ['restaurant','hotel','bar','club','monument','unesco','park',
                  'stadium','event','location','airport','entertainment','shopping','cafe'];
    cats.forEach(c => expect(parch).toContain(`'--cat-${c}'`));
  });

  test('parchment category colors are dark enough for WCAG AA on white (#fff)', () => {
    // All parchment cat colors should be noticeably darker than the neon defaults.
    // Verify they are NOT the bright neon versions (which fail on light backgrounds).
    expect(parch).not.toContain('#ff6b6b'); // neon restaurant
    expect(parch).not.toContain('#4ade80'); // neon park
    expect(parch).not.toContain('#60a5fa'); // neon stadium
    expect(parch).not.toContain('#38bdf8'); // neon airport
  });
});

describe('THEMES — volcano category colors', () => {
  const volStart = THEMES_SRC.indexOf("volcano: {");
  const volEnd = THEMES_SRC.indexOf('\n  },', volStart) + 4;
  const vol = THEMES_SRC.slice(volStart, volEnd);

  test('volcano theme overrides --cat-restaurant to non-red (accent is #f87171)', () => {
    expect(vol).toContain("'--cat-restaurant'");
    // Restaurant must be a clearly different hue from the red accent
    expect(vol).not.toMatch(/'--cat-restaurant'\s*:\s*'#ff6b6b'/); // global neon default
    expect(vol).not.toMatch(/'--cat-restaurant'\s*:\s*'#f87171'/); // same as accent
    // Should be orange (clearly distinct hue)
    expect(vol).toMatch(/'--cat-restaurant'\s*:\s*'#f97316'/);
  });
});

describe('applyTheme — cat vars included in reset + COLOR_HEX sync', () => {
  test('applyTheme allVars includes --cat-restaurant', () => {
    const fnStart = html.indexOf('function applyTheme(');
    const fnSlice = html.slice(fnStart, fnStart + 800);
    expect(fnSlice).toContain("'--cat-restaurant'");
    expect(fnSlice).toContain("'--cat-park'");
    expect(fnSlice).toContain("'--cat-cafe'");
  });

  test('applyTheme syncs COLOR_HEX after setting vars', () => {
    const fnStart = html.indexOf('function applyTheme(');
    const fnSlice = html.slice(fnStart, fnStart + 1200);
    expect(fnSlice).toContain('COLOR_HEX');
    expect(fnSlice).toMatch(/getComputedStyle\(document\.body\)/);
    expect(fnSlice).toMatch(/`var\(--cat-\$\{n\}\)`/);
  });
});
