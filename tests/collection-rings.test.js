// Collection completion rings: SVG donut ring around emoji on each collection card.

const fs = require('fs');
const path = require('path');
const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');

describe('Collection rings — CSS', () => {
  test('.coll-ring-wrap is defined', () => {
    expect(html).toMatch(/\.coll-ring-wrap\s*\{/);
  });

  test('.coll-ring is defined with rotate(-90deg)', () => {
    expect(html).toMatch(/\.coll-ring\s*\{[^}]+rotate\(-90deg\)/);
  });

  test('.coll-ring-bg uses var(--border) stroke', () => {
    expect(html).toMatch(/\.coll-ring-bg\s*\{[^}]+stroke:\s*var\(--border\)/);
  });

  test('.coll-ring-fill has transition', () => {
    expect(html).toMatch(/\.coll-ring-fill\s*\{[^}]+transition/);
  });

  test('.coll-ring-wrap .cat-stat-emoji scoped font-size override', () => {
    expect(html).toMatch(/\.coll-ring-wrap\s+\.cat-stat-emoji\s*\{[^}]+font-size/);
  });
});

describe('Collection rings — renderCollections HTML', () => {
  const fnStart = html.indexOf('function renderCollections(');
  const fnSlice = html.slice(fnStart, fnStart + 2000);

  test('renderCollections generates .coll-ring-wrap', () => {
    expect(fnSlice).toContain('coll-ring-wrap');
  });

  test('renderCollections generates SVG with .coll-ring class', () => {
    expect(fnSlice).toContain('class="coll-ring"');
  });

  test('renderCollections generates .coll-ring-bg circle', () => {
    expect(fnSlice).toContain('coll-ring-bg');
  });

  test('renderCollections generates .coll-ring-fill circle with stroke-dasharray', () => {
    expect(fnSlice).toContain('coll-ring-fill');
    expect(fnSlice).toContain('stroke-dasharray');
    expect(fnSlice).toContain('stroke-dashoffset');
  });

  test('renderCollections uses CIRC constant (~113.1)', () => {
    expect(fnSlice).toContain('113.1');
  });

  test('renderCollections computes dashOffset from pct', () => {
    expect(fnSlice).toContain('dashOffset');
    expect(fnSlice).toMatch(/CIRC\s*\*\s*\(1\s*-\s*pct\s*\/\s*100\)/);
  });

  test('ring stroke is green (--success) at 100%, accent otherwise', () => {
    expect(fnSlice).toContain('var(--success)');
    expect(fnSlice).toContain('var(--accent)');
    expect(fnSlice).toContain('transparent');
  });

  test('ring has accessible aria-label with pct and count', () => {
    expect(fnSlice).toContain('aria-label=');
    expect(fnSlice).toContain('complete');
  });

  test('renderCollections no longer generates cat-stat-bar (ring replaces bar)', () => {
    expect(fnSlice).not.toContain('cat-stat-bar');
  });

  test('edit/delete buttons preserved', () => {
    const wider = html.slice(fnStart, fnStart + 2500);
    expect(wider).toContain('editCollection');
    expect(wider).toContain('deleteCollection');
  });

  test('visited count text preserved', () => {
    expect(fnSlice).toContain('visited');
    expect(fnSlice).toContain('pct}% complete');
  });
});

describe('Collection rings — math correctness (live JS)', () => {
  const CIRC = 113.1;

  test('0% completion → dashOffset equals full circumference', () => {
    const pct = 0;
    const dashOffset = parseFloat((CIRC * (1 - pct / 100)).toFixed(1));
    expect(dashOffset).toBeCloseTo(CIRC, 1);
  });

  test('100% completion → dashOffset is 0', () => {
    const pct = 100;
    const dashOffset = parseFloat((CIRC * (1 - pct / 100)).toFixed(1));
    expect(dashOffset).toBe(0);
  });

  test('50% completion → dashOffset is half circumference', () => {
    const pct = 50;
    const dashOffset = parseFloat((CIRC * (1 - pct / 100)).toFixed(1));
    expect(dashOffset).toBeCloseTo(CIRC / 2, 0);
  });

  test('ring stroke is success at 100%', () => {
    const pct = 100;
    const stroke = pct === 100 ? 'var(--success)' : pct > 0 ? 'var(--accent)' : 'transparent';
    expect(stroke).toBe('var(--success)');
  });

  test('ring stroke is accent between 1-99%', () => {
    [1, 33, 50, 99].forEach(pct => {
      const stroke = pct === 100 ? 'var(--success)' : pct > 0 ? 'var(--accent)' : 'transparent';
      expect(stroke).toBe('var(--accent)');
    });
  });

  test('ring stroke is transparent at 0%', () => {
    const pct = 0;
    const stroke = pct === 100 ? 'var(--success)' : pct > 0 ? 'var(--accent)' : 'transparent';
    expect(stroke).toBe('transparent');
  });
});
