// ⌘K quick-add modal: geocode search → pre-filled openAddModal.

const fs = require('fs');
const path = require('path');
const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');

describe('Quick-add modal — HTML structure', () => {
  test('#quick-add-modal exists with role=dialog', () => {
    expect(html).toContain('id="quick-add-modal"');
    expect(html).toContain('role="dialog"');
  });

  test('#quick-add-modal uses .modal-overlay class', () => {
    const idx = html.indexOf('id="quick-add-modal"');
    expect(html.slice(idx - 5, idx + 70)).toContain('modal-overlay');
  });

  test('#quick-add-input exists with data-input="quickAddSearch"', () => {
    expect(html).toContain('id="quick-add-input"');
    expect(html).toContain('data-input="quickAddSearch"');
  });

  test('#quick-add-results container exists', () => {
    expect(html).toContain('id="quick-add-results"');
  });

  test('close button uses data-click="closeQuickAddModal"', () => {
    expect(html).toContain('data-click="closeQuickAddModal"');
  });

  test('label references quick-add-title', () => {
    expect(html).toContain('id="quick-add-title"');
    expect(html).toContain('aria-labelledby="quick-add-title"');
  });
});

describe('Quick-add modal — CSS', () => {
  test('.quick-add-result button style defined', () => {
    expect(html).toMatch(/\.quick-add-result\s*\{/);
  });

  test('.qa-name and .qa-sub styles defined', () => {
    expect(html).toContain('.qa-name');
    expect(html).toContain('.qa-sub');
  });
});

describe('Quick-add modal — functions', () => {
  test('openQuickAddModal is defined', () => {
    expect(html).toContain('function openQuickAddModal(');
  });

  test('closeQuickAddModal is defined', () => {
    expect(html).toContain('function closeQuickAddModal(');
  });

  test('quickAddSearch is defined', () => {
    expect(html).toContain('function quickAddSearch(');
  });

  test('quickAddPick is defined', () => {
    expect(html).toContain('function quickAddPick(');
  });

  test('openQuickAddModal opens #quick-add-modal', () => {
    const fnStart = html.indexOf('function openQuickAddModal(');
    const fnSlice = html.slice(fnStart, fnStart + 350);
    expect(fnSlice).toContain('quick-add-modal');
    expect(fnSlice).toContain('classList.add');
  });

  test('closeQuickAddModal removes .open and clears timer', () => {
    const fnStart = html.indexOf('function closeQuickAddModal(');
    const fnSlice = html.slice(fnStart, fnStart + 200);
    expect(fnSlice).toContain('classList.remove');
    expect(fnSlice).toContain('clearTimeout');
    expect(fnSlice).toContain('restoreFocus');
  });

  test('quickAddSearch calls /geocode via api()', () => {
    const fnStart = html.indexOf('function quickAddSearch(');
    const fnSlice = html.slice(fnStart, fnStart + 600);
    expect(fnSlice).toContain('/geocode');
    expect(fnSlice).toContain('encodeURIComponent');
  });

  test('quickAddSearch debounces with setTimeout', () => {
    const fnStart = html.indexOf('function quickAddSearch(');
    const fnSlice = html.slice(fnStart, fnStart + 600);
    expect(fnSlice).toContain('_quickAddTimer');
    expect(fnSlice).toContain('setTimeout');
  });

  test('quickAddSearch escapes HTML in results', () => {
    const fnStart = html.indexOf('function quickAddSearch(');
    const fnSlice = html.slice(fnStart, fnStart + 1100);
    expect(fnSlice).toContain('esc(');
  });

  test('quickAddPick calls openAddModal with lat/lon', () => {
    const fnStart = html.indexOf('function quickAddPick(');
    const fnSlice = html.slice(fnStart, fnStart + 300);
    expect(fnSlice).toContain('openAddModal(');
    expect(fnSlice).toContain('r.lat');
    expect(fnSlice).toContain('r.lon');
  });

  test('quickAddPick pre-fills loc-name and loc-address', () => {
    const fnStart = html.indexOf('function quickAddPick(');
    const fnSlice = html.slice(fnStart, fnStart + 400);
    expect(fnSlice).toContain('loc-name');
    expect(fnSlice).toContain('loc-address');
  });

  test('quickAddPick calls closeQuickAddModal before opening add modal', () => {
    const fnStart = html.indexOf('function quickAddPick(');
    const fnSlice = html.slice(fnStart, fnStart + 300);
    const closeIdx = fnSlice.indexOf('closeQuickAddModal');
    const openIdx = fnSlice.indexOf('openAddModal');
    expect(closeIdx).toBeGreaterThan(0);
    expect(openIdx).toBeGreaterThan(closeIdx);
  });
});

describe('Quick-add — keyboard handler', () => {
  test('Ctrl+K / ⌘K opens quick-add modal', () => {
    expect(html).toMatch(/\(e\.ctrlKey \|\| e\.metaKey\) && e\.key === ['"]k['"]/);
    expect(html).toContain('openQuickAddModal()');
  });

  test('⌘K handler prevents default browser behavior', () => {
    const handlerIdx = html.indexOf("e.ctrlKey || e.metaKey) && e.key === 'k'");
    const slice = html.slice(handlerIdx - 30, handlerIdx + 100);
    expect(slice).toContain('e.preventDefault()');
  });
});

describe('Quick-add — Escape integration', () => {
  test('Escape closes quick-add-modal via closeQuickAddModal', () => {
    const escIdx = html.indexOf("e.key !== 'Escape'");
    const slice = html.slice(escIdx, escIdx + 1600);
    expect(slice).toContain('quick-add-modal');
    expect(slice).toContain('closeQuickAddModal()');
  });
});

describe('Quick-add — shortcuts overlay updated', () => {
  test('shortcuts modal mentions ⌘K shortcut', () => {
    const modalIdx = html.indexOf('id="shortcuts-modal"');
    const slice = html.slice(modalIdx, modalIdx + 2500);
    expect(slice).toContain('Quick add location');
  });
});
