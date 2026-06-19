// ? keyboard-shortcut overlay + / focus-search shortcut.

const fs = require('fs');
const path = require('path');
const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');

describe('Keyboard shortcut overlay — HTML structure', () => {
  test('#shortcuts-modal exists with role=dialog', () => {
    expect(html).toContain('id="shortcuts-modal"');
    expect(html).toContain('role="dialog"');
    expect(html).toContain('aria-modal="true"');
  });

  test('#shortcuts-modal uses .modal-overlay class (standard open/close pattern)', () => {
    const idx = html.indexOf('id="shortcuts-modal"');
    const slice = html.slice(idx, idx + 60);
    expect(slice).toContain('modal-overlay');
  });

  test('close button uses data-click="closeShortcutsModal"', () => {
    expect(html).toContain('data-click="closeShortcutsModal"');
  });

  test('modal lists ? shortcut', () => {
    const idx = html.indexOf('id="shortcuts-modal"');
    const slice = html.slice(idx, idx + 2000);
    expect(slice).toContain('Open this overlay');
  });

  test('modal lists / shortcut for search', () => {
    const idx = html.indexOf('id="shortcuts-modal"');
    const slice = html.slice(idx, idx + 2000);
    expect(slice).toContain('Focus map search');
  });

  test('modal lists Escape shortcut', () => {
    const idx = html.indexOf('id="shortcuts-modal"');
    const slice = html.slice(idx, idx + 2000);
    expect(slice).toContain('Close dialog');
  });

  test('uses <kbd> elements for key display', () => {
    const idx = html.indexOf('id="shortcuts-modal"');
    const slice = html.slice(idx, idx + 2000);
    expect(slice).toContain('<kbd>');
  });
});

describe('Keyboard shortcut overlay — functions', () => {
  test('openShortcutsModal is defined', () => {
    expect(html).toContain('function openShortcutsModal(');
  });

  test('closeShortcutsModal is defined', () => {
    expect(html).toContain('function closeShortcutsModal(');
  });

  test('openShortcutsModal adds .open class to #shortcuts-modal', () => {
    const fnStart = html.indexOf('function openShortcutsModal(');
    const fnSlice = html.slice(fnStart, fnStart + 200);
    expect(fnSlice).toContain('shortcuts-modal');
    expect(fnSlice).toContain('classList.add');
    expect(fnSlice).toContain("'open'");
  });

  test('closeShortcutsModal removes .open class and restores focus', () => {
    const fnStart = html.indexOf('function closeShortcutsModal(');
    const fnSlice = html.slice(fnStart, fnStart + 150);
    expect(fnSlice).toContain('classList.remove');
    expect(fnSlice).toContain('restoreFocus');
  });
});

describe('Keyboard shortcut overlay — key handlers', () => {
  test('? key handler opens the modal', () => {
    expect(html).toContain("e.key === '?'");
    expect(html).toContain('openShortcutsModal()');
  });

  test('/ key handler focuses #map-search-input', () => {
    expect(html).toMatch(/e\.key\s*===\s*['"]\/['"]/);
    expect(html).toContain('map-search-input');
  });

  test('key handlers skip when focus is in an input', () => {
    const handlerIdx = html.indexOf("e.key === '?' && !e.ctrlKey");
    const beforeSlice = html.slice(handlerIdx - 300, handlerIdx);
    expect(beforeSlice).toMatch(/inInput.*return|return.*inInput/s);
  });

  test('key handlers skip when a modal is already open', () => {
    const handlerIdx = html.indexOf("e.key === '?' && !e.ctrlKey");
    const beforeSlice = html.slice(handlerIdx - 300, handlerIdx);
    expect(beforeSlice).toMatch(/modal-overlay\.open/);
  });

  test('Escape handler includes shortcuts-modal in modal list', () => {
    // Find the const modals array inside the Escape keydown handler
    const arrIdx = html.indexOf("const modals = ['shortcuts-modal'");
    expect(arrIdx).toBeGreaterThan(0);
    // Verify it's inside the Escape handler by checking the surrounding context
    const slice = html.slice(arrIdx - 50, arrIdx + 120);
    expect(slice).toContain('shortcuts-modal');
  });
});

describe('Keyboard shortcut overlay — topbar button', () => {
  test('⌨️ button exists in topbar with data-click="openShortcutsModal"', () => {
    expect(html).toContain('data-click="openShortcutsModal"');
    const btnIdx = html.indexOf('data-click="openShortcutsModal"');
    const slice = html.slice(btnIdx - 5, btnIdx + 160);
    expect(slice).toMatch(/⌨/);
  });
});

describe('<kbd> CSS', () => {
  test('kbd element has CSS styling', () => {
    expect(html).toMatch(/kbd\s*\{[^}]+font-family/);
  });
});
