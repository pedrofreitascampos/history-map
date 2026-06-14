// Import preview diff (#9) — classify adds / updates / skips before committing.

const path = require('path');
const fs = require('fs');
const vm = require('vm');

const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');

function extractFunction(name) {
  const start = html.indexOf(`function ${name}(`);
  if (start === -1) throw new Error(`Function ${name} not found`);
  let depth = 0, i = start, found = false;
  for (; i < html.length; i++) {
    if (html[i] === '{') { depth++; found = true; }
    if (html[i] === '}') depth--;
    if (found && depth === 0) break;
  }
  return html.substring(start, i + 1);
}

// ── Static markup ─────────────────────────────────────────────────────────
describe('Import diff — static markup', () => {
  test('#import-diff-header exists', () => {
    expect(html).toContain('id="import-diff-header"');
  });

  test('#import-diff-body exists', () => {
    expect(html).toContain('id="import-diff-body"');
  });

  test('#import-confirm-btn exists', () => {
    expect(html).toContain('id="import-confirm-btn"');
  });

  test('_classifyImportItems function defined', () => {
    expect(html).toContain('function _classifyImportItems(');
  });

  test('import-add-cb class used for add checkboxes', () => {
    expect(html).toContain('import-add-cb');
  });

  test('import-update-cb class used for update checkboxes', () => {
    expect(html).toContain('import-update-cb');
  });

  test('diff CSS classes present', () => {
    expect(html).toContain('diff-badge-add');
    expect(html).toContain('diff-badge-update');
    expect(html).toContain('diff-badge-skip');
    expect(html).toContain('diff-section-add');
    expect(html).toContain('diff-section-update');
    expect(html).toContain('diff-section-skip');
  });

  test('pendingImportUpdates in state initializer', () => {
    expect(html).toMatch(/pendingImportUpdates\s*:\s*\[\]/);
  });

  test('cancelImport clears pendingImportUpdates and _importPreClassified', () => {
    const fn = extractFunction('cancelImport');
    expect(fn).toContain('pendingImportUpdates');
    expect(fn).toContain('_importPreClassified');
  });

  test('confirmImport handles .import-add-cb checkboxes', () => {
    const fn = extractFunction('confirmImport');
    expect(fn).toContain('import-add-cb');
    expect(fn).toContain('import-update-cb');
  });

  test('confirmImport pre-classified path applies pendingImportUpdates before bulk insert', () => {
    const fn = extractFunction('confirmImport');
    expect(fn).toContain('_importPreClassified');
    expect(fn).toContain('pendingImportUpdates');
  });
});

// ── _classifyImportItems logic (vm) ──────────────────────────────────────
function makeClassifyCtx(existingLocs, incomingItems) {
  const code = [
    `function haversineKm(lat1, lng1, lat2, lng2) {
      const R = 6371;
      const dLat = (lat2 - lat1) * Math.PI / 180;
      const dLng = (lng2 - lng1) * Math.PI / 180;
      const a = Math.sin(dLat/2)**2 + Math.cos(lat1*Math.PI/180)*Math.cos(lat2*Math.PI/180)*Math.sin(dLng/2)**2;
      return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    }`,
    `const state = { locations: ${JSON.stringify(existingLocs)} };`,
    extractFunction('findDuplicate'),
    extractFunction('_classifyImportItems'),
    `__result = _classifyImportItems(${JSON.stringify(incomingItems)});`,
  ].join('\n');
  const ctx = vm.createContext({ Math, Set, Map, Array, JSON, Infinity, __result: null });
  vm.runInContext(code, ctx);
  return ctx.__result;
}

describe('Import diff — _classifyImportItems', () => {
  test('all items are adds when no existing locations', () => {
    const items = [
      { name: 'Cafe A', lat: 1, lng: 1, visits: [] },
      { name: 'Cafe B', lat: 2, lng: 2, visits: [] },
    ];
    const { adds, updates, skips } = makeClassifyCtx([], items);
    expect(adds).toHaveLength(2);
    expect(updates).toHaveLength(0);
    expect(skips).toHaveLength(0);
  });

  test('exact name match with no new visits → skip', () => {
    const existing = [{ name: 'Cafe A', lat: 1, lng: 1, visits: [{ date: '2024-01-01' }] }];
    const items = [{ name: 'Cafe A', lat: 1, lng: 1, visits: [{ date: '2024-01-01' }] }];
    const { adds, updates, skips } = makeClassifyCtx(existing, items);
    expect(adds).toHaveLength(0);
    expect(updates).toHaveLength(0);
    expect(skips).toHaveLength(1);
    expect(skips[0].existing.name).toBe('Cafe A');
  });

  test('name match with new visit date → update (not skip)', () => {
    const existing = [{ name: 'Cafe A', lat: 1, lng: 1, visits: [{ date: '2024-01-01' }] }];
    const items = [{ name: 'Cafe A', lat: 1, lng: 1, visits: [{ date: '2024-06-15' }] }];
    const { adds, updates, skips } = makeClassifyCtx(existing, items);
    expect(adds).toHaveLength(0);
    expect(updates).toHaveLength(1);
    expect(skips).toHaveLength(0);
    expect(updates[0].newVisits[0].date).toBe('2024-06-15');
    expect(updates[0].existing.name).toBe('Cafe A');
  });

  test('mixed incoming: one new, one update, one skip', () => {
    const existing = [
      { name: 'Old Place', lat: 1, lng: 1, visits: [{ date: '2023-01-01' }] },
      { name: 'Dup Place', lat: 2, lng: 2, visits: [{ date: '2023-05-01' }] },
    ];
    const items = [
      { name: 'Brand New', lat: 5, lng: 5, visits: [] },           // add
      { name: 'Old Place', lat: 1, lng: 1, visits: [{ date: '2024-07-01' }] }, // update
      { name: 'Dup Place', lat: 2, lng: 2, visits: [{ date: '2023-05-01' }] }, // skip
    ];
    const { adds, updates, skips } = makeClassifyCtx(existing, items);
    expect(adds).toHaveLength(1);
    expect(adds[0].name).toBe('Brand New');
    expect(updates).toHaveLength(1);
    expect(updates[0].newVisits[0].date).toBe('2024-07-01');
    expect(skips).toHaveLength(1);
    expect(skips[0].item.name).toBe('Dup Place');
  });

  test('item with no visits and existing has no visits → skip', () => {
    const existing = [{ name: 'Bar X', lat: 3, lng: 3, visits: [] }];
    const items = [{ name: 'Bar X', lat: 3, lng: 3, visits: [] }];
    const { adds, updates, skips } = makeClassifyCtx(existing, items);
    expect(skips).toHaveLength(1);
    expect(updates).toHaveLength(0);
  });

  test('geo proximity match (within 50m) without name match → skip when no new visits', () => {
    // 48.8566, 2.3522 and 48.85664, 2.35224 are ~5m apart
    const existing = [{ name: 'Notre Dame', lat: 48.8566, lng: 2.3522, visits: [] }];
    const items = [{ name: 'Notre-Dame Cathedral', lat: 48.85664, lng: 2.35224, visits: [] }];
    const { adds, updates, skips } = makeClassifyCtx(existing, items);
    expect(skips).toHaveLength(1);
    expect(adds).toHaveLength(0);
  });
});
