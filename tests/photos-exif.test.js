// Photos EXIF — vm-sandbox tests for client-side photo-attach functions.
// Mirrors the style of tests/trips-v2.test.js: extract functions from
// public/index.html, inject mocks, run in an isolated vm context.
const path = require('path');
const fs = require('fs');
const vm = require('vm');

const indexHtml = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');

function extractFunction(name) {
  const start = indexHtml.indexOf(`function ${name}(`);
  if (start === -1) throw new Error(`Function ${name} not found`);
  let depth = 0, i = start, foundFirst = false;
  for (; i < indexHtml.length; i++) {
    if (indexHtml[i] === '{') { depth++; foundFirst = true; }
    if (indexHtml[i] === '}') depth--;
    if (foundFirst && depth === 0) break;
  }
  return indexHtml.substring(start, i + 1);
}

function extractAsyncFunction(name) {
  const start = indexHtml.indexOf(`async function ${name}(`);
  if (start === -1) throw new Error(`Async function ${name} not found`);
  let depth = 0, i = start, foundFirst = false;
  for (; i < indexHtml.length; i++) {
    if (indexHtml[i] === '{') { depth++; foundFirst = true; }
    if (indexHtml[i] === '}') depth--;
    if (foundFirst && depth === 0) break;
  }
  return indexHtml.substring(start, i + 1);
}

function makeCtx({ exifrImpl, mediaReturn, locLat, locLng } = {}) {
  // Shared mutable loc — _handlePhotoFiles mutates it in place
  const loc = { lat: locLat || 38.7, lng: locLng || -9.1, media: [] };

  const domElements = {
    'loc-photo-list': { innerHTML: '', appendChild: () => {}, childNodes: [] },
    'loc-photo-warn': { style: { display: 'none' }, textContent: '' },
    'loc-photo-input': { click: () => {}, value: '' },
  };

  const sandbox = {
    console,
    Map, Set, Array, Object, Math, JSON, Promise,
    parseFloat, parseInt, isFinite, isNaN,
    Date, RegExp, Error, Number, String, Boolean,
    setTimeout: (fn) => fn(),
    // exifr mock — injected per test
    exifr: exifrImpl || {
      parse: async () => null,
    },
    // haversineKm stub — real implementation
    haversineKm: null, // filled below
    esc: (s) => String(s),
    state: { editingId: 'test-id' },
    stateIndex: {
      locationById: new Map([['test-id', loc]]),
    },
    document: {
      getElementById: (id) => domElements[id] || null,
      createElement: (tag) => {
        const el = {
          tagName: tag.toUpperCase(),
          style: { cssText: '' },
          innerHTML: '',
          dataset: {},
          appendChild: () => {},
          children: [],
          childNodes: [],
          remove: () => {},
        };
        return el;
      },
    },
    _loc: loc,        // exposed for assertions
    _domElements: domElements,
  };

  // Inject the real haversineKm
  const haversineCode = extractFunction('haversineKm');
  const ctx = vm.createContext(sandbox);
  vm.runInContext(haversineCode, ctx);

  const code = [
    extractFunction('_distanceMeters'),
    extractFunction('_checkPhotoDistance'),
    extractFunction('_renderAttachedPhotos'),
    extractFunction('_removeAttachedPhoto'),
    extractAsyncFunction('_handlePhotoFiles'),
  ].join('\n');
  vm.runInContext(code, ctx);

  return { ctx, sandbox, loc };
}

// ────────────────────────────────────────────────────────────
// _distanceMeters
// ────────────────────────────────────────────────────────────
describe('_distanceMeters', () => {
  test('returns ~0 for identical coordinates', () => {
    const { ctx } = makeCtx();
    const d = vm.runInContext('_distanceMeters(38.7, -9.1, 38.7, -9.1)', ctx);
    expect(d).toBeCloseTo(0, 0);
  });

  test('returns ~111 km for 1° latitude delta', () => {
    const { ctx } = makeCtx();
    const d = vm.runInContext('_distanceMeters(0, 0, 1, 0)', ctx);
    expect(d).toBeGreaterThan(110_000);
    expect(d).toBeLessThan(112_000);
  });
});

// ────────────────────────────────────────────────────────────
// _handlePhotoFiles
// ────────────────────────────────────────────────────────────
describe('_handlePhotoFiles', () => {
  function makeFile({ name = 'test.jpg', size = 1000 } = {}) {
    return { name, size };
  }

  test('extracts GPS + date from EXIF and pushes to loc.media', async () => {
    const { ctx, loc } = makeCtx({
      exifrImpl: {
        parse: async () => ({
          latitude: 38.7,
          longitude: -9.1,
          DateTimeOriginal: new Date('2025-06-15T12:00:00Z'),
        }),
      },
    });

    await vm.runInContext('_handlePhotoFiles([{ name: "beach.jpg", size: 100 }])', ctx);
    expect(loc.media).toHaveLength(1);
    const m = loc.media[0];
    expect(m.filename).toBe('beach.jpg');
    expect(m.lat).toBeCloseTo(38.7);
    expect(m.lon).toBeCloseTo(-9.1);
    expect(m.takenAt).toContain('2025-06-15');
    expect(m.source).toBe('manual');
  });

  test('attaches a photo with no GPS (omits lat/lon fields)', async () => {
    const { ctx, loc } = makeCtx({
      exifrImpl: {
        parse: async () => ({
          DateTimeOriginal: new Date('2025-01-01T10:00:00Z'),
          // no latitude/longitude
        }),
      },
    });

    await vm.runInContext('_handlePhotoFiles([{ name: "no-gps.jpg", size: 100 }])', ctx);
    expect(loc.media).toHaveLength(1);
    expect(loc.media[0].lat).toBeUndefined();
    expect(loc.media[0].lon).toBeUndefined();
    expect(loc.media[0].takenAt).toContain('2025-01-01');
  });

  test('attaches a photo with no date (omits takenAt)', async () => {
    const { ctx, loc } = makeCtx({
      exifrImpl: {
        parse: async () => ({
          latitude: 48.8,
          longitude: 2.3,
          // no DateTimeOriginal
        }),
      },
    });

    await vm.runInContext('_handlePhotoFiles([{ name: "no-date.jpg", size: 100 }])', ctx);
    expect(loc.media).toHaveLength(1);
    expect(loc.media[0].lat).toBeCloseTo(48.8);
    expect(loc.media[0].takenAt).toBeUndefined();
  });

  test('skips files > 50 MB', async () => {
    const parseMock = jest.fn().mockResolvedValue(null);
    const { ctx, loc } = makeCtx({
      exifrImpl: { parse: parseMock },
    });

    const bigFile = JSON.stringify({ name: 'big.jpg', size: 51 * 1024 * 1024 });
    await vm.runInContext(`_handlePhotoFiles([${bigFile}])`, ctx);
    expect(loc.media).toHaveLength(0);
    expect(parseMock).not.toHaveBeenCalled();
  });

  test('caps the media array at 100 entries', async () => {
    const { ctx, loc } = makeCtx({
      exifrImpl: { parse: async () => null },
    });
    // Pre-fill with 98 entries
    for (let i = 0; i < 98; i++) loc.media.push({ source: 'manual', filename: `old${i}.jpg` });

    // Add 7 more (total 105, should cap at 100)
    const files = JSON.stringify(
      Array.from({ length: 7 }, (_, i) => ({ name: `new${i}.jpg`, size: 100 }))
    );
    await vm.runInContext(`_handlePhotoFiles(${files})`, ctx);
    expect(loc.media).toHaveLength(100);
  });

  test('truncates filename to 255 chars', async () => {
    const { ctx, loc } = makeCtx({
      exifrImpl: { parse: async () => null },
    });
    const longName = 'a'.repeat(300) + '.jpg';
    const file = JSON.stringify({ name: longName, size: 100 });
    await vm.runInContext(`_handlePhotoFiles([${file}])`, ctx);
    expect(loc.media).toHaveLength(1);
    expect(loc.media[0].filename.length).toBe(255);
  });

  test('survives an exifr.parse() rejection — attaches metadata-only entry with just filename', async () => {
    const { ctx, loc } = makeCtx({
      exifrImpl: {
        parse: async () => { throw new Error('parse failed'); },
      },
    });

    await vm.runInContext('_handlePhotoFiles([{ name: "crash.jpg", size: 100 }])', ctx);
    expect(loc.media).toHaveLength(1);
    expect(loc.media[0].filename).toBe('crash.jpg');
    expect(loc.media[0].lat).toBeUndefined();
    expect(loc.media[0].takenAt).toBeUndefined();
  });

  test('clamps invalid GPS — lat out of range → omit lat/lon', async () => {
    const { ctx, loc } = makeCtx({
      exifrImpl: {
        parse: async () => ({ latitude: 999, longitude: 200 }),
      },
    });
    await vm.runInContext('_handlePhotoFiles([{ name: "bad-gps.jpg", size: 100 }])', ctx);
    expect(loc.media[0].lat).toBeUndefined();
    expect(loc.media[0].lon).toBeUndefined();
  });
});

// ────────────────────────────────────────────────────────────
// _removeAttachedPhoto
// ────────────────────────────────────────────────────────────
describe('_removeAttachedPhoto', () => {
  test('removes the photo at the specified index', () => {
    const { ctx, loc } = makeCtx();
    loc.media = [
      { source: 'manual', filename: 'first.jpg' },
      { source: 'manual', filename: 'second.jpg' },
      { source: 'manual', filename: 'third.jpg' },
    ];

    vm.runInContext('_removeAttachedPhoto("1")', ctx);
    expect(loc.media).toHaveLength(2);
    expect(loc.media[0].filename).toBe('first.jpg');
    expect(loc.media[1].filename).toBe('third.jpg');
  });

  test('no-ops on out-of-range index', () => {
    const { ctx, loc } = makeCtx();
    loc.media = [{ source: 'manual', filename: 'only.jpg' }];
    vm.runInContext('_removeAttachedPhoto("99")', ctx);
    expect(loc.media).toHaveLength(1);
  });
});

// ────────────────────────────────────────────────────────────
// _checkPhotoDistance
// ────────────────────────────────────────────────────────────
describe('_checkPhotoDistance', () => {
  test('shows warn when a photo is > 5 km away from the location', () => {
    const { ctx, loc, sandbox } = makeCtx({ locLat: 38.7, locLng: -9.1 });
    // ~12 km away
    loc.media = [{ source: 'manual', filename: 'far.jpg', lat: 38.81, lon: -9.1 }];

    vm.runInContext('_checkPhotoDistance(_loc)', ctx);
    expect(sandbox._domElements['loc-photo-warn'].style.display).toBe('');
    expect(sandbox._domElements['loc-photo-warn'].textContent).toContain('km from this location');
  });

  test('hides warn when all photos are within 5 km', () => {
    const { ctx, loc, sandbox } = makeCtx({ locLat: 38.7, locLng: -9.1 });
    // ~100 m away
    loc.media = [{ source: 'manual', filename: 'close.jpg', lat: 38.701, lon: -9.1 }];

    vm.runInContext('_checkPhotoDistance(_loc)', ctx);
    expect(sandbox._domElements['loc-photo-warn'].style.display).toBe('none');
  });

  test('hides warn when media has no GPS coords', () => {
    const { ctx, loc, sandbox } = makeCtx({ locLat: 38.7, locLng: -9.1 });
    loc.media = [{ source: 'manual', filename: 'no-gps.jpg' }];

    vm.runInContext('_checkPhotoDistance(_loc)', ctx);
    expect(sandbox._domElements['loc-photo-warn'].style.display).toBe('none');
  });
});

// ────────────────────────────────────────────────────────────
// _renderAttachedPhotos — XSS guard
// ────────────────────────────────────────────────────────────
describe('_renderAttachedPhotos XSS guard', () => {
  test('escapes filenames containing <script> (XSS regression)', () => {
    const renderedRows = [];
    const { ctx, loc, sandbox } = makeCtx();

    // Install a proper HTML-escaping esc() in the vm context so the XSS test is meaningful
    // (the makeCtx default uses String() passthrough — we override it here)
    vm.runInContext(`esc = (s) => String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;')`, ctx);

    // Override document.createElement to capture innerHTML
    sandbox.document.createElement = (tag) => {
      const el = {
        tagName: tag,
        style: { cssText: '' },
        innerHTML: '',
        dataset: {},
        appendChild: () => {},
      };
      renderedRows.push(el);
      return el;
    };
    sandbox._domElements['loc-photo-list'].appendChild = () => {};

    loc.media = [{
      source: 'manual',
      filename: '<script>alert(1)</script>.jpg',
      takenAt: '2025-01-01T00:00:00Z',
    }];

    vm.runInContext('_renderAttachedPhotos(_loc)', ctx);
    const row = renderedRows[0];
    expect(row.innerHTML).not.toContain('<script>');
    expect(row.innerHTML).toContain('&lt;script&gt;');
  });
});
