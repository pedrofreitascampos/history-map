// Google Maps Saved Places import — Takeout GeoJSON parser tests.

const path = require('path');
const fs = require('fs');
const vm = require('vm');

const indexHtml = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');

function extractFunction(name) {
  const start = indexHtml.indexOf(`function ${name}(`);
  if (start === -1) throw new Error(`Function ${name} not found`);
  let depth = 0, i = start, found = false;
  for (; i < indexHtml.length; i++) {
    if (indexHtml[i] === '{') { depth++; found = true; }
    if (indexHtml[i] === '}') depth--;
    if (found && depth === 0) break;
  }
  return indexHtml.substring(start, i + 1);
}

// ── Static markup ─────────────────────────────────────────────────────────
describe('Google Saved Places — static markup', () => {
  test('parseGoogleSavedPlaces function defined', () => {
    expect(indexHtml).toContain('function parseGoogleSavedPlaces(');
  });

  test('onGoogleSavedImport function defined', () => {
    expect(indexHtml).toContain('function onGoogleSavedImport(');
  });

  test('#google-saved-input file input exists', () => {
    expect(indexHtml).toContain('id="google-saved-input"');
  });

  test('#google-saved-input wired to onGoogleSavedImport', () => {
    expect(indexHtml).toMatch(/id="google-saved-input"[^>]*data-change="onGoogleSavedImport"/);
  });

  test('Import button targets google-saved-input', () => {
    expect(indexHtml).toMatch(/data-target="google-saved-input"/);
  });

  test('detection guard covers new "Google Maps URL" key', () => {
    const block = indexHtml.slice(
      indexHtml.indexOf('Google Takeout Saved Places'),
      indexHtml.indexOf('Google Takeout Saved Places') + 300
    );
    expect(block).toContain("'Google Maps URL'");
  });
});

// ── parseGoogleSavedPlaces — vm sandbox ──────────────────────────────────
function runParser(data, status) {
  const code = [
    extractFunction('extractPlaceId'),
    // inferCategory stub
    'function inferCategory(s) { return "location"; }',
    extractFunction('parseGoogleSavedPlaces'),
    `__r = parseGoogleSavedPlaces(${JSON.stringify(data)}, ${JSON.stringify(status ?? 'been')});`,
  ].join('\n');
  const ctx = vm.createContext({ Math, Array, Number, parseFloat, isFinite, JSON, __r: null });
  vm.runInContext(code, ctx);
  return ctx.__r;
}

const NEW_FORMAT_FEATURE = {
  type: 'Feature',
  geometry: { type: 'Point', coordinates: [2.2945, 48.8584] },
  properties: {
    Title: 'Eiffel Tower',
    'Google Maps URL': 'https://maps.google.com/?cid=12345',
    Location: {
      Name: 'Eiffel Tower',
      Address: 'Champ de Mars, 75007 Paris, France',
      'Geo Coordinates': { Latitude: '48.858400', Longitude: '2.294500' },
      Website: 'https://toureiffel.paris',
    },
    Updated: '2024-03-15T10:30:00Z',
    Published: '2024-03-15T10:30:00Z',
  },
};

const OLD_FORMAT_FEATURE = {
  type: 'Feature',
  geometry: { type: 'Point', coordinates: [-73.9857, 40.7484] },
  properties: {
    Title: 'Empire State Building',
    google_maps_url: 'https://maps.google.com/?q=place_id:ChIJabc123',
    location: { name: 'Empire State Building', address: '350 5th Ave, New York, NY' },
  },
};

describe('Google Saved Places — new Takeout format', () => {
  const data = { type: 'FeatureCollection', features: [NEW_FORMAT_FEATURE] };

  test('extracts name from Title', () => {
    expect(runParser(data)[0].name).toBe('Eiffel Tower');
  });

  test('extracts lat/lng from Geo Coordinates strings', () => {
    const r = runParser(data)[0];
    expect(r.lat).toBeCloseTo(48.8584, 3);
    expect(r.lng).toBeCloseTo(2.2945, 3);
  });

  test('extracts address from Location.Address', () => {
    expect(runParser(data)[0].address).toContain('Paris');
  });

  test('extracts _googleUrl from "Google Maps URL"', () => {
    expect(runParser(data)[0]._googleUrl).toBe('https://maps.google.com/?cid=12345');
  });

  test('populates createdAt from Updated date', () => {
    expect(runParser(data)[0].createdAt).toBe('2024-03-15');
  });

  test('status defaults to "been"', () => {
    expect(runParser(data)[0].status).toBe('been');
  });

  test('status "bucket" when passed', () => {
    expect(runParser(data, 'bucket')[0].status).toBe('bucket');
  });

  test('visits array populated for "been" with date', () => {
    const r = runParser(data)[0];
    expect(r.visits).toHaveLength(1);
    expect(r.visits[0].date).toBe('2024-03-15');
  });

  test('visits array empty for "bucket"', () => {
    const r = runParser(data, 'bucket')[0];
    expect(r.visits).toHaveLength(0);
  });

  test('website in notes when present', () => {
    expect(runParser(data)[0].notes).toContain('toureiffel.paris');
  });
});

describe('Google Saved Places — old Takeout format', () => {
  const data = { type: 'FeatureCollection', features: [OLD_FORMAT_FEATURE] };

  test('extracts name from Title', () => {
    expect(runParser(data)[0].name).toBe('Empire State Building');
  });

  test('falls back to geometry coords when no Geo Coordinates sub-object', () => {
    const r = runParser(data)[0];
    expect(r.lat).toBeCloseTo(40.7484, 3);
    expect(r.lng).toBeCloseTo(-73.9857, 3);
  });

  test('extracts address from location.address', () => {
    expect(runParser(data)[0].address).toContain('5th Ave');
  });

  test('extracts _googleUrl from google_maps_url', () => {
    expect(runParser(data)[0]._googleUrl).toBe('https://maps.google.com/?q=place_id:ChIJabc123');
  });
});

describe('Google Saved Places — edge cases', () => {
  test('filters out features with zero/invalid coordinates', () => {
    const data = {
      type: 'FeatureCollection',
      features: [
        { type: 'Feature', geometry: { coordinates: [0, 0] }, properties: { Title: 'Null Island', 'Google Maps URL': '' } },
        NEW_FORMAT_FEATURE,
      ],
    };
    expect(runParser(data)).toHaveLength(1);
  });

  test('handles missing Location sub-object gracefully', () => {
    const data = {
      type: 'FeatureCollection',
      features: [{ type: 'Feature', geometry: { coordinates: [2.35, 48.85] }, properties: { Title: 'Paris', 'Google Maps URL': '' } }],
    };
    const r = runParser(data);
    expect(r).toHaveLength(1);
    expect(r[0].name).toBe('Paris');
  });

  test('mixed new + old features in one file', () => {
    const data = { type: 'FeatureCollection', features: [NEW_FORMAT_FEATURE, OLD_FORMAT_FEATURE] };
    const r = runParser(data);
    expect(r).toHaveLength(2);
  });
});
