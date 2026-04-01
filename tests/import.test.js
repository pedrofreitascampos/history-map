const path = require('path');
const fs = require('fs');
const vm = require('vm');

// Set test data dir before requiring anything
const testDataDir = path.join(__dirname, '..', 'data-test-import');
if (!fs.existsSync(testDataDir)) fs.mkdirSync(testDataDir);
process.env.DATA_DIR = testDataDir;
process.env.JWT_SECRET = 'test-secret';
process.env.ALLOWED_EMAILS = '';

const request = require('supertest');
const app = require('../server/index');
const db = require('../server/db');

// ─── Extract parser functions from index.html ───────────
const indexHtml = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');

function extractFunction(name) {
  // Match function declaration including nested braces
  const start = indexHtml.indexOf(`function ${name}(`);
  if (start === -1) throw new Error(`Function ${name} not found`);
  let depth = 0, i = start;
  let foundFirst = false;
  for (; i < indexHtml.length; i++) {
    if (indexHtml[i] === '{') { depth++; foundFirst = true; }
    if (indexHtml[i] === '}') depth--;
    if (foundFirst && depth === 0) break;
  }
  return indexHtml.substring(start, i + 1);
}

function extractConst(name) {
  const start = indexHtml.indexOf(`const ${name}`);
  if (start === -1) throw new Error(`Const ${name} not found`);
  // Find the semicolon that ends the declaration (handling nested objects)
  let depth = 0, i = start, foundFirst = false;
  for (; i < indexHtml.length; i++) {
    if (indexHtml[i] === '{') { depth++; foundFirst = true; }
    if (indexHtml[i] === '}') depth--;
    if (indexHtml[i] === ';' && depth === 0 && foundFirst) break;
  }
  return indexHtml.substring(start, i + 1);
}

// Build a sandbox with all parser functions
const sandbox = {};
const code = [
  extractConst('OSM_CATEGORY_MAP'),
  extractFunction('osmToCategory'),
  extractFunction('inferCategory'),
  extractFunction('extractPlaceId'),
  extractFunction('haversineKm'),
  extractFunction('parseCSVLine'),
  // parseGoogleSavedPlaces, parseGoogleTimelineOld, etc.
  extractFunction('parseGoogleSavedPlaces'),
  extractFunction('parseGoogleTimelineOld'),
  extractFunction('parseGoogleTimelineNew'),
  extractFunction('parseGoogleTimelineSegments'),
  extractFunction('parseGoogleTimelineEdits'),
  extractFunction('parseGoogleRawLocations'),
  extractFunction('parseGeoJSON'),
  extractFunction('findDuplicate'),
].join('\n');

// Provide DOMParser stub for parseKML
let JSDOM, JSDOMDomParser;
try {
  JSDOM = require('jsdom').JSDOM;
  JSDOMDomParser = new JSDOM('').window.DOMParser;
} catch (e) {
  JSDOM = null;
  JSDOMDomParser = null;
}

const contextCode = `
  ${code}
  // parseCSV without geocoding (strip DOM/network dependencies)
  function parseCSV(content) {
    const lines = content.trim().split('\\n').map(l => l.replace(/\\r$/, ''));
    if (lines.length < 2) return [];
    const firstLine = lines[0];
    const delim = firstLine.includes(';') ? ';' : ',';
    const headers = parseCSVLine(firstLine, delim).map(h => h.toLowerCase().replace(/"/g, ''));
    const isGoogleSaved = headers.includes('title') && headers.includes('url') && !headers.includes('lat') && !headers.includes('latitude');
    const results = [];
    for (const line of lines.slice(1)) {
      const vals = parseCSVLine(line, delim);
      const obj = {};
      headers.forEach((h, i) => obj[h] = vals[i] || '');
      const name = obj.title || obj.name || obj.nom || '';
      if (!name) continue;
      let lat = parseFloat(obj.lat || obj.latitude || 0);
      let lng = parseFloat(obj.lng || obj.longitude || obj.lon || 0);
      if (!lat || !lng) {
        for (const key of Object.keys(obj)) {
          if (key.includes('url') || key.includes('link')) {
            const m = (obj[key] || '').match(/@(-?\\d+\\.?\\d*),(-?\\d+\\.?\\d*)/);
            if (m) { lat = parseFloat(m[1]); lng = parseFloat(m[2]); break; }
          }
        }
      }
      const tags = (obj.tags || obj.tag || obj.liste || obj.label || '').split(',').map(t => t.trim()).filter(Boolean);
      const address = obj.address || obj.adresse || obj.city || obj.location || '';
      if (isGoogleSaved && (!lat || !lng)) {
        results.push({ name, lat: 0, lng: 0, category: inferCategory(name + ' ' + tags.join(' ')), address, status: 'been', notes: obj.note || obj.notes || obj.comment || '', tags, _needsGeocode: true });
      } else if (lat && lng) {
        results.push({ name, lat, lng, category: inferCategory(name + ' ' + tags.join(' ') + ' ' + (obj.category || '') + ' ' + address), address, status: 'been', notes: obj.note || obj.notes || obj.comment || '', tags });
      }
    }
    if (results.some(r => r._needsGeocode)) return results;
    return results.filter(l => isFinite(l.lat) && isFinite(l.lng) && (l.lat !== 0 || l.lng !== 0));
  }

  // parseJSON orchestrator (stripped of DOM deps)
  function parseJSON(content) {
    const data = JSON.parse(content);
    if (data.exportDate && Array.isArray(data.locations) && data.locations[0]?.category) {
      return data.locations.map(item => ({
        name: item.name, lat: item.lat, lng: item.lng,
        category: item.category || 'location', address: item.address || '',
        status: item.status || 'been', googleRating: item.googleRating || null,
        myRating: item.myRating || 0, people: item.people || [],
        visits: item.visits || [], notes: item.notes || '',
        needsApproval: item.needsApproval || false, suggestedCategory: item.suggestedCategory || null,
        tags: item.tags || [], priceLevel: item.priceLevel || null, createdAt: item.createdAt || '',
        _restoreTripId: item.tripId, _restoreCollections: item.collections || [], _isFullRestore: true,
      })).filter(l => isFinite(l.lat) && isFinite(l.lng) && (l.lat !== 0 || l.lng !== 0));
    }
    if (data.type === 'FeatureCollection' && data.features?.[0]?.properties?.google_maps_url) return parseGoogleSavedPlaces(data);
    if (data.timelineObjects) return parseGoogleTimelineOld(data);
    if (Array.isArray(data) && data[0]?.placeVisit) return parseGoogleTimelineOld({ timelineObjects: data });
    if (Array.isArray(data) && data[0]?.visit) return parseGoogleTimelineNew(data);
    if (Array.isArray(data) && data[0]?.startTime && data[0]?.endTime) return parseGoogleTimelineNew(data);
    if (data.semanticSegments || data.rawSignals) return parseGoogleTimelineSegments(data);
    if (data.timelineEdits) return parseGoogleTimelineEdits(data);
    if (data.locations && Array.isArray(data.locations) && data.locations[0]?.latitudeE7) return parseGoogleRawLocations(data);
    if (data.type === 'FeatureCollection' && data.features) {
      return data.features.map(f => ({
        name: f.properties?.name || 'Unknown', lat: f.geometry?.coordinates?.[1] || 0,
        lng: f.geometry?.coordinates?.[0] || 0, category: inferCategory(f.properties?.name || f.properties?.category || ''),
        address: f.properties?.address || '', status: 'been',
      })).filter(l => isFinite(l.lat) && isFinite(l.lng) && (l.lat !== 0 || l.lng !== 0));
    }
    const arr = Array.isArray(data) ? data : (data.features || data.locations || [data]);
    return arr.map(item => ({
      name: item.name || item.title || item.properties?.name || 'Unknown',
      lat: item.lat || item.latitude || item.geometry?.coordinates?.[1] || 0,
      lng: item.lng || item.longitude || item.lon || item.geometry?.coordinates?.[0] || 0,
      category: inferCategory(item.name || item.category || ''),
      address: item.address || item.properties?.address || '', status: 'been',
    })).filter(l => isFinite(l.lat) && isFinite(l.lng) && (l.lat !== 0 || l.lng !== 0));
  }
`;

// Create a DOMParser shim that bridges jsdom into the vm sandbox
let DOMParserShim;
if (JSDOM) {
  // jsdom classes can't cross vm realm boundaries directly, so wrap in a plain function
  DOMParserShim = function() {};
  DOMParserShim.prototype.parseFromString = function(str, type) {
    const dom = new JSDOM(str, { contentType: type });
    return dom.window.document;
  };
}

const ctx = vm.createContext({ console, Map, Set, Array, Object, Math, JSON, parseFloat, parseInt, isFinite, isNaN, Date, RegExp, Error, Number, String, Boolean, undefined, DOMParser: DOMParserShim });
vm.runInContext(contextCode, ctx);

// Also set up parseKML if JSDOM available
if (DOMParserShim) {
  const kmlCode = extractFunction('parseKML');
  vm.runInContext(kmlCode, ctx);
}

let token;

beforeAll(async () => {
  await db.users.remove({}, { multi: true });
  await db.locations.remove({}, { multi: true });
  await db.trips.remove({}, { multi: true });
  await db.collections.remove({}, { multi: true });
  // Register test user
  const res = await request(app).post('/api/auth/register').send({ username: 'importuser', password: 'testpass123' });
  token = res.body.token;
});

afterAll(() => {
  if (fs.existsSync(testDataDir)) {
    fs.readdirSync(testDataDir).forEach(f => fs.unlinkSync(path.join(testDataDir, f)));
    fs.rmdirSync(testDataDir);
  }
});

// ═══════════════════════════════════════════════════════════
// PARSER UNIT TESTS
// ═══════════════════════════════════════════════════════════

describe('inferCategory', () => {
  const inferCategory = (...args) => vm.runInContext(`inferCategory(${JSON.stringify(args[0])})`, ctx);

  test('detects restaurants in multiple languages', () => {
    expect(inferCategory('Trattoria da Mario')).toBe('restaurant');
    expect(inferCategory('Churrascaria Fogo')).toBe('restaurant');
    expect(inferCategory('Sushi Nakazawa')).toBe('restaurant');
    expect(inferCategory('Brasserie Lipp')).toBe('restaurant');
  });

  test('detects hotels', () => {
    expect(inferCategory('Hotel Negresco')).toBe('hotel');
    expect(inferCategory('Pousada do Gerês')).toBe('hotel');
    expect(inferCategory('Youth Hostel Barcelona')).toBe('hotel');
  });

  test('detects monuments and churches', () => {
    expect(inferCategory('Sagrada Família Cathedral')).toBe('monument');
    expect(inferCategory('Château de Versailles')).toBe('monument');
    expect(inferCategory('Colosseum')).toBe('monument');
  });

  test('detects parks and nature', () => {
    expect(inferCategory('Yosemite National Park')).toBe('park');
    expect(inferCategory('Jardim Botânico')).toBe('park');
    expect(inferCategory('Praia da Marinha')).toBe('park');
  });

  test('detects airports', () => {
    expect(inferCategory('Lisbon Airport')).toBe('airport');
    expect(inferCategory('Flughafen München')).toBe('airport');
  });

  test('detects stadiums', () => {
    expect(inferCategory('Camp Nou')).toBe('stadium');
    expect(inferCategory('Estádio da Luz')).toBe('stadium');
  });

  test('returns location for unknown', () => {
    expect(inferCategory('Random Place 123')).toBe('location');
    expect(inferCategory('')).toBe('location');
  });
});

describe('extractPlaceId', () => {
  const extractPlaceId = (url) => vm.runInContext(`extractPlaceId(${JSON.stringify(url)})`, ctx);

  test('extracts from place_id= format', () => {
    expect(extractPlaceId('https://maps.google.com/?q=place_id=ChIJN1t_tDeuEmsRUsoyG83frY4')).toBe('ChIJN1t_tDeuEmsRUsoyG83frY4');
  });

  test('extracts from place_id: format', () => {
    expect(extractPlaceId('https://maps.google.com/?q=place_id:ChIJABC123')).toBe('ChIJABC123');
  });

  test('extracts from ftid format', () => {
    expect(extractPlaceId('https://maps.google.com/maps/place/?ftid=0x89c2588f046ee661:0xa0b3c8c2b3f3b4e5')).toBe('0x89c2588f046ee661:0xa0b3c8c2b3f3b4e5');
  });

  test('returns empty for missing URL', () => {
    expect(extractPlaceId('')).toBe('');
    expect(extractPlaceId(null)).toBe('');
    expect(extractPlaceId(undefined)).toBe('');
  });

  test('returns empty for URL without place_id', () => {
    expect(extractPlaceId('https://maps.google.com/@48.8566,2.3522')).toBe('');
  });
});

describe('parseCSVLine', () => {
  const parseCSVLine = (line, delim) => vm.runInContext(`parseCSVLine(${JSON.stringify(line)}, ${JSON.stringify(delim)})`, ctx);

  test('parses simple comma-delimited', () => {
    expect(parseCSVLine('a,b,c', ',')).toEqual(['a', 'b', 'c']);
  });

  test('handles quoted fields with commas', () => {
    expect(parseCSVLine('"Hello, World",42,test', ',')).toEqual(['Hello, World', '42', 'test']);
  });

  test('handles semicolon delimiter', () => {
    expect(parseCSVLine('a;b;c', ';')).toEqual(['a', 'b', 'c']);
  });

  test('trims whitespace', () => {
    expect(parseCSVLine(' a , b , c ', ',')).toEqual(['a', 'b', 'c']);
  });
});

describe('parseCSV', () => {
  const parseCSV = (content) => vm.runInContext(`parseCSV(${JSON.stringify(content)})`, ctx);

  test('parses standard CSV with lat/lng', () => {
    const csv = 'name,lat,lng,category\nEiffel Tower,48.8584,2.2945,monument\nLouvre Museum,48.8606,2.3376,museum';
    const result = parseCSV(csv);
    expect(result).toHaveLength(2);
    expect(result[0].name).toBe('Eiffel Tower');
    expect(result[0].lat).toBeCloseTo(48.8584);
    expect(result[0].lng).toBeCloseTo(2.2945);
    expect(result[1].name).toBe('Louvre Museum');
  });

  test('parses semicolon-delimited CSV', () => {
    const csv = 'name;lat;lng\nBerliner Dom;52.5191;13.4010';
    const result = parseCSV(csv);
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('Berliner Dom');
  });

  test('extracts coords from URL (@lat,lng pattern)', () => {
    // URL with commas must be quoted in CSV to avoid delimiter confusion
    const csv = 'name,url\nSome Place,"https://maps.google.com/@48.8566,2.3522,17z"';
    const result = parseCSV(csv);
    expect(result).toHaveLength(1);
    expect(result[0].lat).toBeCloseTo(48.8566);
    expect(result[0].lng).toBeCloseTo(2.3522);
  });

  test('preserves notes and tags', () => {
    const csv = 'name,lat,lng,notes,tags\nTest Place,10,20,Great spot,"food,travel"';
    const result = parseCSV(csv);
    expect(result[0].notes).toBe('Great spot');
    expect(result[0].tags).toEqual(['food', 'travel']);
  });

  test('skips empty rows', () => {
    const csv = 'name,lat,lng\n,,\nReal Place,10,20';
    const result = parseCSV(csv);
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('Real Place');
  });

  test('handles header-only CSV', () => {
    const csv = 'name,lat,lng';
    const result = parseCSV(csv);
    expect(result).toHaveLength(0);
  });

  test('returns empty for single-line input', () => {
    const result = parseCSV('just a header');
    expect(result).toHaveLength(0);
  });

  test('detects Google Takeout CSV and marks for geocoding', () => {
    const csv = 'Title,Note,URL,Tags,Comment\nColosseum,,https://maps.google.com,history,Amazing place';
    const result = parseCSV(csv);
    // Google Takeout CSV without coords -> _needsGeocode
    expect(result).toHaveLength(1);
    expect(result[0]._needsGeocode).toBe(true);
    expect(result[0].name).toBe('Colosseum');
    expect(result[0].notes).toBe('Amazing place');
  });

  test('handles alternative column names (nom, adresse, longitude)', () => {
    const csv = 'nom,latitude,longitude,adresse\nTour Eiffel,48.8584,2.2945,Paris';
    const result = parseCSV(csv);
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('Tour Eiffel');
    expect(result[0].address).toBe('Paris');
  });

  test('infers category from name', () => {
    const csv = 'name,lat,lng\nHilton Hotel,40.7128,-74.0060';
    const result = parseCSV(csv);
    expect(result[0].category).toBe('hotel');
  });
});

describe('parseJSON — Oikumene backup', () => {
  const parseJSON = (content) => vm.runInContext(`parseJSON(${JSON.stringify(content)})`, ctx);

  test('restores full backup with all fields', () => {
    const backup = JSON.stringify({
      exportDate: '2026-03-01',
      locations: [
        { name: 'Place A', lat: 38.7, lng: -9.1, category: 'restaurant', status: 'been', myRating: 4, tags: ['food'], visits: [{ date: '2025-12-01', notes: '' }], tripId: 'trip1', collections: ['col1'] },
        { name: 'Place B', lat: 41.4, lng: 2.2, category: 'bar', status: 'bucket', notes: 'Must visit' },
      ],
      trips: [{ _id: 'trip1', name: 'Portugal 2025' }],
      collections: [{ _id: 'col1', name: 'Favorites' }],
    });
    const result = parseJSON(backup);
    expect(result).toHaveLength(2);
    expect(result[0]._isFullRestore).toBe(true);
    expect(result[0].name).toBe('Place A');
    expect(result[0].myRating).toBe(4);
    expect(result[0].tags).toEqual(['food']);
    expect(result[0]._restoreTripId).toBe('trip1');
    expect(result[0]._restoreCollections).toEqual(['col1']);
    expect(result[1].status).toBe('bucket');
    expect(result[1].notes).toBe('Must visit');
  });

  test('filters out locations with no coordinates', () => {
    const backup = JSON.stringify({
      exportDate: '2026-01-01',
      locations: [
        { name: 'Valid', lat: 10, lng: 20, category: 'location' },
        { name: 'No coords', lat: 0, lng: 0, category: 'location' },
      ],
    });
    const result = parseJSON(backup);
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('Valid');
  });
});

describe('parseJSON — Google Saved Places (GeoJSON)', () => {
  const parseJSON = (content) => vm.runInContext(`parseJSON(${JSON.stringify(content)})`, ctx);

  test('parses Google Saved Places with place IDs', () => {
    const data = JSON.stringify({
      type: 'FeatureCollection',
      features: [
        {
          type: 'Feature',
          geometry: { type: 'Point', coordinates: [2.2945, 48.8584] },
          properties: {
            Title: 'Eiffel Tower',
            google_maps_url: 'https://maps.google.com/?cid=0x12345&place_id=ChIJLU7jZClu5kcR4PcOOO6p3I0',
            Comment: 'Iconic landmark',
            location: { name: 'Eiffel Tower', address: 'Champ de Mars, Paris' },
          },
        },
        {
          type: 'Feature',
          geometry: { type: 'Point', coordinates: [-9.1393, 38.7223] },
          properties: {
            Title: 'Pastéis de Belém',
            google_maps_url: 'https://maps.google.com/?q=place_id:ChIJABC123',
            location: { address: 'Rua de Belém, Lisboa' },
          },
        },
      ],
    });
    const result = parseJSON(data);
    expect(result).toHaveLength(2);
    expect(result[0].name).toBe('Eiffel Tower');
    expect(result[0].lat).toBeCloseTo(48.8584);
    expect(result[0]._googlePlaceId).toBe('ChIJLU7jZClu5kcR4PcOOO6p3I0');
    expect(result[0]._googleUrl).toContain('maps.google.com');
    expect(result[0].notes).toBe('Iconic landmark');
    expect(result[1].name).toBe('Pastéis de Belém');
    expect(result[1]._googlePlaceId).toBe('ChIJABC123');
    expect(result[1].address).toBe('Rua de Belém, Lisboa');
  });

  test('handles missing coordinates gracefully', () => {
    const data = JSON.stringify({
      type: 'FeatureCollection',
      features: [
        { type: 'Feature', geometry: null, properties: { Title: 'Ghost', google_maps_url: 'https://maps.google.com' } },
        { type: 'Feature', geometry: { type: 'Point', coordinates: [10, 20] }, properties: { Title: 'Real', google_maps_url: 'https://maps.google.com' } },
      ],
    });
    const result = parseJSON(data);
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('Real');
  });
});

describe('parseJSON — Google Timeline Old format', () => {
  const parseJSON = (content) => vm.runInContext(`parseJSON(${JSON.stringify(content)})`, ctx);

  test('parses timelineObjects with latitudeE7', () => {
    const data = JSON.stringify({
      timelineObjects: [
        {
          placeVisit: {
            location: { name: 'Café Central', latitudeE7: 482000000, longitudeE7: 163500000, address: 'Vienna' },
            duration: { startTimestamp: '2025-06-15T10:00:00Z' },
          },
        },
        {
          placeVisit: {
            location: { name: 'Prater', latitudeE7: 482150000, longitudeE7: 164000000 },
            duration: { startTimestamp: '2025-06-15T14:00:00Z' },
          },
        },
      ],
    });
    const result = parseJSON(data);
    expect(result).toHaveLength(2);
    expect(result[0].name).toBe('Café Central');
    expect(result[0].lat).toBeCloseTo(48.2, 1);
    expect(result[0].visits).toHaveLength(1);
    expect(result[0].visits[0].date).toBe('2025-06-15');
    expect(result[0].address).toBe('Vienna');
  });

  test('deduplicates by name+coords and merges visits', () => {
    const data = JSON.stringify({
      timelineObjects: [
        { placeVisit: { location: { name: 'Home', latitudeE7: 387000000, longitudeE7: -91000000 }, duration: { startTimestamp: '2025-01-01T08:00:00Z' } } },
        { placeVisit: { location: { name: 'Home', latitudeE7: 387000000, longitudeE7: -91000000 }, duration: { startTimestamp: '2025-01-02T08:00:00Z' } } },
        { placeVisit: { location: { name: 'Home', latitudeE7: 387000000, longitudeE7: -91000000 }, duration: { startTimestamp: '2025-01-01T08:00:00Z' } } }, // same date, should not duplicate
      ],
    });
    const result = parseJSON(data);
    expect(result).toHaveLength(1);
    expect(result[0].visits).toHaveLength(2);
  });

  test('handles mid-era format (array of placeVisit)', () => {
    const data = JSON.stringify([
      { placeVisit: { location: { name: 'Place X', latitude: 40.0, longitude: -8.0 }, duration: { startTimestamp: '2025-03-01T12:00:00Z' } } },
    ]);
    const result = parseJSON(data);
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('Place X');
    expect(result[0].lat).toBeCloseTo(40.0);
  });

  test('skips entries without location', () => {
    const data = JSON.stringify({
      timelineObjects: [
        { activitySegment: { distance: 1000 } }, // not a placeVisit
        { placeVisit: { location: { name: 'Real', latitudeE7: 100000000, longitudeE7: 200000000 } } },
      ],
    });
    const result = parseJSON(data);
    expect(result).toHaveLength(1);
  });
});

describe('parseJSON — Google Timeline New format', () => {
  const parseJSON = (content) => vm.runInContext(`parseJSON(${JSON.stringify(content)})`, ctx);

  test('parses visit.topCandidate with latLng string', () => {
    const data = JSON.stringify([
      {
        visit: {
          topCandidate: {
            placeLocation: { latLng: '48.2082, 16.3738' },
            semanticType: 'TYPE_RESTAURANT',
            placeId: 'ChIJ123',
          },
        },
        startTime: '2025-07-01T19:00:00Z',
        endTime: '2025-07-01T21:00:00Z',
      },
    ]);
    const result = parseJSON(data);
    expect(result).toHaveLength(1);
    expect(result[0].lat).toBeCloseTo(48.2082);
    expect(result[0].lng).toBeCloseTo(16.3738);
    expect(result[0].name).toBe('Restaurant');
    expect(result[0].category).toBe('restaurant');
    expect(result[0].visits[0].date).toBe('2025-07-01');
    expect(result[0]._placeId).toBe('ChIJ123');
  });

  test('deduplicates by coordinates', () => {
    const data = JSON.stringify([
      { visit: { topCandidate: { placeLocation: { latLng: '48.2082, 16.3738' }, semanticType: 'TYPE_HOME' } }, startTime: '2025-01-01T08:00:00Z', endTime: '2025-01-01T09:00:00Z' },
      { visit: { topCandidate: { placeLocation: { latLng: '48.2082, 16.3738' }, semanticType: 'TYPE_HOME' } }, startTime: '2025-01-02T08:00:00Z', endTime: '2025-01-02T09:00:00Z' },
    ]);
    const result = parseJSON(data);
    expect(result).toHaveLength(1);
    expect(result[0].visits).toHaveLength(2);
  });

  test('skips entries without placeLocation', () => {
    const data = JSON.stringify([
      { visit: { topCandidate: { placeLocation: null } } },
      { visit: { topCandidate: { placeLocation: { latLng: '10, 20' } } } },
    ]);
    const result = parseJSON(data);
    expect(result).toHaveLength(1);
  });
});

describe('parseJSON — Google Timeline Segments', () => {
  const parseSegments = (data) => vm.runInContext(`parseGoogleTimelineSegments(${JSON.stringify(data)})`, ctx);

  test('parses semanticSegments with latLng string', () => {
    const data = {
      semanticSegments: [
        {
          visit: {
            topCandidate: {
              placeLocation: { latLng: '41.3874, 2.1686', name: 'La Boqueria' },
            },
          },
          startTime: '2025-09-10T10:00:00Z',
        },
      ],
    };
    const result = parseSegments(data);
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('La boqueria');
    expect(result[0].lat).toBeCloseTo(41.3874);
  });

  test('handles empty semanticSegments', () => {
    const result = parseSegments({ semanticSegments: [] });
    expect(result).toHaveLength(0);
  });

  test('skips non-visit segments', () => {
    const result = parseSegments({
      semanticSegments: [
        { activity: { type: 'WALKING' } },
        { visit: { topCandidate: { placeLocation: { latLng: '10, 20' } } } },
      ],
    });
    expect(result).toHaveLength(1);
  });
});

describe('parseJSON — Google Timeline Edits', () => {
  const parseJSON = (content) => vm.runInContext(`parseJSON(${JSON.stringify(content)})`, ctx);

  test('parses placeAggregateInfo with latE7/lngE7', () => {
    const data = JSON.stringify({
      timelineEdits: [
        {
          placeAggregates: {
            placeAggregateInfo: [
              { placePoint: { latE7: 387000000, lngE7: -91400000 }, placeId: 'ChIJPlace1', score: 85 },
              { placePoint: { latE7: 414000000, lngE7: 21700000 }, placeId: 'ChIJPlace2', score: 42 },
            ],
          },
        },
      ],
    });
    const result = parseJSON(data);
    expect(result).toHaveLength(2);
    expect(result[0].score).toBeGreaterThan(result[1].score); // sorted by score
    expect(result[0].lat).toBeCloseTo(38.7, 1);
    expect(result[0]._placeId).toBe('ChIJPlace1');
  });

  test('deduplicates by placeId', () => {
    const data = JSON.stringify({
      timelineEdits: [
        { placeAggregates: { placeAggregateInfo: [
          { placePoint: { latE7: 100000000, lngE7: 200000000 }, placeId: 'same', score: 10 },
        ]}},
        { placeAggregates: { placeAggregateInfo: [
          { placePoint: { latE7: 100000000, lngE7: 200000000 }, placeId: 'same', score: 50 },
        ]}},
      ],
    });
    const result = parseJSON(data);
    expect(result).toHaveLength(1);
    expect(result[0].score).toBe(50); // takes max
  });
});

describe('parseJSON — Google Raw Locations', () => {
  const parseJSON = (content) => vm.runInContext(`parseJSON(${JSON.stringify(content)})`, ctx);

  test('clusters raw GPS records into places', () => {
    // 5 readings at roughly the same spot -> 1 place
    const records = [];
    for (let i = 0; i < 5; i++) {
      records.push({ latitudeE7: 387230000 + i, longitudeE7: -91390000 + i, timestamp: `2025-01-0${i+1}T12:00:00Z` });
    }
    const data = JSON.stringify({ locations: records });
    const result = parseJSON(data);
    expect(result).toHaveLength(1);
    expect(result[0].visits.length).toBeGreaterThan(0);
    expect(result[0].category).toBe('location');
  });

  test('filters out cells with fewer than 3 readings', () => {
    const data = JSON.stringify({
      locations: [
        { latitudeE7: 100000000, longitudeE7: 200000000 },
        { latitudeE7: 100000000, longitudeE7: 200000000 },
        // only 2 readings at this cell
        { latitudeE7: 300000000, longitudeE7: 400000000 },
        { latitudeE7: 300000000, longitudeE7: 400000000 },
        { latitudeE7: 300000000, longitudeE7: 400000000 },
        // 3 readings -> qualifies
      ],
    });
    const result = parseJSON(data);
    expect(result).toHaveLength(1);
    expect(result[0].lat).toBeCloseTo(30.0, 0);
  });

  test('caps at 500 places', () => {
    const records = [];
    // Create 600 distinct grid cells with 3+ readings each
    for (let i = 0; i < 600; i++) {
      const lat = (i * 1000000) + 100000000; // unique grid cells
      for (let j = 0; j < 3; j++) {
        records.push({ latitudeE7: lat, longitudeE7: 200000000 });
      }
    }
    const data = JSON.stringify({ locations: records });
    const result = parseJSON(data);
    expect(result.length).toBeLessThanOrEqual(500);
  });
});

describe('parseJSON — generic GeoJSON', () => {
  const parseJSON = (content) => vm.runInContext(`parseJSON(${JSON.stringify(content)})`, ctx);

  test('parses standard GeoJSON FeatureCollection', () => {
    const data = JSON.stringify({
      type: 'FeatureCollection',
      features: [
        { type: 'Feature', geometry: { type: 'Point', coordinates: [-9.1, 38.7] }, properties: { name: 'Lisbon Spot', address: 'Lisbon' } },
        { type: 'Feature', geometry: { type: 'Point', coordinates: [2.3, 48.9] }, properties: { name: 'Paris Spot' } },
      ],
    });
    const result = parseJSON(data);
    expect(result).toHaveLength(2);
    expect(result[0].name).toBe('Lisbon Spot');
    expect(result[0].lat).toBeCloseTo(38.7);
    expect(result[0].lng).toBeCloseTo(-9.1);
    expect(result[0].address).toBe('Lisbon');
  });
});

describe('parseJSON — generic JSON', () => {
  const parseJSON = (content) => vm.runInContext(`parseJSON(${JSON.stringify(content)})`, ctx);

  test('parses array of objects with lat/lng', () => {
    const data = JSON.stringify([
      { name: 'Place 1', lat: 10, lng: 20 },
      { name: 'Place 2', lat: 30, lng: 40 },
    ]);
    const result = parseJSON(data);
    expect(result).toHaveLength(2);
  });

  test('handles latitude/longitude field names', () => {
    const data = JSON.stringify([{ name: 'Alt Fields', latitude: 10, longitude: 20 }]);
    const result = parseJSON(data);
    expect(result).toHaveLength(1);
    expect(result[0].lat).toBe(10);
  });

  test('handles single object (not array)', () => {
    const data = JSON.stringify({ name: 'Solo', lat: 15, lng: 25 });
    const result = parseJSON(data);
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('Solo');
  });
});

describe('parseGeoJSON', () => {
  const parseGeoJSON = (content) => vm.runInContext(`parseGeoJSON(${JSON.stringify(content)})`, ctx);

  test('parses FeatureCollection', () => {
    const data = JSON.stringify({
      type: 'FeatureCollection',
      features: [
        { properties: { name: 'Test', category: 'museum' }, geometry: { type: 'Point', coordinates: [10, 20] } },
      ],
    });
    const result = parseGeoJSON(data);
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('Test');
    expect(result[0].lat).toBe(20);
    expect(result[0].lng).toBe(10);
  });

  test('handles empty features array', () => {
    const data = JSON.stringify({ type: 'FeatureCollection', features: [] });
    const result = parseGeoJSON(data);
    expect(result).toHaveLength(0);
  });

  test('filters out features without coordinates', () => {
    const data = JSON.stringify({
      type: 'FeatureCollection',
      features: [
        { properties: { name: 'No Geo' }, geometry: null },
        { properties: { name: 'Has Geo' }, geometry: { type: 'Point', coordinates: [5, 10] } },
      ],
    });
    const result = parseGeoJSON(data);
    expect(result).toHaveLength(1);
  });
});

// KML tests only run if jsdom is available
const describeKML = JSDOM ? describe : describe.skip;
describeKML('parseKML', () => {
  const parseKML = (content) => vm.runInContext(`parseKML(${JSON.stringify(content)})`, ctx);

  test('parses KML with folders (Google My Maps)', () => {
    const kml = `<?xml version="1.0" encoding="UTF-8"?>
    <kml xmlns="http://www.opengis.net/kml/2.2">
      <Document>
        <Folder>
          <name>Restaurants</name>
          <Placemark>
            <name>Trattoria Mario</name>
            <description>Best pasta in town</description>
            <Point><coordinates>11.2558,43.7696,0</coordinates></Point>
          </Placemark>
        </Folder>
        <Folder>
          <name>Hotels</name>
          <Placemark>
            <name>Grand Hotel</name>
            <Point><coordinates>11.2500,43.7700,0</coordinates></Point>
          </Placemark>
        </Folder>
      </Document>
    </kml>`;
    const result = parseKML(kml);
    expect(result).toHaveLength(2);
    expect(result[0].name).toBe('Trattoria Mario');
    expect(result[0].lat).toBeCloseTo(43.7696);
    expect(result[0].lng).toBeCloseTo(11.2558);
    expect(result[0].category).toBe('restaurant');
    expect(result[0]._folderName).toBe('Restaurants');
    expect(result[1].name).toBe('Grand Hotel');
    expect(result[1].category).toBe('hotel');
  });

  test('parses KML without folders', () => {
    const kml = `<?xml version="1.0" encoding="UTF-8"?>
    <kml xmlns="http://www.opengis.net/kml/2.2">
      <Document>
        <Placemark>
          <name>Standalone Place</name>
          <Point><coordinates>-9.1393,38.7223,0</coordinates></Point>
        </Placemark>
      </Document>
    </kml>`;
    const result = parseKML(kml);
    expect(result.length).toBeGreaterThanOrEqual(1);
    expect(result.find(r => r.name === 'Standalone Place')).toBeDefined();
  });

  test('handles missing coordinates', () => {
    const kml = `<?xml version="1.0" encoding="UTF-8"?>
    <kml xmlns="http://www.opengis.net/kml/2.2">
      <Document>
        <Folder><name>Test</name>
          <Placemark><name>No Coords</name></Placemark>
          <Placemark><name>Has Coords</name><Point><coordinates>5,10,0</coordinates></Point></Placemark>
        </Folder>
      </Document>
    </kml>`;
    const result = parseKML(kml);
    const valid = result.filter(r => r.lat && r.lng);
    expect(valid).toHaveLength(1);
    expect(valid[0].name).toBe('Has Coords');
  });
});

describe('findDuplicate', () => {
  test('finds duplicate by exact name', () => {
    const locations = [{ name: 'Eiffel Tower', lat: 48.8584, lng: 2.2945 }];
    const nameIndex = new Map();
    locations.forEach(l => nameIndex.set(l.name.toLowerCase(), l));

    const result = vm.runInContext(`
      (function() {
        const state = { locations: ${JSON.stringify(locations)} };
        const nameIndex = new Map();
        state.locations.forEach(l => nameIndex.set((l.name || '').toLowerCase(), l));
        return findDuplicate({ name: 'Eiffel Tower', lat: 10, lng: 20 }, nameIndex);
      })()
    `, ctx);
    expect(result).toBeDefined();
    expect(result.name).toBe('Eiffel Tower');
  });

  test('finds duplicate by proximity (<50m)', () => {
    // Set global state in sandbox
    vm.runInContext(`var state = { locations: [{ name: 'Place A', lat: 48.8584, lng: 2.2945 }] };`, ctx);
    const result = vm.runInContext(`
      (function() {
        const nameIndex = new Map();
        state.locations.forEach(l => nameIndex.set((l.name || '').toLowerCase(), l));
        return findDuplicate({ name: 'Different Name', lat: 48.8584, lng: 2.2945 }, nameIndex);
      })()
    `, ctx);
    expect(result).toBeDefined();
  });

  test('returns null for non-duplicate', () => {
    vm.runInContext(`state = { locations: [{ name: 'Far Away', lat: 10, lng: 20 }] };`, ctx);
    const result = vm.runInContext(`
      (function() {
        const nameIndex = new Map();
        state.locations.forEach(l => nameIndex.set((l.name || '').toLowerCase(), l));
        return findDuplicate({ name: 'Totally Different', lat: 48.8584, lng: 2.2945 }, nameIndex);
      })()
    `, ctx);
    expect(result).toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════
// API INTEGRATION TESTS
// ═══════════════════════════════════════════════════════════

describe('Bulk import API', () => {
  beforeEach(async () => {
    await db.locations.remove({}, { multi: true });
  });

  test('imports valid locations', async () => {
    const res = await request(app).post('/api/locations/bulk').set('Authorization', `Bearer ${token}`)
      .send({ locations: [
        { name: 'API Place 1', lat: 38.7, lng: -9.1, category: 'restaurant' },
        { name: 'API Place 2', lat: 41.4, lng: 2.2, category: 'bar' },
        { name: 'API Place 3', lat: 48.9, lng: 2.3, category: 'museum' },
      ]});
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(3);
    res.body.forEach(loc => {
      expect(loc._id).toBeDefined();
      expect(loc.userId).toBeDefined();
      expect(loc.updatedAt).toBeDefined();
    });
  });

  test('skips locations with missing name', async () => {
    const res = await request(app).post('/api/locations/bulk').set('Authorization', `Bearer ${token}`)
      .send({ locations: [
        { name: 'Valid', lat: 10, lng: 20, category: 'location' },
        { lat: 10, lng: 20, category: 'location' }, // no name
        { name: '', lat: 10, lng: 20, category: 'location' }, // empty name
      ]});
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(1);
  });

  test('skips locations with non-numeric coordinates', async () => {
    const res = await request(app).post('/api/locations/bulk').set('Authorization', `Bearer ${token}`)
      .send({ locations: [
        { name: 'Valid', lat: 10, lng: 20 },
        { name: 'String coords', lat: 'abc', lng: 'def' },
        { name: 'NaN coords', lat: NaN, lng: NaN },
      ]});
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(1);
  });

  test('rejects empty array', async () => {
    const res = await request(app).post('/api/locations/bulk').set('Authorization', `Bearer ${token}`)
      .send({ locations: [] });
    expect(res.status).toBe(400);
  });

  test('rejects non-array', async () => {
    const res = await request(app).post('/api/locations/bulk').set('Authorization', `Bearer ${token}`)
      .send({ locations: 'not an array' });
    expect(res.status).toBe(400);
  });

  test('strips disallowed fields (security)', async () => {
    const res = await request(app).post('/api/locations/bulk').set('Authorization', `Bearer ${token}`)
      .send({ locations: [
        { name: 'Sanitized', lat: 10, lng: 20, category: 'location', _evil: 'hack', __proto__: { admin: true }, isAdmin: true },
      ]});
    expect(res.status).toBe(200);
    expect(res.body[0]._evil).toBeUndefined();
    expect(res.body[0].isAdmin).toBeUndefined();
    expect(res.body[0].name).toBe('Sanitized');
  });

  test('preserves Google Places fields', async () => {
    const res = await request(app).post('/api/locations/bulk').set('Authorization', `Bearer ${token}`)
      .send({ locations: [
        { name: 'Google Place', lat: 10, lng: 20, _googlePlaceId: 'ChIJ123', _googleUrl: 'https://maps.google.com/test', _googleSyncedAt: '2026-01-01T00:00:00Z' },
      ]});
    expect(res.status).toBe(200);
    expect(res.body[0]._googlePlaceId).toBe('ChIJ123');
    expect(res.body[0]._googleUrl).toBe('https://maps.google.com/test');
    expect(res.body[0]._googleSyncedAt).toBe('2026-01-01T00:00:00Z');
  });

  test('preserves approval workflow fields', async () => {
    const res = await request(app).post('/api/locations/bulk').set('Authorization', `Bearer ${token}`)
      .send({ locations: [
        { name: 'Pending Review', lat: 10, lng: 20, needsApproval: true, suggestedCategory: 'restaurant', category: 'location' },
      ]});
    expect(res.status).toBe(200);
    expect(res.body[0].needsApproval).toBe(true);
    expect(res.body[0].suggestedCategory).toBe('restaurant');
  });

  test('preserves visits, tags, people, and collections', async () => {
    const res = await request(app).post('/api/locations/bulk').set('Authorization', `Bearer ${token}`)
      .send({ locations: [
        {
          name: 'Full Location', lat: 10, lng: 20, category: 'restaurant',
          visits: [{ date: '2025-01-01', notes: 'Great' }],
          tags: ['food', 'travel'],
          people: ['Alice', 'Bob'],
          collections: ['col1'],
          notes: 'A note',
        },
      ]});
    expect(res.status).toBe(200);
    expect(res.body[0].visits).toEqual([{ date: '2025-01-01', notes: 'Great' }]);
    expect(res.body[0].tags).toEqual(['food', 'travel']);
    expect(res.body[0].people).toEqual(['Alice', 'Bob']);
    expect(res.body[0].notes).toBe('A note');
  });

  test('requires authentication', async () => {
    const res = await request(app).post('/api/locations/bulk')
      .send({ locations: [{ name: 'Unauth', lat: 10, lng: 20 }] });
    expect(res.status).toBe(401);
  });

  test('sets userId from token, not from payload', async () => {
    const res = await request(app).post('/api/locations/bulk').set('Authorization', `Bearer ${token}`)
      .send({ locations: [
        { name: 'User Override', lat: 10, lng: 20, userId: 'hacker-id' },
      ]});
    expect(res.status).toBe(200);
    // userId should NOT be 'hacker-id', should be undefined (stripped by allowlist)
    expect(res.body[0].userId).not.toBe('hacker-id');
  });

  test('large batch import (100 locations)', async () => {
    const locations = [];
    for (let i = 0; i < 100; i++) {
      locations.push({ name: `Batch ${i}`, lat: 10 + i * 0.01, lng: 20 + i * 0.01, category: 'location' });
    }
    const res = await request(app).post('/api/locations/bulk').set('Authorization', `Bearer ${token}`)
      .send({ locations });
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(100);
  });
});

describe('Import + query integration', () => {
  beforeEach(async () => {
    await db.locations.remove({}, { multi: true });
  });

  test('imported locations appear in GET /api/locations', async () => {
    await request(app).post('/api/locations/bulk').set('Authorization', `Bearer ${token}`)
      .send({ locations: [
        { name: 'Visible', lat: 10, lng: 20, category: 'bar' },
      ]});
    const list = await request(app).get('/api/locations').set('Authorization', `Bearer ${token}`);
    expect(list.body).toHaveLength(1);
    expect(list.body[0].name).toBe('Visible');
  });

  test('imported locations can be updated', async () => {
    const imp = await request(app).post('/api/locations/bulk').set('Authorization', `Bearer ${token}`)
      .send({ locations: [{ name: 'Updatable', lat: 10, lng: 20, category: 'location', needsApproval: true }] });
    const id = imp.body[0]._id;
    const updated = await request(app).put(`/api/locations/${id}`).set('Authorization', `Bearer ${token}`)
      .send({ category: 'restaurant', needsApproval: false });
    expect(updated.status).toBe(200);
    expect(updated.body.category).toBe('restaurant');
    expect(updated.body.needsApproval).toBe(false);
  });

  test('imported locations can be deleted', async () => {
    const imp = await request(app).post('/api/locations/bulk').set('Authorization', `Bearer ${token}`)
      .send({ locations: [{ name: 'Deletable', lat: 10, lng: 20 }] });
    const id = imp.body[0]._id;
    await request(app).delete(`/api/locations/${id}`).set('Authorization', `Bearer ${token}`);
    const list = await request(app).get('/api/locations').set('Authorization', `Bearer ${token}`);
    expect(list.body).toHaveLength(0);
  });
});
