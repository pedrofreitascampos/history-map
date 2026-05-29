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
  extractConst('TRIP_QUALITY_GROUPS'),
  extractConst('CATEGORIES'),
  extractFunction('osmToCategory'),
  extractFunction('inferCategory'),
  extractFunction('extractPlaceId'),
  extractFunction('haversineKm'),
  extractFunction('computeTripStats'),
  extractFunction('computeChronologyMilestones'),
  extractFunction('computeMarkerSize'),
  extractFunction('inferTransitMode'),
  extractConst('COUNTRY_CODES'),
  extractFunction('regionToCountryCode'),
  extractFunction('countryCodeToFlag'),
  extractFunction('markerHash'),
  extractFunction('computeReplayFrames'),
  extractFunction('pickMarkerEmoji'),
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
  extractFunction('greatCircleArc'),
  extractFunction('splitAntiMeridian'),
  extractFunction('transitGreatCircleKm'),
  extractConst('TRANSIT_MODE_META'),
  extractFunction('transitMeta'),
  extractFunction('parseFr24Csv'),
  extractFunction('parseCsvLine'),
  extractFunction('extractIata'),
  extractFunction('normalizeDate'),
  extractFunction('parseDurationMinutes'),
  extractFunction('buildIataIndex'),
  extractFunction('resolveFr24Row'),
  extractFunction('interleaveStopsAndTransits'),
  extractFunction('computeTransitStats'),
  extractFunction('formatTransitMinutes'),
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
// TRANSITS UNIT TESTS
// ═══════════════════════════════════════════════════════════

describe('greatCircleArc', () => {
  const arc = (lat1, lng1, lat2, lng2, steps) =>
    vm.runInContext(`greatCircleArc(${lat1}, ${lng1}, ${lat2}, ${lng2}${steps !== undefined ? ', ' + steps : ''})`, ctx);

  test('returns steps+1 points for normal route', () => {
    const result = arc(38.78, -9.13, 40.64, -73.78, 64);
    // steps=64 → 65 points
    expect(result).toHaveLength(65);
  });

  test('first point matches origin (LIS)', () => {
    const result = arc(38.78, -9.13, 40.64, -73.78, 64);
    expect(result[0][0]).toBeCloseTo(38.78, 2);
    expect(result[0][1]).toBeCloseTo(-9.13, 2);
  });

  test('last point matches destination (JFK)', () => {
    const result = arc(38.78, -9.13, 40.64, -73.78, 64);
    const last = result[result.length - 1];
    expect(last[0]).toBeCloseTo(40.64, 2);
    expect(last[1]).toBeCloseTo(-73.78, 2);
  });

  test('LIS→JFK midpoint is over the North Atlantic (lat > 0)', () => {
    const result = arc(38.78, -9.13, 40.64, -73.78, 64);
    const mid = result[Math.floor(result.length / 2)];
    // Great-circle arc between two northern-hemisphere points peaks northward
    expect(mid[0]).toBeGreaterThan(0);
  });

  test('same-point returns 2-point degenerate path', () => {
    const result = arc(48.85, 2.35, 48.85, 2.35, 10);
    expect(result).toHaveLength(2);
    expect(result[0]).toEqual(result[1]);
  });

  test('default steps is 64 (returns 65 points)', () => {
    const result = arc(0, 0, 10, 10);
    expect(result).toHaveLength(65);
  });
});

describe('splitAntiMeridian', () => {
  const split = (pts) =>
    vm.runInContext(`splitAntiMeridian(${JSON.stringify(pts)})`, ctx);

  test('splits across anti-meridian into 2 segments', () => {
    const result = split([[35, 175], [35, -175]]);
    expect(result).toHaveLength(2);
  });

  test('non-wrapping route stays as 1 segment', () => {
    const result = split([[38.78, -9.13], [50, 10], [48.85, 2.35]]);
    expect(result).toHaveLength(1);
    expect(result[0]).toHaveLength(3);
  });

  test('single point returns empty', () => {
    // points.length < 2 → returns []; caller must skip degenerate segments.
    expect(split([[35, 175]])).toHaveLength(0);
  });

  test('empty array returns empty', () => {
    expect(split([])).toHaveLength(0);
  });

  test('mid-Pacific crossing splits correctly', () => {
    // Simulate points that jump >180° in longitude
    const result = split([[40, 170], [40, -170], [40, -160]]);
    expect(result).toHaveLength(2);
    expect(result[0]).toHaveLength(1);
    expect(result[1]).toHaveLength(2);
  });
});

describe('transitGreatCircleKm', () => {
  const dist = (lat1, lng1, lat2, lng2) =>
    vm.runInContext(`transitGreatCircleKm(${lat1}, ${lng1}, ${lat2}, ${lng2})`, ctx);

  test('LIS→JFK is approximately 5400 km (±200 km)', () => {
    const km = dist(38.78, -9.13, 40.64, -73.78);
    expect(km).toBeGreaterThan(5200);
    expect(km).toBeLessThan(5600);
  });

  test('same point returns 0', () => {
    expect(dist(48.85, 2.35, 48.85, 2.35)).toBeCloseTo(0, 2);
  });

  test('opposite poles is approximately 20015 km', () => {
    const km = dist(90, 0, -90, 0);
    expect(km).toBeGreaterThan(19900);
    expect(km).toBeLessThan(20200);
  });

  test('symmetric: A→B equals B→A', () => {
    const ab = dist(38.78, -9.13, 40.64, -73.78);
    const ba = dist(40.64, -73.78, 38.78, -9.13);
    expect(ab).toBeCloseTo(ba, 1);
  });
});

describe('transitMeta', () => {
  const meta = (mode) => vm.runInContext(`transitMeta(${JSON.stringify(mode)})`, ctx);

  test('flight returns correct emoji/color/label', () => {
    const m = meta('flight');
    expect(m.emoji).toBe('✈');
    expect(m.color).toBe('#60a5fa');
    expect(m.label).toBe('Flight');
  });

  test('car returns correct emoji/color/label', () => {
    const m = meta('car');
    expect(m.emoji).toBe('🚗');
    expect(m.color).toBe('#4ade80');
    expect(m.label).toBe('Car');
  });

  test('train returns correct emoji/color/label', () => {
    const m = meta('train');
    expect(m.emoji).toBe('🚆');
    expect(m.color).toBe('#f472b6');
    expect(m.label).toBe('Train');
  });

  test('ferry returns correct emoji/color/label', () => {
    const m = meta('ferry');
    expect(m.emoji).toBe('⛴');
    expect(m.color).toBe('#22d3ee');
    expect(m.label).toBe('Ferry');
  });

  test('unknown mode returns fallback with neutral color', () => {
    const m = meta('bicycle');
    expect(m.emoji).toBe('•');
    expect(m.color).toBe('#888');
    expect(m.label).toBe('bicycle');
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

// ─── Trip stats aggregation ──────────────────────────────
describe('computeTripStats', () => {
  // Helper: run computeTripStats inside the vm context, then flatten the Set
  // to a Number so we don't need a cross-realm `instanceof` check in expectations.
  const compute = (trip, locs) => {
    const out = vm.runInContext(
      `(() => {
         const s = computeTripStats(${JSON.stringify(trip)}, ${JSON.stringify(locs)});
         return { ...s, peopleCount: s.allPeople.size };
       })()`,
      ctx
    );
    return out;
  };

  const trip = { id: 't1', name: 'Iberia', startDate: '2026-06-01', endDate: '2026-06-08' };
  const locs = [
    { name: 'Belém Tower',  lat: 38.6916, lng: -9.2160, category: 'monument',   myRating: 4,   googleRating: 4.6, people: ['Ana'] },
    { name: 'Pestana',      lat: 38.7100, lng: -9.1300, category: 'hotel',      myRating: 3,   googleRating: 4.1, people: ['Ana'] },
    { name: 'Cervejaria',   lat: 41.1500, lng: -8.6100, category: 'restaurant', myRating: 5,   googleRating: 4.4 },
    { name: 'Park Güell',   lat: 41.4145, lng: 2.1527,  category: 'park',       myRating: 4,   googleRating: 4.5, people: ['Bea', 'Ana'] },
    { name: 'Hotel Madrid', lat: 40.4168, lng: -3.7038, category: 'hotel',                    googleRating: 4.0 },
  ];

  test('place + people + categories counts', () => {
    const s = compute(trip, locs);
    expect(s.placeCount).toBe(5);
    expect(s.peopleCount).toBe(2); // Ana + Bea
    expect(s.catCounts).toEqual({ monument: 1, hotel: 2, restaurant: 1, park: 1 });
  });

  test('days + nights from date range', () => {
    const s = compute(trip, locs);
    expect(s.days).toBe(8);   // Jun 1..Jun 8 inclusive
    expect(s.nights).toBe(7); // days - 1
  });

  test('days + nights zero when dates absent', () => {
    const s = compute({ id: 't2', name: 'Open' }, locs);
    expect(s.days).toBe(0);
    expect(s.nights).toBe(0);
  });

  test('distance sums consecutive haversine legs', () => {
    const s = compute(trip, locs);
    // Belém → Pestana (~8 km) → Porto (~270 km) → Barcelona (~900 km) → Madrid (~500 km)
    // ≈ 1680 km total. Use a wide ballpark for tolerance.
    expect(s.km).toBeGreaterThan(1500);
    expect(s.km).toBeLessThan(2000);
  });

  test('distance is zero for a single location', () => {
    const s = compute(trip, [locs[0]]);
    expect(s.km).toBe(0);
  });

  test('distance skips legs with invalid coords', () => {
    const dirty = [
      locs[0],
      { name: 'BadCoords', lat: NaN, lng: NaN, category: 'location' },
      locs[2],
    ];
    const s = compute(trip, dirty);
    expect(s.km).toBe(0); // both legs touch the NaN row → skipped
  });

  test('hotel stays counted correctly', () => {
    const s = compute(trip, locs);
    expect(s.stays).toBe(2);
  });

  test('quality breakdown: food group (restaurant/cafe/bar/club)', () => {
    const s = compute(trip, locs);
    expect(s.quality.food.count).toBe(1);    // 1 restaurant
    expect(s.quality.food.myAvg).toBe(5);
    expect(s.quality.food.googleAvg).toBe(4.4);
  });

  test('quality breakdown: nature group', () => {
    const s = compute(trip, locs);
    expect(s.quality.nature.count).toBe(1);
    expect(s.quality.nature.myAvg).toBe(4);
    expect(s.quality.nature.googleAvg).toBe(4.5);
  });

  test('quality breakdown: attractions group', () => {
    const s = compute(trip, locs);
    expect(s.quality.attractions.count).toBe(1);   // monument
    expect(s.quality.attractions.myAvg).toBe(4);
    expect(s.quality.attractions.googleAvg).toBe(4.6);
  });

  test('quality averages ignore zero / missing ratings', () => {
    const noRatings = [
      { name: 'A', lat: 0, lng: 0, category: 'restaurant', myRating: 0,    googleRating: 0    },
      { name: 'B', lat: 0, lng: 0, category: 'restaurant', myRating: null, googleRating: null },
      { name: 'C', lat: 0, lng: 0, category: 'restaurant', myRating: 4,    googleRating: 4.2  },
    ];
    const s = compute({ id: 't' }, noRatings);
    expect(s.quality.food.count).toBe(3);
    expect(s.quality.food.myAvg).toBe(4);       // only the one with a real rating
    expect(s.quality.food.googleAvg).toBe(4.2);
  });

  test('avgRating null when no rated locations', () => {
    const s = compute({ id: 't' }, [
      { name: 'X', lat: 0, lng: 0, category: 'location' },
    ]);
    expect(s.avgRating).toBeNull();
  });
});

// ─── Chronology milestones ───────────────────────────────
describe('computeChronologyMilestones', () => {
  const computeMilestones = (locs, trips) => {
    const out = vm.runInContext(
      `(() => {
         const r = computeChronologyMilestones(${JSON.stringify(locs)}, ${JSON.stringify(trips)});
         return {
           firstVisit: Array.from(r.firstVisit.entries()),
           yearStats: Array.from(r.yearStats.entries()),
         };
       })()`,
      ctx
    );
    return out;
  };

  test('first visit per region — single region, single visit', () => {
    const locs = [{ id: 'l1', name: 'Lisbon', status: 'been', needsApproval: false, address: 'Lisbon, Portugal', visits: [{ date: '2023-06-01' }] }];
    const { firstVisit } = computeMilestones(locs, []);
    expect(firstVisit).toHaveLength(1);
    expect(firstVisit[0]).toEqual(['l1|2023-06-01', 'Portugal']);
  });

  test('first visit per region — multiple visits same region', () => {
    const locs = [{ id: 'l1', name: 'Lisbon', status: 'been', needsApproval: false, address: 'Lisbon, Portugal', visits: [{ date: '2023-06-01' }, { date: '2022-03-10' }, { date: '2024-01-15' }] }];
    const { firstVisit } = computeMilestones(locs, []);
    expect(firstVisit).toHaveLength(1);
    expect(firstVisit[0]).toEqual(['l1|2022-03-10', 'Portugal']);
  });

  test('first visit per region — two regions', () => {
    const locs = [
      { id: 'l1', name: 'Lisbon', status: 'been', needsApproval: false, address: 'Lisbon, Portugal', visits: [{ date: '2023-06-01' }] },
      { id: 'l2', name: 'Berlin', status: 'been', needsApproval: false, address: 'Berlin, Germany', visits: [{ date: '2022-05-10' }] },
    ];
    const { firstVisit } = computeMilestones(locs, []);
    expect(firstVisit).toHaveLength(2);
    const keys = firstVisit.map(([k]) => k);
    expect(keys).toContain('l1|2023-06-01');
    expect(keys).toContain('l2|2022-05-10');
  });

  test('first visit per region — needsApproval excluded', () => {
    const locs = [{ id: 'l1', name: 'Porto', status: 'been', needsApproval: true, address: 'Porto, Portugal', visits: [{ date: '2023-06-01' }] }];
    const { firstVisit } = computeMilestones(locs, []);
    expect(firstVisit).toHaveLength(0);
  });

  test('first visit per region — status bucket excluded', () => {
    const locs = [{ id: 'l1', name: 'Paris', status: 'bucket', needsApproval: false, address: 'Paris, France', visits: [{ date: '2023-06-01' }] }];
    const { firstVisit } = computeMilestones(locs, []);
    expect(firstVisit).toHaveLength(0);
  });

  test('most-visited per year — single year', () => {
    const locs = [
      { id: 'a', name: 'LocA', status: 'been', needsApproval: false, address: 'City, Country', visits: [{ date: '2024-01-01' }, { date: '2024-02-01' }, { date: '2024-03-01' }] },
      { id: 'b', name: 'LocB', status: 'been', needsApproval: false, address: 'City2, Country', visits: [{ date: '2024-04-01' }] },
    ];
    const { yearStats } = computeMilestones(locs, []);
    const entry = yearStats.find(([y]) => y === '2024');
    expect(entry).toBeTruthy();
    expect(entry[1].mostVisited).toEqual({ name: 'LocA', count: 3 });
  });

  test('most-visited per year — tie broken alphabetically', () => {
    const locs = [
      { id: 'z', name: 'Zebra', status: 'been', needsApproval: false, address: 'City, Country', visits: [{ date: '2024-01-01' }, { date: '2024-02-01' }] },
      { id: 'a', name: 'Apple', status: 'been', needsApproval: false, address: 'City2, Country', visits: [{ date: '2024-03-01' }, { date: '2024-04-01' }] },
    ];
    const { yearStats } = computeMilestones(locs, []);
    const entry = yearStats.find(([y]) => y === '2024');
    expect(entry[1].mostVisited.name).toBe('Apple');
  });

  test('longest trip per year — single year', () => {
    const trips = [
      { id: 't1', name: 'Short', startDate: '2024-06-01', endDate: '2024-06-06' },
      { id: 't2', name: 'Long', startDate: '2024-07-01', endDate: '2024-07-11' },
    ];
    const { yearStats } = computeMilestones([], trips);
    const entry = yearStats.find(([y]) => y === '2024');
    expect(entry[1].longestTrip).toEqual({ name: 'Long', nights: 10 });
  });

  test('longest trip per year — invalid dates skipped', () => {
    const trips = [
      { id: 't1', name: 'Valid', startDate: '2024-06-01', endDate: '2024-06-06' },
      { id: 't2', name: 'Bad', startDate: '2024-07-01', endDate: '' },
    ];
    const { yearStats } = computeMilestones([], trips);
    const entry = yearStats.find(([y]) => y === '2024');
    expect(entry[1].longestTrip.name).toBe('Valid');
  });

  test('longest trip per year — grouped by start year', () => {
    const trips = [
      { id: 't1', name: 'NewYear', startDate: '2023-12-30', endDate: '2024-01-05' },
    ];
    const { yearStats } = computeMilestones([], trips);
    const in2023 = yearStats.find(([y]) => y === '2023');
    const in2024 = yearStats.find(([y]) => y === '2024');
    expect(in2023).toBeTruthy();
    expect(in2023[1].longestTrip.name).toBe('NewYear');
    expect(in2024).toBeFalsy();
  });

  test('year appears in yearStats only when has data', () => {
    const { yearStats } = computeMilestones([], []);
    expect(yearStats).toHaveLength(0);
  });

  test('empty inputs', () => {
    const { firstVisit, yearStats } = computeMilestones([], []);
    expect(firstVisit).toHaveLength(0);
    expect(yearStats).toHaveLength(0);
  });
});

// ─── Marker size by mode ─────────────────────────────────
describe('computeMarkerSize', () => {
  const size = (loc, mode) => vm.runInContext(
    `computeMarkerSize(${JSON.stringify(loc)}, ${JSON.stringify(mode)})`,
    ctx
  );

  test('default mode always returns 34', () => {
    expect(size({}, 'default')).toBe(34);
    expect(size({ myRating: 5, googleRating: 5, userRatingsTotal: 10000, visits: [{date:'2024-01-01'}], bucketStrength: 5 }, 'default')).toBe(34);
  });

  test('missing/unknown mode returns 34', () => {
    expect(size({}, undefined)).toBe(34);
    expect(size({}, '')).toBe(34);
    expect(size({}, 'nonsense')).toBe(34);
  });

  test('my-rating: 0/missing → 20, 1 → 24, 5 → 50', () => {
    expect(size({}, 'my-rating')).toBe(20);
    expect(size({ myRating: 0 }, 'my-rating')).toBe(20);
    expect(size({ myRating: 1 }, 'my-rating')).toBe(24);
    expect(size({ myRating: 3 }, 'my-rating')).toBe(37);
    expect(size({ myRating: 5 }, 'my-rating')).toBe(50);
  });

  test('my-rating clamps values > 5', () => {
    expect(size({ myRating: 99 }, 'my-rating')).toBe(50);
  });

  test('bucket: 0/missing → 20, 1 → 24, 5 → 50, clamps', () => {
    expect(size({}, 'bucket')).toBe(20);
    expect(size({ bucketStrength: 0 }, 'bucket')).toBe(20);
    expect(size({ bucketStrength: 1 }, 'bucket')).toBe(24);
    expect(size({ bucketStrength: 5 }, 'bucket')).toBe(50);
    expect(size({ bucketStrength: 99 }, 'bucket')).toBe(50);
  });

  test('visits: 0 → 20, 1 → ~26, many → caps at 50', () => {
    expect(size({}, 'visits')).toBe(20);
    expect(size({ visits: [] }, 'visits')).toBe(20);
    const s1 = size({ visits: [{ date: '2024-01-01' }] }, 'visits');
    expect(s1).toBeGreaterThanOrEqual(24);
    expect(s1).toBeLessThanOrEqual(28);
    const sMany = size({ visits: new Array(100).fill({ date: '2024-01-01' }) }, 'visits');
    expect(sMany).toBe(50);
  });

  test('google-pop: no data → 20, top-tier → 50', () => {
    expect(size({}, 'google-pop')).toBe(20);
    expect(size({ googleRating: 0, userRatingsTotal: 0 }, 'google-pop')).toBe(20);
    const top = size({ googleRating: 5, userRatingsTotal: 100000 }, 'google-pop');
    expect(top).toBe(50);
    const meh = size({ googleRating: 3, userRatingsTotal: 10 }, 'google-pop');
    expect(meh).toBeGreaterThan(20);
    expect(meh).toBeLessThan(40);
  });

  test('google-pop scales with both rating and count', () => {
    // Same rating, more reviews → larger
    const fewReviews = size({ googleRating: 4.5, userRatingsTotal: 10 }, 'google-pop');
    const manyReviews = size({ googleRating: 4.5, userRatingsTotal: 10000 }, 'google-pop');
    expect(manyReviews).toBeGreaterThan(fewReviews);
    // Same count, higher rating → larger
    const lowRating = size({ googleRating: 3.0, userRatingsTotal: 1000 }, 'google-pop');
    const highRating = size({ googleRating: 4.8, userRatingsTotal: 1000 }, 'google-pop');
    expect(highRating).toBeGreaterThan(lowRating);
  });

  test('size always within [20, 50] bounds', () => {
    const modes = ['default', 'my-rating', 'google-pop', 'visits', 'bucket'];
    const samples = [
      {}, { myRating: 3 }, { googleRating: 4, userRatingsTotal: 500 },
      { visits: [{ date: '2024-01-01' }, { date: '2024-02-01' }] }, { bucketStrength: 3 },
    ];
    for (const m of modes) {
      for (const s of samples) {
        const px = size(s, m);
        expect(px).toBeGreaterThanOrEqual(20);
        expect(px).toBeLessThanOrEqual(50);
      }
    }
  });
});

describe('computeReplayFrames', () => {
  const run = (locs, filters) => vm.runInContext(
    `computeReplayFrames(${JSON.stringify(locs)}, ${JSON.stringify(filters || null)})`,
    ctx
  );

  it('returns empty for no locations', () => {
    expect(run([])).toEqual([]);
  });

  it('skips bucket locations', () => {
    const out = run([{ id: 'a', name: 'A', lat: 1, lng: 2, category: 'cafe', status: 'bucket', visits: [{ date: '2024-01-01' }] }]);
    expect(out).toEqual([]);
  });

  it('skips needs-approval locations', () => {
    const out = run([{ id: 'a', name: 'A', lat: 1, lng: 2, category: 'cafe', status: 'been', needsApproval: true, visits: [{ date: '2024-01-01' }] }]);
    expect(out).toEqual([]);
  });

  it('skips locations without valid coords', () => {
    const out = run([{ id: 'a', name: 'A', lat: null, lng: 2, category: 'cafe', status: 'been', visits: [{ date: '2024-01-01' }] }]);
    expect(out).toEqual([]);
  });

  it('skips visits without date', () => {
    const out = run([{ id: 'a', name: 'A', lat: 1, lng: 2, category: 'cafe', status: 'been', visits: [{ date: '' }, { date: '2024-01-01' }] }]);
    expect(out.length).toBe(1);
    expect(out[0].date).toBe('2024-01-01');
  });

  it('emits one frame per visit', () => {
    const out = run([{ id: 'a', name: 'A', lat: 1, lng: 2, category: 'cafe', status: 'been', visits: [{ date: '2024-01-01' }, { date: '2024-02-01' }] }]);
    expect(out.length).toBe(2);
  });

  it('sorts chronologically ascending', () => {
    const out = run([
      { id: 'a', name: 'A', lat: 1, lng: 2, category: 'cafe', status: 'been', visits: [{ date: '2024-03-01' }] },
      { id: 'b', name: 'B', lat: 3, lng: 4, category: 'cafe', status: 'been', visits: [{ date: '2024-01-01' }] },
      { id: 'c', name: 'C', lat: 5, lng: 6, category: 'cafe', status: 'been', visits: [{ date: '2024-02-01' }] },
    ]);
    expect(out.map(f => f.name)).toEqual(['B', 'C', 'A']);
  });

  it('respects year filter', () => {
    const out = run([
      { id: 'a', name: 'A', lat: 1, lng: 2, category: 'cafe', status: 'been', visits: [{ date: '2023-01-01' }, { date: '2024-01-01' }] },
    ], { year: '2024' });
    expect(out.length).toBe(1);
    expect(out[0].date).toBe('2024-01-01');
  });

  it('respects category filter', () => {
    const out = run([
      { id: 'a', name: 'A', lat: 1, lng: 2, category: 'cafe', status: 'been', visits: [{ date: '2024-01-01' }] },
      { id: 'b', name: 'B', lat: 1, lng: 2, category: 'monument', status: 'been', visits: [{ date: '2024-01-02' }] },
    ], { category: 'cafe' });
    expect(out.length).toBe(1);
    expect(out[0].name).toBe('A');
  });

  it('respects trip filter', () => {
    const out = run([
      { id: 'a', name: 'A', lat: 1, lng: 2, category: 'cafe', status: 'been', tripId: 't1', visits: [{ date: '2024-01-01' }] },
      { id: 'b', name: 'B', lat: 1, lng: 2, category: 'cafe', status: 'been', tripId: 't2', visits: [{ date: '2024-01-02' }] },
    ], { trip: 't1' });
    expect(out.length).toBe(1);
    expect(out[0].name).toBe('A');
  });

  it('falls back to _id when id is missing (legacy NeDB)', () => {
    const out = run([{ _id: 'nedb1', name: 'A', lat: 1, lng: 2, category: 'cafe', status: 'been', visits: [{ date: '2024-01-01' }] }]);
    expect(out[0].id).toBe('nedb1');
  });

  it('tags visit frames with kind:visit', () => {
    const out = run([{ id: 'a', name: 'A', lat: 1, lng: 2, category: 'cafe', status: 'been', visits: [{ date: '2024-01-01' }] }]);
    expect(out[0].kind).toBe('visit');
  });
});

describe('computeReplayFrames — transits + heuristic', () => {
  const runFull = (locs, trips, transits, filters) => vm.runInContext(
    `computeReplayFrames(${JSON.stringify(locs)}, ${JSON.stringify(trips)}, ${JSON.stringify(transits)}, ${JSON.stringify(filters || null)})`,
    ctx
  );

  it('interleaves explicit transits with visits by date', () => {
    const out = runFull(
      [
        { id: 'lis', name: 'Lisbon', lat: 38.7, lng: -9.1, category: 'cafe', status: 'been', tripId: 't1', visits: [{ date: '2024-06-01' }] },
        { id: 'jfk', name: 'NYC',    lat: 40.7, lng: -74.0, category: 'cafe', status: 'been', tripId: 't1', visits: [{ date: '2024-06-03' }] },
      ],
      [{ id: 't1', name: 'Trip 1' }],
      [{ id: 'tr1', mode: 'flight', tripId: 't1', date: '2024-06-02', fromLat: 38.7, fromLng: -9.1, toLat: 40.7, toLng: -74.0, fromName: 'LIS', toName: 'JFK' }],
    );
    expect(out.length).toBe(3);
    expect(out.map(f => f.kind)).toEqual(['visit', 'transit', 'visit']);
    expect(out[1].mode).toBe('flight');
    expect(out[1].fromName).toBe('LIS');
  });

  it('visit < transit when sharing a date (tie-break)', () => {
    const out = runFull(
      [{ id: 'a', name: 'A', lat: 1, lng: 2, category: 'cafe', status: 'been', tripId: 't1', visits: [{ date: '2024-01-01' }] }],
      [{ id: 't1' }],
      [{ id: 't', mode: 'car', tripId: 't1', date: '2024-01-01', fromLat: 1, fromLng: 2, toLat: 3, toLng: 4 }],
    );
    expect(out[0].kind).toBe('visit');
    expect(out[1].kind).toBe('transit');
  });

  it('synthesizes heuristic transits between same-trip consecutive visits', () => {
    // 38.7,-9.1 → 41.15,-8.6 is ~270km, mid-range → train
    const out = runFull(
      [
        { id: 'lis', name: 'Lisbon', lat: 38.7,  lng: -9.1, category: 'cafe', status: 'been', tripId: 't1', visits: [{ date: '2024-06-01' }] },
        { id: 'opo', name: 'Porto',  lat: 41.15, lng: -8.6, category: 'cafe', status: 'been', tripId: 't1', visits: [{ date: '2024-06-03' }] },
      ],
      [{ id: 't1' }],
      [],
    );
    const synthetic = out.find(f => f.kind === 'transit' && f.synthetic);
    expect(synthetic).toBeTruthy();
    expect(synthetic.mode).toBe('train');
    expect(synthetic.tripId).toBe('t1');
  });

  it('does not synthesize when an explicit transit already links the stops', () => {
    const out = runFull(
      [
        { id: 'lis', name: 'Lisbon', lat: 38.7, lng: -9.1, category: 'cafe', status: 'been', tripId: 't1', visits: [{ date: '2024-06-01' }] },
        { id: 'jfk', name: 'NYC',    lat: 40.7, lng: -74.0, category: 'cafe', status: 'been', tripId: 't1', visits: [{ date: '2024-06-03' }] },
      ],
      [{ id: 't1' }],
      [{ id: 'tr1', mode: 'flight', tripId: 't1', date: '2024-06-03', fromLat: 38.7, fromLng: -9.1, toLat: 40.7, toLng: -74.0 }],
    );
    const transitFrames = out.filter(f => f.kind === 'transit');
    expect(transitFrames.length).toBe(1);
    expect(transitFrames[0].synthetic).toBe(false);
  });

  it('does not synthesize across trips (only within a trip)', () => {
    const out = runFull(
      [
        { id: 'a', name: 'A', lat: 38, lng: -9,  category: 'cafe', status: 'been', tripId: 't1', visits: [{ date: '2024-01-01' }] },
        { id: 'b', name: 'B', lat: 48, lng:  2,  category: 'cafe', status: 'been', tripId: 't2', visits: [{ date: '2024-02-01' }] },
      ],
      [{ id: 't1' }, { id: 't2' }],
      [],
    );
    expect(out.filter(f => f.kind === 'transit')).toEqual([]);
  });

  it('heuristic picks car for <30km, train for <500km, flight for >=500km', () => {
    const distCases = [
      // ~5km
      { lat1: 38.70, lng1: -9.10, lat2: 38.72, lng2: -9.05, expected: 'car' },
      // ~300km
      { lat1: 38.70, lng1: -9.10, lat2: 41.30, lng2: -8.50, expected: 'train' },
      // >5000km
      { lat1: 38.70, lng1: -9.10, lat2: 40.70, lng2: -74.0, expected: 'flight' },
    ];
    distCases.forEach(c => {
      const out = runFull(
        [
          { id: 'a', name: 'A', lat: c.lat1, lng: c.lng1, category: 'cafe', status: 'been', tripId: 't1', visits: [{ date: '2024-01-01' }] },
          { id: 'b', name: 'B', lat: c.lat2, lng: c.lng2, category: 'cafe', status: 'been', tripId: 't1', visits: [{ date: '2024-01-02' }] },
        ],
        [{ id: 't1' }],
        [],
      );
      const syn = out.find(f => f.kind === 'transit' && f.synthetic);
      expect(syn?.mode).toBe(c.expected);
    });
  });

  it('back-compat: (locations, filters) signature still works', () => {
    // Older call sites passed only two args. The shim must accept this.
    const out = vm.runInContext(
      `computeReplayFrames([{id:'a',name:'A',lat:1,lng:2,category:'cafe',status:'been',visits:[{date:'2024-01-01'}]}], { year: '2024' })`,
      ctx,
    );
    expect(out.length).toBe(1);
    expect(out[0].kind).toBe('visit');
  });

  it('skips transits with invalid coords', () => {
    const out = runFull(
      [],
      [],
      [{ id: 't', mode: 'flight', date: '2024-01-01', fromLat: null, fromLng: -9, toLat: 40, toLng: -74 }],
    );
    expect(out).toEqual([]);
  });

  it('skips transits without a date', () => {
    const out = runFull(
      [],
      [],
      [{ id: 't', mode: 'flight', fromLat: 1, fromLng: 2, toLat: 3, toLng: 4 }],
    );
    expect(out).toEqual([]);
  });
});

describe('pickMarkerEmoji', () => {
  const run = (loc, opts) => vm.runInContext(
    `pickMarkerEmoji(${JSON.stringify(loc)}, ${JSON.stringify(opts || null)})`,
    ctx
  );

  it('returns category emoji when no opts', () => {
    expect(run({ category: 'cafe' })).toBe('☕');
  });

  it('returns category emoji when opts is empty object', () => {
    expect(run({ category: 'cafe' }, {})).toBe('☕');
  });

  it('returns category emoji when emojiOverride is empty string', () => {
    expect(run({ category: 'cafe' }, { emojiOverride: '' })).toBe('☕');
  });

  it('returns override when emojiOverride is a non-empty string', () => {
    expect(run({ category: 'cafe' }, { emojiOverride: '🏆' })).toBe('🏆');
  });

  it('returns override even when category emoji exists', () => {
    expect(run({ category: 'restaurant' }, { emojiOverride: '🦄' })).toBe('🦄');
  });

  it('falls back to location category emoji for unknown category', () => {
    expect(run({ category: 'nonsense_xyz' })).toBe('📍');
  });

  it('ignores non-string emojiOverride values', () => {
    expect(run({ category: 'cafe' }, { emojiOverride: 42 })).toBe('☕');
    expect(run({ category: 'cafe' }, { emojiOverride: null })).toBe('☕');
  });
});

// ─── M-T1: osmToCategory ─────────────────────────────────
describe('osmToCategory', () => {
  const run = (osmClass, osmType) => vm.runInContext(`osmToCategory(${JSON.stringify(osmClass)}, ${JSON.stringify(osmType)})`, ctx);

  test('amenity:restaurant → restaurant', () => expect(run('amenity', 'restaurant')).toBe('restaurant'));
  test('amenity:cafe → cafe', () => expect(run('amenity', 'cafe')).toBe('cafe'));
  test('amenity:bar → bar', () => expect(run('amenity', 'bar')).toBe('bar'));
  test('amenity:place_of_worship → monument', () => expect(run('amenity', 'place_of_worship')).toBe('monument'));
  test('tourism:museum → museum', () => expect(run('tourism', 'museum')).toBe('museum'));
  test('leisure:park → park', () => expect(run('leisure', 'park')).toBe('park'));
  test('natural:beach → park', () => expect(run('natural', 'beach')).toBe('park'));
  test('natural:peak → park', () => expect(run('natural', 'peak')).toBe('park'));
  test('aeroway:aerodrome → airport', () => expect(run('aeroway', 'aerodrome')).toBe('airport'));
  test('unknown class+type → null (location fallback)', () => expect(run('foo', 'bar')).toBeNull());
});

// ─── M-T2: haversineKm ───────────────────────────────────
describe('haversineKm', () => {
  const run = (lat1, lng1, lat2, lng2) => vm.runInContext(`haversineKm(${lat1}, ${lng1}, ${lat2}, ${lng2})`, ctx);

  test('same point returns 0', () => expect(run(48.8566, 2.3522, 48.8566, 2.3522)).toBe(0));
  test('London to Paris ~344 km', () => {
    const d = run(51.5074, -0.1278, 48.8566, 2.3522);
    expect(d).toBeGreaterThan(334);
    expect(d).toBeLessThan(354);
  });
  test('antipodal points ~20000 km', () => {
    const d = run(0, 0, 0, 180);
    expect(d).toBeGreaterThan(19900);
    expect(d).toBeLessThan(20100);
  });
  test('NaN args return NaN', () => expect(run(NaN, 0, 0, 0)).toBeNaN());
  test('undefined args return NaN', () => expect(run(undefined, 0, 0, 0)).toBeNaN());
});

// ═══════════════════════════════════════════════════════════
// FR24 CSV IMPORT UNIT TESTS
// ═══════════════════════════════════════════════════════════

describe('parseFr24Csv', () => {
  test('parses standard FR24 export with header', () => {
    const csv = `Date,Flight number,From,To,Dep time,Arr time,Duration,Aircraft,Registration,Seat,Note
2024-07-10,TP201,"Lisbon (LIS)","New York (JFK)",13:30,16:45,07:15,A330-900,CS-TUB,12A,Test`;
    const rows = vm.runInContext(`parseFr24Csv(${JSON.stringify(csv)})`, ctx);
    expect(rows).toHaveLength(1);
    expect(rows[0].flightNumber).toBe('TP201');
    expect(rows[0].from).toBe('Lisbon (LIS)');
    expect(rows[0].to).toBe('New York (JFK)');
    expect(rows[0].duration).toBe('07:15');
    expect(rows[0].seat).toBe('12A');
    expect(rows[0].note).toBe('Test');
  });

  test('handles CSV without header row', () => {
    const csv = `2024-07-10,TP201,LIS,JFK,13:30,16:45,07:15,A330,,,`;
    const rows = vm.runInContext(`parseFr24Csv(${JSON.stringify(csv)})`, ctx);
    expect(rows).toHaveLength(1);
    expect(rows[0].flightNumber).toBe('TP201');
  });

  test('handles quoted fields containing commas', () => {
    const csv = `Date,Flight number,From,To,Dep time,Arr time,Duration,Aircraft,Registration,Seat,Note
2024-07-10,TP201,"Lisbon, PT (LIS)","JFK",13:30,16:45,07:15,A330,,,"Note, with comma"`;
    const rows = vm.runInContext(`parseFr24Csv(${JSON.stringify(csv)})`, ctx);
    expect(rows[0].from).toBe('Lisbon, PT (LIS)');
    expect(rows[0].note).toBe('Note, with comma');
  });

  test('skips blank lines', () => {
    const csv = `Date,Flight number,From,To,Dep time,Arr time,Duration,Aircraft,Registration,Seat,Note

2024-07-10,TP201,LIS,JFK,13:30,16:45,07:15,A330,,,

`;
    const rows = vm.runInContext(`parseFr24Csv(${JSON.stringify(csv)})`, ctx);
    expect(rows).toHaveLength(1);
  });

  // Regression (2026-05-30): real FR24 export now has an Airline column at
  // index 7, shifting Aircraft → 8, Registration → 9, Seat → 10, Note → 14.
  // Parser must auto-detect the airline column and align downstream fields,
  // otherwise the "Aircraft" field receives "Norwegian Air International (D8/IBK)".
  // Plus: leading blank line, HH:MM:SS duration, (IATA/ICAO) paired form.
  test('handles real FR24 export (Airline column + HH:MM:SS + IATA/ICAO + leading blank)', () => {
    const csv = `\nDate,"Flight number",From,To,"Dep time","Arr time",Duration,Airline,Aircraft,Registration,"Seat number","Seat type","Flight class","Flight reason",Note,Dep_id,Arr_id,Airline_id,Aircraft_id\n2018-12-02,D83302,"Copenhagen / Kastrup (CPH/EKCH)","Berlin / Schonefeld (SXF/EDDB)",15:25:00,16:25:00,01:00:00,"Norwegian Air International (D8/IBK)","Boeing 737-800 (B738)",,,0,0,0,,606,2828,1644,231`;
    const rows = vm.runInContext(`parseFr24Csv(${JSON.stringify(csv)})`, ctx);
    expect(rows).toHaveLength(1);
    const r = rows[0];
    expect(r.date).toBe('2018-12-02');
    expect(r.flightNumber).toBe('D83302');
    expect(r.from).toBe('Copenhagen / Kastrup (CPH/EKCH)');
    expect(r.to).toBe('Berlin / Schonefeld (SXF/EDDB)');
    expect(r.duration).toBe('01:00:00');
    expect(r.aircraft).toBe('Boeing 737-800 (B738)');  // NOT "Norwegian Air International..."
    expect(r.airline).toBe('Norwegian Air International (D8/IBK)');
  });
});

describe('extractIata', () => {
  const ex = (s) => vm.runInContext(`extractIata(${JSON.stringify(s)})`, ctx);
  test('extracts from parens', () => { expect(ex('Lisbon (LIS)')).toBe('LIS'); });
  test('extracts from bare 3-letter', () => { expect(ex('JFK')).toBe('JFK'); });
  test('extracts from bare 3-letter lowercase', () => { expect(ex('jfk')).toBe('JFK'); });
  test('returns null for unmatchable', () => { expect(ex('Some Place')).toBe(null); });
  test('returns null for empty', () => { expect(ex('')).toBe(null); });

  // Regression (2026-05-30): real FR24 export uses "Name (IATA/ICAO)" paired
  // form, e.g. "Copenhagen / Kastrup (CPH/EKCH)". The old regex required just
  // "(XXX)" so every row failed → 0 flights imported.
  test('extracts IATA from (IATA/ICAO) paired form (real FR24 export)', () => {
    expect(ex('Copenhagen / Kastrup (CPH/EKCH)')).toBe('CPH');
    expect(ex('Berlin / Schonefeld (SXF/EDDB)')).toBe('SXF');
    expect(ex('Amsterdam / Schiphol (AMS/EHAM)')).toBe('AMS');
    expect(ex('Boston / Logan (BOS/KBOS)')).toBe('BOS');
  });

  test('paired form is robust to trailing whitespace', () => {
    expect(ex('Lisbon (LIS/LPPT)   ')).toBe('LIS');
  });
});

describe('normalizeDate', () => {
  const nd = (s) => vm.runInContext(`normalizeDate(${JSON.stringify(s)})`, ctx);
  test('passes through YYYY-MM-DD', () => { expect(nd('2024-07-10')).toBe('2024-07-10'); });
  test('converts DD/MM/YYYY (day > 12)', () => { expect(nd('15/07/2024')).toBe('2024-07-15'); });
  test('assumes MM/DD/YYYY when ambiguous', () => { expect(nd('07/10/2024')).toBe('2024-07-10'); });
  test('handles DD-MM-YYYY', () => { expect(nd('15-07-2024')).toBe('2024-07-15'); });
  test('returns empty for empty', () => { expect(nd('')).toBe(''); });
});

describe('parseDurationMinutes', () => {
  const pd = (s) => vm.runInContext(`parseDurationMinutes(${JSON.stringify(s)})`, ctx);
  test('07:15 → 435', () => { expect(pd('07:15')).toBe(435); });
  test('00:45 → 45', () => { expect(pd('00:45')).toBe(45); });
  test('12:00 → 720', () => { expect(pd('12:00')).toBe(720); });
  test('returns null for garbage', () => { expect(pd('garbage')).toBe(null); });
  test('returns null for empty', () => { expect(pd('')).toBe(null); });

  // Regression (2026-05-30): real FR24 export uses HH:MM:SS not HH:MM.
  test('accepts HH:MM:SS (real FR24 export form)', () => {
    expect(pd('01:00:00')).toBe(60);
    expect(pd('07:15:30')).toBe(435); // seconds truncated
    expect(pd('00:45:00')).toBe(45);
  });
});

describe('buildIataIndex', () => {
  const build = (obj) => vm.runInContext(`buildIataIndex(${JSON.stringify(obj)})`, ctx);
  test('keys by iata', () => {
    const idx = build({
      LPPT: { iata: 'LIS', name: 'Humberto Delgado', lat: 38.7, lon: -9.1 },
      KJFK: { iata: 'JFK', name: 'John F. Kennedy', lat: 40.6, lon: -73.7 },
    });
    expect(idx.LIS.lat).toBe(38.7);
    expect(idx.JFK.lat).toBe(40.6);
  });
  test('skips entries with no iata', () => {
    const idx = build({
      LPPT: { iata: 'LIS', name: 'X', lat: 0, lon: 0 },
      ZZZZ: { iata: '', name: 'Empty', lat: 0, lon: 0 },
      YYYY: { name: 'No IATA', lat: 0, lon: 0 },
    });
    expect(idx.LIS).toBeDefined();
    expect(Object.keys(idx)).toHaveLength(1);
  });
});

describe('resolveFr24Row', () => {
  const idx = { LIS: { iata: 'LIS', name: 'Humberto Delgado', lat: 38.78, lon: -9.13 },
                JFK: { iata: 'JFK', name: 'John F. Kennedy', lat: 40.64, lon: -73.78 } };
  const resolve = (row) => vm.runInContext(`resolveFr24Row(${JSON.stringify(row)}, ${JSON.stringify(idx)})`, ctx);

  test('resolves a known route', () => {
    const r = resolve({ date: '2024-07-10', flightNumber: 'TP201', from: 'Lisbon (LIS)', to: 'JFK', duration: '07:15', aircraft: 'A330', seat: '12A', note: '', registration: 'CS-TUB' });
    expect(r.ok).toBe(true);
    expect(r.transit.mode).toBe('flight');
    expect(r.transit.fromIata).toBe('LIS');
    expect(r.transit.toIata).toBe('JFK');
    expect(r.transit.distanceKm).toBeGreaterThan(5000);
    expect(r.transit.distanceKm).toBeLessThan(5600);
    expect(r.transit.durationMin).toBe(435);
    expect(r.transit.notes).toMatch(/CS-TUB/);
  });

  test('rejects unknown origin', () => {
    const r = resolve({ from: 'Atlantis (ATL)', to: 'JFK' });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/ATL/);
  });

  test('rejects unparseable origin string', () => {
    const r = resolve({ from: 'Some Place', to: 'JFK' });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/origin/i);
  });

  // End-to-end regression (2026-05-30): real FR24 export rows must resolve
  // even though airports use "(IATA/ICAO)" paired form.
  test('resolves a real FR24 paired-form row', () => {
    const idx2 = {
      CPH: { iata: 'CPH', name: 'Copenhagen', lat: 55.6180, lon: 12.6508 },
      SXF: { iata: 'SXF', name: 'Berlin Schonefeld', lat: 52.3800, lon: 13.5225 },
    };
    const row = { date: '2018-12-02', flightNumber: 'D83302',
      from: 'Copenhagen / Kastrup (CPH/EKCH)',
      to: 'Berlin / Schonefeld (SXF/EDDB)',
      duration: '01:00:00', aircraft: 'Boeing 737-800 (B738)', seat: '', note: '', registration: '' };
    const r = vm.runInContext(`resolveFr24Row(${JSON.stringify(row)}, ${JSON.stringify(idx2)})`, ctx);
    expect(r.ok).toBe(true);
    expect(r.transit.fromIata).toBe('CPH');
    expect(r.transit.toIata).toBe('SXF');
    expect(r.transit.durationMin).toBe(60);
    expect(r.transit.aircraft).toBe('Boeing 737-800 (B738)');
  });
});

// ═══════════════════════════════════════════════════════════
// TRIP ↔ TRANSIT INTEGRATION TESTS
// ═══════════════════════════════════════════════════════════

describe('interleaveStopsAndTransits', () => {
  const interleave = (locs, transits) =>
    vm.runInContext(`interleaveStopsAndTransits(${JSON.stringify(locs)}, ${JSON.stringify(transits)})`, ctx);

  // helper: build a loc with a single visit date
  const loc = (name, date) => ({ id: name, name, visits: date ? [{ date }] : [], category: 'location', lat: 0, lng: 0 });
  const transit = (id, date) => ({ id, mode: 'flight', date, fromLat: 0, fromLng: 0, toLat: 1, toLng: 1 });

  test('empty inputs return empty array', () => {
    expect(interleave([], [])).toEqual([]);
  });

  test('stops only, no transits', () => {
    const out = interleave([loc('A', '2024-01-01'), loc('B', '2024-01-05')], []);
    expect(out).toHaveLength(2);
    expect(out.every(e => e.type === 'stop')).toBe(true);
  });

  test('single stop, no transits', () => {
    const out = interleave([loc('A', '2024-01-01')], []);
    expect(out).toHaveLength(1);
    expect(out[0].type).toBe('stop');
  });

  test('transit between two stops is placed in gap', () => {
    const stops = [loc('A', '2024-01-01'), loc('B', '2024-01-10')];
    const transits = [transit('T1', '2024-01-05')];
    const out = interleave(stops, transits);
    // A, T1, B
    expect(out).toHaveLength(3);
    expect(out[0].type).toBe('stop');
    expect(out[1].type).toBe('transit');
    expect(out[1].gap).toBe(0);
    expect(out[2].type).toBe('stop');
  });

  test('transit with date before first stop is loose', () => {
    const stops = [loc('A', '2024-06-01'), loc('B', '2024-06-10')];
    const transits = [transit('T1', '2024-01-01')]; // way before trip
    const out = interleave(stops, transits);
    const t = out.find(e => e.type === 'transit');
    expect(t).toBeDefined();
    expect(t.loose).toBe(true);
  });

  test('transit with date after last stop is loose', () => {
    const stops = [loc('A', '2024-06-01'), loc('B', '2024-06-10')];
    const transits = [transit('T1', '2024-12-31')];
    const out = interleave(stops, transits);
    const t = out.find(e => e.type === 'transit');
    expect(t).toBeDefined();
    expect(t.loose).toBe(true);
  });

  test('undated transit is loose', () => {
    const stops = [loc('A', '2024-01-01'), loc('B', '2024-01-10')];
    const transits = [{ id: 'T1', mode: 'car', date: null, fromLat: 0, fromLng: 0, toLat: 1, toLng: 1 }];
    const out = interleave(stops, transits);
    const t = out.find(e => e.type === 'transit');
    expect(t.loose).toBe(true);
  });

  test('multiple transits in same gap are all placed', () => {
    const stops = [loc('A', '2024-01-01'), loc('B', '2024-01-15')];
    const transits = [transit('T1', '2024-01-05'), transit('T2', '2024-01-10')];
    const out = interleave(stops, transits);
    const transitEntries = out.filter(e => e.type === 'transit');
    expect(transitEntries).toHaveLength(2);
    expect(transitEntries.every(e => e.gap === 0)).toBe(true);
  });

  test('transits with no stops are all loose', () => {
    const transits = [transit('T1', '2024-01-05'), transit('T2', '2024-01-10')];
    const out = interleave([], transits);
    expect(out).toHaveLength(2);
    expect(out.every(e => e.loose === true)).toBe(true);
  });
});

describe('computeTransitStats', () => {
  const compute = (transits) =>
    vm.runInContext(`computeTransitStats(${JSON.stringify(transits)})`, ctx);

  test('empty input returns zero totals', () => {
    const s = compute([]);
    expect(s.totalCount).toBe(0);
    expect(s.totalKm).toBe(0);
    expect(s.totalMin).toBe(0);
  });

  test('single flight is counted in flight bucket', () => {
    const s = compute([{ mode: 'flight', distanceKm: 5418, durationMin: 435 }]);
    expect(s.byMode.flight.count).toBe(1);
    expect(s.byMode.flight.km).toBe(5418);
    expect(s.byMode.flight.min).toBe(435);
    expect(s.totalKm).toBe(5418);
    expect(s.totalMin).toBe(435);
  });

  test('unknown mode is skipped', () => {
    const s = compute([{ mode: 'teleport', distanceKm: 100, durationMin: 1 }]);
    expect(s.totalCount).toBe(1); // totalCount counts all transits
    expect(s.totalKm).toBe(0);   // but km is only summed for known modes
  });

  test('mixed modes sum correctly', () => {
    const s = compute([
      { mode: 'flight', distanceKm: 1000, durationMin: 120 },
      { mode: 'car',   distanceKm: 500,  durationMin: 360 },
      { mode: 'train', distanceKm: 300,  durationMin: 180 },
    ]);
    expect(s.byMode.flight.count).toBe(1);
    expect(s.byMode.car.count).toBe(1);
    expect(s.byMode.train.count).toBe(1);
    expect(s.totalKm).toBe(1800);
    expect(s.totalMin).toBe(660);
  });

  test('route count aggregation: same route twice counts 2', () => {
    const s = compute([
      { mode: 'flight', fromIata: 'LIS', toIata: 'JFK', distanceKm: 5418 },
      { mode: 'flight', fromIata: 'LIS', toIata: 'JFK', distanceKm: 5418 },
    ]);
    const topRoute = s.byMode.flight.topRoutes[0];
    expect(topRoute.route).toBe('LIS → JFK');
    expect(topRoute.count).toBe(2);
  });

  test('topRoutes is capped at 5', () => {
    const transits = ['A→B','A→C','A→D','A→E','A→F','A→G'].map(r => {
      const [from, to] = r.split('→');
      return { mode: 'flight', fromName: from, toName: to, distanceKm: 100 };
    });
    const s = compute(transits);
    expect(s.byMode.flight.topRoutes.length).toBeLessThanOrEqual(5);
  });

  test('totalKm and totalMin match sums', () => {
    const s = compute([
      { mode: 'flight', distanceKm: 1000, durationMin: 100 },
      { mode: 'car',   distanceKm: 200,  durationMin: 200 },
    ]);
    expect(s.totalKm).toBe(1200);
    expect(s.totalMin).toBe(300);
  });

  test('missing distanceKm / durationMin treated as 0', () => {
    const s = compute([{ mode: 'flight' }]);
    expect(s.byMode.flight.km).toBe(0);
    expect(s.byMode.flight.min).toBe(0);
    expect(s.totalKm).toBe(0);
  });
});

describe('formatTransitMinutes', () => {
  const fmt = (min) => vm.runInContext(`formatTransitMinutes(${JSON.stringify(min)})`, ctx);

  test('0 returns —', () => expect(fmt(0)).toBe('—'));
  test('null returns —', () => expect(fmt(null)).toBe('—'));
  test('undefined returns —', () => expect(fmt(undefined)).toBe('—'));
  test('60 returns 1h', () => expect(fmt(60)).toBe('1h'));
  test('75 returns 1h 15m', () => expect(fmt(75)).toBe('1h 15m'));
  test('600 returns 10h', () => expect(fmt(600)).toBe('10h'));
  test('90 returns 1h 30m', () => expect(fmt(90)).toBe('1h 30m'));
});

// Regression: the entire app is one inline <script>. A single syntax error
// (e.g. `await` inside a non-async function) aborts the whole script, so NO
// functions get defined and the login button silently no-ops. This compiles
// the inline script to catch that class of error before it ships.
// See: enrichInBackground's onResult was missing `async` (broke Sign In).
describe('index.html inline script', () => {
  test('parses without syntax errors', () => {
    const scripts = [...indexHtml.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
    expect(scripts.length).toBeGreaterThan(0);
    for (const src of scripts) {
      // new vm.Script compiles (parses) without executing — throws SyntaxError if invalid.
      expect(() => new vm.Script(src)).not.toThrow();
    }
  });
});

// Regression (P0, 2026-05-29): there used to be TWO `deleteTrip` declarations — a
// correct callback-style one and a broken `async` one that `await`ed showConfirm.
// The later shadowed the former, so every trip-delete button ran the broken one
// (silent no-op + it never persisted the location unlink). Guard the dedup.
describe('deleteTrip single declaration (regression)', () => {
  test('exactly one deleteTrip function declaration (no shadowing duplicate)', () => {
    const matches = indexHtml.match(/function deleteTrip\s*\(/g) || [];
    expect(matches.length).toBe(1);
  });
});

// Stats: Countries-visited flag section (2026-05-30)
describe('regionToCountryCode / countryCodeToFlag', () => {
  const r2c = (s) => vm.runInContext(`regionToCountryCode(${JSON.stringify(s)})`, ctx);
  const c2f = (s) => vm.runInContext(`countryCodeToFlag(${JSON.stringify(s)})`, ctx);
  const codes = vm.runInContext('JSON.stringify(COUNTRY_CODES)', ctx);
  const COUNTRY_CODES = JSON.parse(codes);

  test('canonical names map to expected ISO-2', () => {
    expect(r2c('Portugal')).toBe('PT');
    expect(r2c('Germany')).toBe('DE');
    expect(r2c('Japan')).toBe('JP');
    expect(r2c('United States')).toBe('US');
  });

  test('aliases resolve to the same code', () => {
    expect(r2c('USA')).toBe('US');
    expect(r2c('UK')).toBe('GB');
    expect(r2c('England')).toBe('GB');
    expect(r2c('Holland')).toBe('NL');
    expect(r2c('Czechia')).toBe('CZ');
  });

  test('case-insensitive + trims whitespace', () => {
    expect(r2c('  portugal  ')).toBe('PT');
    expect(r2c('PORTUGAL')).toBe('PT');
    expect(r2c('PoRtUgAl')).toBe('PT');
  });

  test('compound "City, Country" picks the country', () => {
    expect(r2c('Lisbon, Portugal')).toBe('PT');
    expect(r2c('Berlin, Germany')).toBe('DE');
  });

  test('unknown / empty / non-string returns null (graceful fallback)', () => {
    expect(r2c('Atlantis')).toBeNull();
    expect(r2c('')).toBeNull();
    expect(r2c(null)).toBeNull();
    expect(r2c(undefined)).toBeNull();
    expect(r2c(42)).toBeNull();
  });

  test('countryCodeToFlag produces the regional-indicator flag emoji', () => {
    expect(c2f('PT')).toBe('🇵🇹');
    expect(c2f('US')).toBe('🇺🇸');
    expect(c2f('JP')).toBe('🇯🇵');
    expect(c2f('pt')).toBe('🇵🇹'); // case-insensitive
  });

  test('countryCodeToFlag rejects bad input', () => {
    expect(c2f('')).toBe('');
    expect(c2f(null)).toBe('');
    expect(c2f('XYZ')).toBe(''); // wrong length
    expect(c2f('X1')).toBe('🏳'); // non-letter → white flag fallback
  });

  test('COUNTRY_CODES covers ≥ 100 entries (sanity)', () => {
    expect(Object.keys(COUNTRY_CODES).length).toBeGreaterThanOrEqual(100);
  });

  test('every COUNTRY_CODES value is a 2-letter A-Z code', () => {
    const bad = Object.entries(COUNTRY_CODES).filter(([, v]) => !/^[A-Z]{2}$/.test(v));
    expect(bad).toEqual([]);
  });

  test('all keys are lowercased (so .toLowerCase() lookups always hit)', () => {
    const wrong = Object.keys(COUNTRY_CODES).filter(k => k !== k.toLowerCase());
    expect(wrong).toEqual([]);
  });
});

// Marker layer-diff perf (2026-05-30)
describe('markerHash + incremental renderMarkers', () => {
  const hash = (loc) => vm.runInContext(`markerHash(${JSON.stringify(loc)})`, ctx);

  test('identical loc produces identical hash', () => {
    const loc = { lat: 38.71, lng: -9.14, status: 'been', category: 'restaurant', myRating: 4 };
    expect(hash(loc)).toBe(hash(loc));
  });

  test('status flip invalidates hash (been ↔ bucket)', () => {
    const a = { lat: 1, lng: 2, status: 'been', category: 'cafe' };
    const b = { ...a, status: 'bucket' };
    expect(hash(a)).not.toBe(hash(b));
  });

  test('category change invalidates hash', () => {
    const a = { lat: 1, lng: 2, status: 'been', category: 'restaurant' };
    const b = { ...a, category: 'hotel' };
    expect(hash(a)).not.toBe(hash(b));
  });

  test('lat/lng move invalidates hash', () => {
    const a = { lat: 1, lng: 2, status: 'been', category: 'park' };
    const b = { ...a, lat: 1.0001 };
    expect(hash(a)).not.toBe(hash(b));
  });

  test('myRating / googleRating / visits affect hash (icon-size inputs)', () => {
    const base = { lat: 0, lng: 0, status: 'been', category: 'restaurant' };
    expect(hash(base)).not.toBe(hash({ ...base, myRating: 4 }));
    expect(hash(base)).not.toBe(hash({ ...base, googleRating: 4.5 }));
    expect(hash(base)).not.toBe(hash({ ...base, visits: [{}, {}] }));
  });

  test('needsApproval flips hash', () => {
    const a = { lat: 0, lng: 0, status: 'been', category: 'restaurant' };
    expect(hash(a)).not.toBe(hash({ ...a, needsApproval: true }));
  });

  test('unrelated edits do NOT change hash (description, address, notes)', () => {
    const a = { lat: 0, lng: 0, status: 'been', category: 'restaurant', myRating: 4 };
    const b = { ...a, description: 'updated', address: 'new addr', notes: 'edit' };
    expect(hash(a)).toBe(hash(b));
  });
});

// Source-grep invariants for the incremental marker diff
describe('renderMarkers incremental diff (source invariants)', () => {
  test('_renderState registry exists with markerById Map', () => {
    expect(indexHtml).toMatch(/_renderState\s*=\s*\{[\s\S]{0,200}markerById:\s*new Map\(\)/);
  });

  test('diff path uses markersLayer.removeLayers / addLayers (not clearLayers)', () => {
    // renderMarkers contains both: a diff branch and a teardown branch with clearLayers
    const fn = indexHtml.match(/function renderMarkers\(\)[\s\S]*?\n\}/);
    expect(fn).not.toBeNull();
    expect(fn[0]).toMatch(/markersLayer\.removeLayers\(/);
    expect(fn[0]).toMatch(/markersLayer\.addLayers\(/);
    expect(fn[0]).toMatch(/markersLayer\.clearLayers\(\)/); // teardown branch still uses it
  });

  test('diff is skipped when mapStyle changes (heat ↔ cluster forces teardown)', () => {
    expect(indexHtml).toMatch(/styleChanged\s*=\s*state\.mapStyle\s*!==\s*_renderState\.mapStyle/);
  });

  test('diff is skipped when markerSizeMode changes (all markers must resize)', () => {
    expect(indexHtml).toMatch(/sizeChanged\s*=\s*state\.markerSizeMode\s*!==\s*_renderState\.markerSizeMode/);
  });

  test('registry is cleared in teardown branch (no stale entries when switching to heat)', () => {
    const fn = indexHtml.match(/function renderMarkers\(\)[\s\S]*?\n\}/)[0];
    // Both clearLayers() and registry.clear() must appear in the teardown path
    expect(fn).toMatch(/markersLayer\.clearLayers\(\);\s*\n\s*_renderState\.markerById\.clear\(\)/);
  });
});

// Source-grep invariants for the stats render path
describe('Countries-visited stats section (source invariants)', () => {
  test('stats-view has the #countries-flags container right after #category-stats', () => {
    expect(indexHtml).toMatch(/id="category-stats"[\s\S]{0,500}id="countries-flags"/);
  });

  test('renderStats writes into #countries-flags and #countries-count', () => {
    expect(indexHtml).toMatch(/getElementById\(['"]countries-flags['"]\)/);
    expect(indexHtml).toMatch(/getElementById\(['"]countries-count['"]\)/);
  });

  test('viewCountryOnMap exists and switches to map-view', () => {
    expect(indexHtml).toMatch(/function viewCountryOnMap\([\s\S]{0,400}switchView\(['"]map-view['"]\)/);
  });

  test('flag cards include onclick + aria-label (a11y)', () => {
    expect(indexHtml).toMatch(/flag-card[\s\S]{0,300}onclick="viewCountryOnMap/);
    expect(indexHtml).toMatch(/flag-emoji[^>]*aria-label/);
  });
});

// Regression (P0, 2026-05-29): showConfirm must return a Promise<boolean>. It was
// callback-only, so `await showConfirm(...)` in deleteFromPopup/deleteTrip resolved
// to undefined → those deletes silently no-opped and clicking "Delete" threw
// `onConfirm is not a function`. These tests pin the dual-mode contract.
const describeDom = JSDOM ? describe : describe.skip;
describeDom('showConfirm contract (regression)', () => {
  const src = extractFunction('showConfirm');

  function mount(onConfirm) {
    const dom = new JSDOM('<!DOCTYPE html><body></body>');
    const ctx = { document: dom.window.document, esc: s => String(s) };
    vm.createContext(ctx);
    vm.runInContext(src + '\nthis.showConfirm = showConfirm;', ctx);
    const promise = ctx.showConfirm('Delete this?', onConfirm);
    return { dom, promise };
  }

  test('returns a thenable (Promise), not undefined', () => {
    const { promise } = mount();
    expect(promise).toBeDefined();
    expect(typeof promise.then).toBe('function');
  });

  test('resolves true when the danger button is clicked', async () => {
    const { dom, promise } = mount();
    dom.window.document.querySelector('.confirm-danger').click();
    await expect(promise).resolves.toBe(true);
  });

  test('resolves false when the cancel button is clicked', async () => {
    const { dom, promise } = mount();
    dom.window.document.querySelector('.confirm-cancel').click();
    await expect(promise).resolves.toBe(false);
  });

  test('still fires the optional onConfirm callback (back-compat)', async () => {
    let called = false;
    const { dom, promise } = mount(() => { called = true; });
    dom.window.document.querySelector('.confirm-danger').click();
    await promise;
    expect(called).toBe(true);
  });
});
