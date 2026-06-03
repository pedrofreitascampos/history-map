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
  extractFunction('_gmTimelineDisplayName'),
  extractFunction('parseGoogleTimelineNew'),
  extractFunction('parseGoogleTimelineSegments'),
  extractFunction('parseGoogleTimelineEdits'),
  extractFunction('parseGoogleRawLocations'),
  extractFunction('parseGeoJSON'),
  extractFunction('findDuplicate'),
  extractFunction('greatCircleArc'),
  extractFunction('splitAntiMeridian'),
  extractFunction('transitGreatCircleKm'),
  extractConst('DECOMMISSIONED_AIRPORTS'),
  extractConst('TRANSIT_MODE_META'),
  extractConst('TRANSIT_DISTANCE_BUCKETS'),
  extractConst('DISTANCE_BUCKET_COLORS'),
  extractFunction('distanceBucket'),
  extractFunction('transitDistanceColor'),
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
  extractFunction('getGoogleMapsUrl'),
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

  test('parses semanticSegments with latLng string, preserves real place-name casing', () => {
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
    expect(result[0].name).toBe('La Boqueria');  // real name — NOT title-cased / lower-cased
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

describe('Google Timeline parsers — phone-export fidelity (2026-05-30 fix)', () => {
  const parseNew = (content) => vm.runInContext(`parseJSON(${JSON.stringify(content)})`, ctx);
  const parseSegments = (data) => vm.runInContext(`parseGoogleTimelineSegments(${JSON.stringify(data)})`, ctx);

  test('parseGoogleTimelineNew reads placeLocation.name (not just semanticType)', () => {
    // Before the fix, name was forced to the semanticType enum ("Restaurant")
    // regardless of whether placeLocation.name was present. This locked the
    // user out of real names from phone exports.
    const data = JSON.stringify([
      {
        visit: {
          topCandidate: {
            placeLocation: {
              latLng: '38.7100, -9.1400',
              name: 'Pastéis de Belém',
              address: 'R. de Belém 84-92, Lisboa',
            },
            semanticType: 'TYPE_RESTAURANT',
            placeId: 'ChIJBelem',
          },
        },
        startTime: '2025-08-12T15:00:00Z',
      },
    ]);
    const result = parseNew(data);
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('Pastéis de Belém');
    expect(result[0].address).toBe('R. de Belém 84-92, Lisboa');
    expect(result[0]._placeId).toBe('ChIJBelem');
    expect(result[0].category).toBe('restaurant');
  });

  test('parseGoogleTimelineNew still falls back to semanticType when name is absent', () => {
    const data = JSON.stringify([
      {
        visit: {
          topCandidate: {
            placeLocation: { latLng: '48.2082, 16.3738' },
            semanticType: 'TYPE_HOME',
          },
        },
        startTime: '2025-01-01T08:00:00Z',
      },
    ]);
    const result = parseNew(data);
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('Home');  // title-cased TYPE_ enum
  });

  test('parseGoogleTimelineSegments preserves real-name casing, captures placeId + address', () => {
    const data = {
      semanticSegments: [
        {
          visit: {
            topCandidate: {
              placeLocation: {
                latLng: '38.7077, -9.1366',
                name: 'Praça do Comércio',
                address: 'Praça do Comércio, 1100-148 Lisboa',
              },
              placeId: 'ChIJPraca',
              semanticType: 'TYPE_TOURIST_ATTRACTION',
            },
          },
          startTime: '2025-08-13T11:00:00Z',
        },
      ],
    };
    const result = parseSegments(data);
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('Praça do Comércio');  // diacritics + multi-word casing preserved
    expect(result[0].address).toBe('Praça do Comércio, 1100-148 Lisboa');
    expect(result[0]._placeId).toBe('ChIJPraca');
  });

  test('parseGoogleTimelineSegments still title-cases semanticType fallback', () => {
    const data = {
      semanticSegments: [
        {
          visit: {
            topCandidate: {
              placeLocation: { latLng: '52.5200, 13.4050' },
              semanticType: 'TYPE_RESTAURANT',
            },
          },
          startTime: '2025-07-01T19:00:00Z',
        },
      ],
    };
    const result = parseSegments(data);
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('Restaurant');  // enum → title-cased
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
    // Empty / missing iata are skipped (only the LIS row is from the input).
    // The decommissioned-airports patch is merged in afterwards, so the total
    // count is LIS + the patch entries (not 1).
    expect(idx['']).toBeUndefined();
  });

  // Regression (2026-05-30): historical FR24 logbooks contain SXF (Berlin
  // Schönefeld) which OpenFlights dropped after its 2020 closure. Without the
  // decommissioned patch, every pre-2020 Berlin flight failed to resolve.
  test('decommissioned-airports patch fills SXF / TXL / THF when missing from live data', () => {
    const idx = build({}); // No live data — patch must cover the gap
    expect(idx.SXF).toBeDefined();
    expect(idx.SXF.lat).toBeCloseTo(52.38, 1);
    expect(idx.SXF.lon).toBeCloseTo(13.52, 1);
    expect(idx.TXL).toBeDefined();
    expect(idx.THF).toBeDefined();
  });

  test('live data wins over the decommissioned patch (no override)', () => {
    const liveSxf = { iata: 'SXF', name: 'Live SXF', lat: 99.9, lon: 99.9 };
    const idx = build({ XXXX: liveSxf });
    expect(idx.SXF.name).toBe('Live SXF');
    expect(idx.SXF.lat).toBe(99.9);
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

  // 2026-05-30: airline must propagate to the transit (server allowlist
  // already permits it but resolveFr24Row was dropping it on the floor).
  test('propagates airline from the parsed row to transit.airline', () => {
    const idx2 = {
      LIS: { iata: 'LIS', name: 'Lisbon', lat: 38.78, lon: -9.13 },
      JFK: { iata: 'JFK', name: 'JFK',    lat: 40.64, lon: -73.78 },
    };
    const row = { from: 'Lisbon (LIS)', to: 'JFK',
      airline: 'TAP Air Portugal (TP/TAP)',
      aircraft: 'A330', duration: '07:15:00' };
    const r = vm.runInContext(`resolveFr24Row(${JSON.stringify(row)}, ${JSON.stringify(idx2)})`, ctx);
    expect(r.ok).toBe(true);
    expect(r.transit.airline).toBe('TAP Air Portugal (TP/TAP)');
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

  // 2026-05-30: airline / aircraft / airport leaderboards
  test('topAirlines aggregates by airline string', () => {
    const s = compute([
      { mode: 'flight', airline: 'TAP Air Portugal', distanceKm: 100 },
      { mode: 'flight', airline: 'TAP Air Portugal', distanceKm: 100 },
      { mode: 'flight', airline: 'Ryanair', distanceKm: 100 },
    ]);
    expect(s.topAirlines[0]).toEqual({ airline: 'TAP Air Portugal', count: 2 });
    expect(s.topAirlines[1]).toEqual({ airline: 'Ryanair', count: 1 });
  });

  test('topAircraft aggregates by aircraft string', () => {
    const s = compute([
      { mode: 'flight', aircraft: 'A320', distanceKm: 100 },
      { mode: 'flight', aircraft: 'A320', distanceKm: 100 },
      { mode: 'flight', aircraft: 'B737', distanceKm: 100 },
    ]);
    expect(s.topAircraft[0]).toEqual({ aircraft: 'A320', count: 2 });
  });

  test('topAirports counts each endpoint (from + to) separately', () => {
    const s = compute([
      { mode: 'flight', fromIata: 'LIS', toIata: 'JFK', fromName: 'Lisbon', toName: 'JFK', distanceKm: 100 },
      { mode: 'flight', fromIata: 'JFK', toIata: 'LAX', fromName: 'JFK',    toName: 'LAX', distanceKm: 100 },
    ]);
    const jfk = s.topAirports.find(a => a.key === 'JFK');
    expect(jfk.count).toBe(2);
    const lis = s.topAirports.find(a => a.key === 'LIS');
    expect(lis.count).toBe(1);
  });

  test('top-N leaderboards skip empty strings / missing fields', () => {
    const s = compute([
      { mode: 'flight', airline: '', aircraft: undefined, distanceKm: 100 },
      { mode: 'flight', distanceKm: 100 },
    ]);
    expect(s.topAirlines).toEqual([]);
    expect(s.topAircraft).toEqual([]);
  });

  test('leaderboards capped at 8', () => {
    const transits = [];
    for (let i = 0; i < 20; i++) transits.push({ mode: 'flight', airline: 'Airline ' + i, distanceKm: 100 });
    const s = compute(transits);
    expect(s.topAirlines.length).toBe(8);
  });
});

// 2026-05-30: per-mode distance buckets drive line color on the transit map
// and replay v2. Single green/amber/red scale across all modes; thresholds
// differ so a "long" flight (≥6000km) and a "long" car drive (≥1000km) read
// equally hot.
describe('distanceBucket + transitDistanceColor', () => {
  const bucket = (mode, km) => vm.runInContext(`distanceBucket(${JSON.stringify(mode)}, ${km})`, ctx);
  const color  = (mode, km) => vm.runInContext(`transitDistanceColor(${JSON.stringify(mode)}, ${km})`, ctx);

  test('flight thresholds: <1500 short, <6000 medium, ≥6000 long', () => {
    expect(bucket('flight', 500)).toBe('short');
    expect(bucket('flight', 1499)).toBe('short');
    expect(bucket('flight', 1500)).toBe('medium');
    expect(bucket('flight', 5999)).toBe('medium');
    expect(bucket('flight', 6000)).toBe('long');
    expect(bucket('flight', 11000)).toBe('long');
  });

  test('car thresholds: <200 short, <1000 medium, ≥1000 long', () => {
    expect(bucket('car', 50)).toBe('short');
    expect(bucket('car', 200)).toBe('medium');
    expect(bucket('car', 999)).toBe('medium');
    expect(bucket('car', 1000)).toBe('long');
  });

  test('train thresholds: <300 / <1500 / ≥1500', () => {
    expect(bucket('train', 100)).toBe('short');
    expect(bucket('train', 500)).toBe('medium');
    expect(bucket('train', 2000)).toBe('long');
  });

  test('ferry thresholds: <50 / <300 / ≥300', () => {
    expect(bucket('ferry', 20)).toBe('short');
    expect(bucket('ferry', 100)).toBe('medium');
    expect(bucket('ferry', 400)).toBe('long');
  });

  test('returns null for unknown mode or invalid distance', () => {
    expect(bucket('teleport', 100)).toBeNull();
    expect(bucket('flight', null)).toBeNull();
    expect(bucket('flight', NaN)).toBeNull();
    expect(bucket('flight', -1)).toBeNull();
  });

  test('color short=green, medium=amber, long=red across all modes', () => {
    expect(color('flight', 500)).toBe('#22c55e');
    expect(color('flight', 3000)).toBe('#f59e0b');
    expect(color('flight', 8000)).toBe('#ef4444');
    expect(color('car', 50)).toBe('#22c55e');
    expect(color('car', 500)).toBe('#f59e0b');
    expect(color('car', 1500)).toBe('#ef4444');
  });

  test('color falls back to mode base color when distance is unknown/invalid', () => {
    // Mode color for flight is #60a5fa (blue) — see TRANSIT_MODE_META
    expect(color('flight', null)).toBe('#60a5fa');
    expect(color('flight', undefined)).toBe('#60a5fa');
    expect(color('teleport', 100)).toBe('#888'); // unknown mode → fallback
  });

  test('TRANSIT_MODE_META carries a dash property per mode', () => {
    const meta = JSON.parse(vm.runInContext('JSON.stringify(TRANSIT_MODE_META)', ctx));
    expect(meta.flight.dash).toBeNull();
    expect(meta.car.dash).toBe('10,5');
    expect(meta.train.dash).toBe('6,4');
    expect(meta.ferry.dash).toBe('2,6');
  });
});

describe('renderTransitsMap + buildReplayTransitLine use distance color (source invariants)', () => {
  test('renderTransitsMap passes transitDistanceColor as the line color', () => {
    const fn = indexHtml.match(/function renderTransitsMap\([\s\S]*?\n\}/)[0];
    expect(fn).toMatch(/transitDistanceColor\(t\.mode,\s*t\.distanceKm\)/);
    // dashArray drives off m.dash now (not the inline ternary)
    expect(fn).toMatch(/dashArray:\s*m\.dash/);
  });

  test('buildReplayTransitLine uses transitDistanceColor + m.dash', () => {
    const fn = indexHtml.match(/function buildReplayTransitLine\([\s\S]*?\n\}/)[0];
    expect(fn).toMatch(/transitDistanceColor\(frame\.mode/);
    expect(fn).toMatch(/dashArray:\s*m\.dash/);
  });

  test('transit page has the color legend chip block', () => {
    expect(indexHtml).toMatch(/id="transit-legend"[\s\S]{0,400}short[\s\S]{0,200}medium[\s\S]{0,200}long/);
  });
});

// 2026-05-30: click a transit (polyline on the map OR card in the list) opens
// the linked trip in the Trips view.
describe('Transit → Trip navigation', () => {
  test('openTripById exists and switches to trips-view + selectTrip', () => {
    const fn = indexHtml.match(/function openTripById\([\s\S]*?\n\}/)[0];
    expect(fn).toMatch(/switchView\(['"]trips-view['"]\)/);
    expect(fn).toMatch(/selectTrip\(tripId\)/);
    // Fail gracefully when no tripId or trip was deleted
    expect(fn).toMatch(/showToast\([\s\S]{0,60}linked to a trip/);
    expect(fn).toMatch(/showToast\([\s\S]{0,60}Linked trip was deleted/);
  });

  test('renderTransitsMap attaches click → openTripById when transit.tripId exists', () => {
    const fn = indexHtml.match(/function renderTransitsMap\([\s\S]*?\n\}/)[0];
    expect(fn).toMatch(/linkedTrip\s*=\s*t\.tripId/);
    expect(fn).toMatch(/line\.on\(['"]click['"],\s*\(\)\s*=>\s*openTripById\(t\.tripId\)/);
    // Tooltip mentions "click to open" when linked
    expect(fn).toMatch(/click to open/);
  });

  test('renderTransitsList card has data-click=openTripById when linked', () => {
    const fn = indexHtml.match(/function renderTransitsList\([\s\S]*?\n\}/)[0];
    expect(fn).toMatch(/data-click="openTripById"\s+data-arg0="\$\{esc\(t\.tripId\)\}"/);
    // edit/delete buttons must stop propagation so they don't trigger the card click
    // — post-onclick-refactor (2026-05-30) this is the data-stop="1" flag the
    // dispatcher reads BEFORE running the action.
    expect(fn).toMatch(/data-stop="1"/);
    // Trip chip is rendered when linked
    expect(fn).toMatch(/transit-trip-chip/);
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
    // Inline <script> may carry attributes (CSP nonce since 2026-05-30) —
    // match opening tags with optional attrs but exclude `<script src="…">`
    // which references external CDN content.
    const scripts = [...indexHtml.matchAll(/<script(?![^>]*\bsrc=)([^>]*)>([\s\S]*?)<\/script>/g)].map(m => m[2]);
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

  test('flag cards include onclick + alt (a11y)', () => {
    expect(indexHtml).toMatch(/flag-card[\s\S]{0,300}data-click="viewCountryOnMap/);
    // Flag images come from flagcdn.com (regional-indicator emoji render as
    // text on Windows). Alt text carries the country name for screen readers.
    expect(indexHtml).toMatch(/flag-img[^>]*alt="\$\{esc\(c\.name\)\} flag"/);
    expect(indexHtml).toMatch(/flagcdn\.com\/w80/);
  });
});

describe('Sidebar+modal restructure (2026-05-31)', () => {
  test('modal NO longer carries the redundant 🔍 Search Place field', () => {
    expect(indexHtml).not.toMatch(/id="loc-search"/);
    expect(indexHtml).not.toMatch(/id="loc-search-results"/);
  });

  test('sidebar has BOTH quick-add-input AND map-search-input at the top', () => {
    expect(indexHtml).toMatch(/id="quick-add-input"[^>]*placeholder="Add place"/);
    expect(indexHtml).toMatch(/id="map-search-input"[^>]*placeholder="Search place"/);
    // Quick-add comes BEFORE search-place in source (top of the sidebar).
    const quickIdx = indexHtml.indexOf('id="quick-add-input"');
    const searchIdx = indexHtml.indexOf('id="map-search-input"');
    expect(quickIdx).toBeGreaterThan(-1);
    expect(searchIdx).toBeGreaterThan(quickIdx);
  });

  test('legacy bottom "+ Add New Location" button is gone', () => {
    expect(indexHtml).not.toMatch(/sidebar-add-btn/);
    expect(indexHtml).not.toMatch(/\+ Add New Location/);
  });

  test('quickAddPlace function exists and pre-fills loc-name from the input', () => {
    expect(indexHtml).toMatch(/function quickAddPlace\(\)[\s\S]{0,400}openAddModal\(\)/);
    expect(indexHtml).toMatch(/function quickAddPlace[\s\S]{0,400}getElementById\(['"]loc-name['"]\)/);
  });
});

describe('Popup interactive rating + marker rating label (2026-05-31)', () => {
  test('popup renders 5 interactive star buttons wired to setPopupRating', () => {
    // The stars are generated by [1..5].map(n => ...) so the source contains
    // the template literal form with ${n}, not literal 1-5. Assert the loop
    // shape + the dispatcher wiring.
    expect(indexHtml).toMatch(/\[1,2,3,4,5\]\.map\(n =>/);
    expect(indexHtml).toMatch(/popup-star[\s\S]{0,200}data-click="setPopupRating"[\s\S]{0,80}data-arg1="\$\{n\}"/);
  });

  test('setPopupRating does optimistic UI + PUT + rollback on failure', () => {
    expect(indexHtml).toMatch(/async function setPopupRating\(locId, val\)/);
    expect(indexHtml).toMatch(/setPopupRating[\s\S]{0,1500}api\(['"]PUT['"][\s\S]{0,80}\/locations\//);
    // Rollback on PUT failure restores the previous rating.
    expect(indexHtml).toMatch(/setPopupRating[\s\S]{0,2000}loc\.myRating = prev/);
  });

  test('marker icon renders a tiny .marker-rating label when rating exists', () => {
    expect(indexHtml).toMatch(/class="marker-rating"/);
    // Rating source is status-conditional (see marker-style.test.js for the
    // full table): bucket → bucketStrength else googleRating; been → myRating
    // else googleRating.
    expect(indexHtml).toMatch(/loc\.status === 'bucket'[\s\S]{0,200}loc\.bucketStrength \|\| loc\.googleRating/);
    expect(indexHtml).toMatch(/loc\.myRating \|\| loc\.googleRating/);
    // CSS rule defines the position and look of the label.
    expect(indexHtml).toMatch(/\.marker-rating\s*\{[\s\S]{0,300}position:\s*absolute/);
  });
});

describe('Edit modal declutter — Light + cut Lat/Lng + cut Visits list (2026-05-31)', () => {
  test('Organize and Memory section dividers are present, in that order', () => {
    const orgIdx = indexHtml.indexOf('<span>Organize</span>');
    const memIdx = indexHtml.indexOf('<span>Memory</span>');
    expect(orgIdx).toBeGreaterThan(-1);
    expect(memIdx).toBeGreaterThan(orgIdx);
    // .modal-divider CSS rule exists.
    expect(indexHtml).toMatch(/\.modal-divider\s*\{[\s\S]{0,300}display:\s*flex/);
  });

  test('Lat/Lng row is in the DOM but hidden (save handler still reads them)', () => {
    expect(indexHtml).toMatch(/id="loc-lat"/);
    expect(indexHtml).toMatch(/id="loc-lng"/);
    // The form-row wrapping them carries display:none style. 2026-06-03
    // mobile-UX batch added id="loc-coords-row" so saveLocation can unhide
    // the row when coords are missing — markup updated accordingly.
    expect(indexHtml).toMatch(/<div class="form-row" id="loc-coords-row" style="display:none;">[\s\S]{0,500}id="loc-lat"/);
  });

  test('Visits collapsible: summary + expandable list with per-visit remove + custom date', () => {
    // Legacy per-visit elements gone.
    expect(indexHtml).not.toMatch(/id="loc-visits"\b/);
    expect(indexHtml).not.toMatch(/class="visits-list"/);
    expect(indexHtml).not.toMatch(/data-click="addVisitField"/);
    expect(indexHtml).not.toMatch(/\+ Add Visit\b/);
    // Summary is now a button (toggles expand) with chevron + text spans.
    expect(indexHtml).toMatch(/id="loc-visits-summary"[\s\S]{0,400}data-click="toggleVisitsExpanded"/);
    expect(indexHtml).toMatch(/id="loc-visits-chevron"/);
    expect(indexHtml).toMatch(/id="loc-visits-summary-text"/);
    // Expanded list container + new action buttons.
    expect(indexHtml).toMatch(/id="loc-visits-list"/);
    expect(indexHtml).toMatch(/data-click="addTodayVisit"[\s\S]{0,40}\+ Today/);
    expect(indexHtml).toMatch(/id="loc-visit-custom-date"/);
    expect(indexHtml).toMatch(/data-click="addCustomVisit"[\s\S]{0,40}\+ Add date/);
    // Handlers exist and touch state.modalVisits.
    expect(indexHtml).toMatch(/function renderVisitFields\(\)[\s\S]{0,1200}loc-visits-summary-text/);
    expect(indexHtml).toMatch(/function renderVisitFields\(\)[\s\S]{0,1800}loc-visits-list/);
    expect(indexHtml).toMatch(/function toggleVisitsExpanded\(\)[\s\S]{0,400}rotate\(90deg\)/);
    expect(indexHtml).toMatch(/function addTodayVisit\(\)[\s\S]{0,400}state\.modalVisits/);
    expect(indexHtml).toMatch(/function addCustomVisit\(\)[\s\S]{0,500}state\.modalVisits/);
    expect(indexHtml).toMatch(/function removeVisit\(idx\)[\s\S]{0,300}splice/);
  });

  test('Status and Price share a single form-row (Status taking 60%)', () => {
    expect(indexHtml).toMatch(/Status[\s\S]{0,500}status-toggle[\s\S]{0,1000}id="price-group"/);
    expect(indexHtml).toMatch(/style="flex:1 1 60%;"[\s\S]{0,400}Status/);
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

// ─── getGoogleMapsUrl scheme validation (M-3) ───────────
describe('getGoogleMapsUrl rejects non-http(s) _googleUrl', () => {
  const ctx = vm.createContext({});
  vm.runInContext(contextCode, ctx);

  function call(loc) {
    return vm.runInContext(`getGoogleMapsUrl(${JSON.stringify(loc)})`, ctx);
  }

  test('honors http(s) _googleUrl as-is', () => {
    expect(call({ _googleUrl: 'https://maps.google.com/?cid=123' }))
      .toBe('https://maps.google.com/?cid=123');
    expect(call({ _googleUrl: 'http://example.com/maps' }))
      .toBe('http://example.com/maps');
  });

  test('javascript: URI falls through to placeId branch', () => {
    const url = call({ _googleUrl: 'javascript:alert(1)', _googlePlaceId: 'abc123' });
    expect(url).toMatch(/^https:\/\/www\.google\.com\/maps\/place\/.*place_id:abc123$/);
  });

  test('javascript: URI falls through to lat/lng branch when no placeId', () => {
    const url = call({ _googleUrl: 'JaVaScRiPt:alert(1)', lat: 38.7, lng: -9.1 });
    expect(url).toMatch(/^https:\/\/www\.google\.com\/maps\/search\/.*38\.7.*-9\.1/);
  });

  test('data: URI also rejected', () => {
    expect(call({ _googleUrl: 'data:text/html,<script>alert(1)</script>' }))
      .toBe('');
  });

  test('vbscript: URI rejected', () => {
    expect(call({ _googleUrl: 'vbscript:msgbox(1)' })).toBe('');
  });

  test('empty / null / non-string _googleUrl falls through cleanly', () => {
    expect(call({ _googleUrl: '', _googlePlaceId: 'p' }))
      .toBe('https://www.google.com/maps/place/?q=place_id:p');
    expect(call({ _googleUrl: null, lat: 1, lng: 2 }))
      .toMatch(/maps\/search/);
  });

  test('protocol-relative URL (//evil.com) rejected — no scheme', () => {
    expect(call({ _googleUrl: '//evil.com/x' })).toBe('');
  });
});

// ─── sanitizeLocationUpdate _googleUrl scheme guard (M-3 server) ──
describe('sanitizeLocationUpdate strips non-http(s) _googleUrl', () => {
  const serverSrc = fs.readFileSync(path.join(__dirname, '..', 'server', 'index.js'), 'utf-8');

  test('sanitizer function contains the _googleUrl scheme check', () => {
    const fnStart = serverSrc.indexOf('function sanitizeLocationUpdate');
    expect(fnStart).toBeGreaterThan(-1);
    // The check must look at updates._googleUrl and require http(s)
    const fnBody = serverSrc.substring(fnStart, fnStart + 2000);
    expect(fnBody).toMatch(/updates\._googleUrl/);
    expect(fnBody).toMatch(/https\?:\\\/\\\//);
  });

  test('_googleUrl is in the LOCATION_FIELDS allowlist (so it reaches the sanitizer)', () => {
    expect(serverSrc).toMatch(/LOCATION_FIELDS\s*=\s*\[[\s\S]*?_googleUrl[\s\S]*?\]/);
  });
});

// ─── Server body-limit scoping (M-5) ─────────────────────
describe('express.json body limit is 1mb global + 10mb on bulk routes', () => {
  const serverSrc = fs.readFileSync(path.join(__dirname, '..', 'server', 'index.js'), 'utf-8');

  test('global express.json is 1mb (not 10mb)', () => {
    // The unscoped app.use(express.json(...)) call must be 1mb
    expect(serverSrc).toMatch(/app\.use\(express\.json\(\{\s*limit:\s*['"]1mb['"]\s*\}\)\)/);
  });

  test('bulk-import paths mounted with 10mb limit before the global', () => {
    const tenMb = serverSrc.indexOf("express.json({ limit: '10mb' })");
    const oneMb = serverSrc.indexOf("express.json({ limit: '1mb' })");
    expect(tenMb).toBeGreaterThan(-1);
    expect(oneMb).toBeGreaterThan(-1);
    expect(tenMb).toBeLessThan(oneMb); // path-mounted runs FIRST
    // and the path-mounted block names the bulk endpoints
    const tenMbWindow = serverSrc.substring(tenMb - 200, tenMb + 100);
    expect(tenMbWindow).toMatch(/\/api\/locations\/bulk/);
    expect(tenMbWindow).toMatch(/\/api\/transits\/bulk/);
  });
});

// ─── FR24 'not an export' guard ──────────────────────────
describe('renderFr24Preview surfaces a clear error when zero rows resolve', () => {
  test('source contains the dedicated zero-resolved branch', () => {
    const renderFn = extractFunction('renderFr24Preview');
    // The "not an FR24 export" message must mention this specifically
    expect(renderFn).toMatch(/Flightradar24 export/);
    // Must be gated on okCount === 0 AND resolved.length > 0 (so an empty file
    // still hits the "no rows" path higher up, not this banner)
    expect(renderFn).toMatch(/resolved\.length\s*>\s*0\s*&&\s*okCount\s*===\s*0/);
    // Must offer a retry affordance so the user isn't stuck
    expect(renderFn).toMatch(/Try another file/);
  });

  test('happy-path status text still shows for mixed/all-OK runs', () => {
    const renderFn = extractFunction('renderFr24Preview');
    // The original "X rows · Y resolved · Z unresolved" line must still exist
    // in the else branch
    expect(renderFn).toMatch(/rows.*okCount.*resolved.*failCount.*unresolved/s);
  });
});

// ─── Transit stat strip auto-hides at 0 transits ─────────
describe('Transit stats strip is empty when state.transits is empty', () => {
  test('renderTransitsView gates the strip on state.transits.length > 0', () => {
    const renderFn = extractFunction('renderTransitsView');
    // The strip render must be wrapped in a length check, not unconditional
    expect(renderFn).toMatch(/state\.transits\.length\s*>\s*0\s*\?\s*renderTransitsStatsStrip/);
  });
});

// ─── 12px font floor (a11y) ──────────────────────────────
describe('No CSS font-size is below 12px', () => {
  test('no `font-size: 11px` or `font-size:11px` declarations remain', () => {
    // Both spaced and unspaced forms should be gone — the floor is 12px.
    // (10px is occasionally fine for super-tiny utility labels but the audit
    // bumped EVERY 11px to 12px for a uniform readability floor.)
    expect(indexHtml).not.toMatch(/font-size:\s*11px/);
  });

  test('Transits tab icon has the emoji variation selector (U+FE0F)', () => {
    // Plain U+2708 (✈) renders as a B/W text glyph in some browsers.
    // Adding U+FE0F (✈️) forces the emoji presentation, matching the other
    // tab icons (🧳 🏆 🌍 …) which are already emoji-class codepoints.
    const tabMatch = indexHtml.match(/data-view="transits-view"[\s\S]{0,200}/);
    expect(tabMatch).toBeTruthy();
    expect(tabMatch[0]).toContain('✈️');
  });
});

// ─── H-2 HttpOnly cookie session (2026-05-30) ────────────
describe('H-2 cookie auth — cookie issued, accepted, cleared', () => {
  const TEST_USER = { username: 'cookie-test-user', password: 'cookie-test-pw-12345' };
  let token;

  beforeAll(async () => {
    await db.users.remove({ username: TEST_USER.username }, { multi: true });
  });

  test('POST /auth/register sets HttpOnly hm_token cookie + returns token in body', async () => {
    const res = await request(app).post('/api/auth/register').send(TEST_USER);
    expect(res.status).toBe(200);
    expect(res.body.token).toBeTruthy();
    token = res.body.token;
    const setCookie = res.headers['set-cookie'] || [];
    const cookieLine = setCookie.find(c => c.startsWith('hm_token='));
    expect(cookieLine).toBeTruthy(); // hm_token cookie must be set on register
    expect(cookieLine).toMatch(/HttpOnly/i);
    expect(cookieLine).toMatch(/SameSite=Strict/i);
    // Path must be / so the cookie rides on every API request
    expect(cookieLine).toMatch(/Path=\//i);
  });

  test('POST /auth/login also sets the cookie', async () => {
    const res = await request(app).post('/api/auth/login').send(TEST_USER);
    expect(res.status).toBe(200);
    expect((res.headers['set-cookie'] || []).find(c => c.startsWith('hm_token='))).toBeTruthy();
  });

  test('GET /auth/me authenticates via Cookie header alone (no Authorization)', async () => {
    const res = await request(app)
      .get('/api/auth/me')
      .set('Cookie', `hm_token=${token}`);
    expect(res.status).toBe(200);
    expect(res.body.username).toBe(TEST_USER.username);
  });

  test('Authorization header still works (back-compat for CLI / tests)', async () => {
    const res = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.username).toBe(TEST_USER.username);
  });

  test('cookie wins when both present (no preference confusion)', async () => {
    const res = await request(app)
      .get('/api/auth/me')
      .set('Cookie', `hm_token=${token}`)
      .set('Authorization', 'Bearer not-a-real-token-12345');
    // If header were preferred, this would 401. Cookie precedence → 200.
    expect(res.status).toBe(200);
  });

  test('POST /auth/logout clears the cookie + revokes the jti', async () => {
    const res = await request(app)
      .post('/api/auth/logout')
      .set('Cookie', `hm_token=${token}`);
    expect(res.status).toBe(200);
    const clear = (res.headers['set-cookie'] || []).find(c => c.startsWith('hm_token='));
    expect(clear).toBeTruthy(); // logout must Set-Cookie to clear hm_token
    // Cleared cookies set an expired date (Thu, 01 Jan 1970 …) or Max-Age=0
    expect(clear).toMatch(/Expires=Thu, 01 Jan 1970|Max-Age=0/i);
    // jti was revoked — same token must now 401 on any auth-gated route
    const probe = await request(app)
      .get('/api/auth/me')
      .set('Cookie', `hm_token=${token}`);
    expect(probe.status).toBe(401);
  });
});

describe('H-2 frontend — no localStorage(hm_token), no Authorization header', () => {
  test('public/index.html no longer reads/writes hm_token in localStorage', () => {
    // The HttpOnly cookie is unreadable from JS — there's nothing for the
    // frontend to stash, and stashing the bearer in localStorage would
    // re-open the XSS exfiltration window the migration was meant to close.
    expect(indexHtml).not.toMatch(/localStorage\.(get|set|remove)Item\(\s*['"]hm_token/);
  });

  test('public/index.html does not stamp Authorization: Bearer anywhere', () => {
    // The cookie travels via credentials:'same-origin'. Any leftover
    // `Authorization: 'Bearer ' + …` would mean the frontend was still
    // trying to read a token it no longer has.
    expect(indexHtml).not.toMatch(/Authorization['"]?\s*:\s*['"]Bearer/);
  });

  test('api() helper uses credentials:"same-origin" so the cookie auto-attaches', () => {
    // The single api() definition — if this regex stops matching, somebody
    // changed the auth shape and the rest of the app will break with it.
    expect(indexHtml).toMatch(/async\s+function\s+api\([\s\S]{0,400}credentials:\s*['"]same-origin['"]/);
  });
});

// ─── CSP nonce refactor (2026-05-30) ─────────────────────
describe('CSP nonce wiring — inline <script> carries placeholder', () => {
  test('every inline <script> (no src=) has nonce="__CSP_NONCE__"', () => {
    // External CDN scripts (with src=) are URL-allowlisted in CSP, no nonce needed.
    // Inline scripts MUST carry the placeholder or they get blocked by CSP and
    // the page dies (login first — see feedback_inline_script_syntax memory).
    const inlineScriptOpenTags = [...indexHtml.matchAll(/<script(?![^>]*\bsrc=)([^>]*)>/g)]
      .map(m => m[0]);
    expect(inlineScriptOpenTags.length).toBeGreaterThan(0);
    for (const tag of inlineScriptOpenTags) {
      expect(tag).toMatch(/nonce="__CSP_NONCE__"/);
    }
  });

  test('inline <style> carries NO nonce — style-src stays permissive because Leaflet injects styles at runtime', () => {
    // Per CSP-3, mixing 'unsafe-inline' with a nonce in style-src causes
    // modern browsers to IGNORE 'unsafe-inline' and enforce nonces strictly.
    // Leaflet injects nonceless inline styles for cursors/panes — so we can't
    // have both. Keep style-src permissive (no nonce) until we have a strict-
    // dynamic story for third-party CSS.
    const styleOpenTags = [...indexHtml.matchAll(/<style([^>]*)>/g)].map(m => m[0]);
    expect(styleOpenTags.length).toBeGreaterThan(0);
    for (const tag of styleOpenTags) {
      expect(tag).not.toMatch(/nonce=/);
    }
  });
});

describe('CSP nonce wiring — server middleware + templated index.html', () => {
  test('server generates res.locals.cspNonce before Helmet', () => {
    const serverSrc = fs.readFileSync(path.join(__dirname, '..', 'server', 'index.js'), 'utf-8');
    const nonceMiddleware = serverSrc.indexOf('res.locals.cspNonce');
    const helmetCall = serverSrc.indexOf('app.use(helmet(');
    expect(nonceMiddleware).toBeGreaterThan(-1);
    expect(helmetCall).toBeGreaterThan(-1);
    // Nonce must be assigned BEFORE Helmet so the CSP header generator can read it
    expect(nonceMiddleware).toBeLessThan(helmetCall);
    expect(serverSrc).toMatch(/crypto\.randomBytes\(\d+\)\.toString\(['"]base64['"]\)/);
  });

  test('Helmet CSP scriptSrc references the nonce via a function-valued directive', () => {
    const serverSrc = fs.readFileSync(path.join(__dirname, '..', 'server', 'index.js'), 'utf-8');
    // scriptSrc must contain a function that emits 'nonce-…' and NO 'unsafe-inline'
    expect(serverSrc).toMatch(/scriptSrc:\s*\[[^\]]*\(req,\s*res\)\s*=>\s*`'nonce-\$\{res\.locals\.cspNonce\}'`/);
    const scriptSrcLine = serverSrc.match(/scriptSrc:\s*\[[^\]]+\]/)[0];
    expect(scriptSrcLine).not.toMatch(/'unsafe-inline'/);
    // styleSrc stays permissive (see comment in server/index.js) — Leaflet
    // injects nonceless inline styles at runtime.
    const styleSrcLine = serverSrc.match(/styleSrc:\s*\[[^\]]+\]/)[0];
    expect(styleSrcLine).toMatch(/'unsafe-inline'/);
  });

  test('GET / templates the nonce into the served HTML and sets a matching CSP header', async () => {
    const res = await request(app).get('/').expect(200);
    // The served HTML must NOT contain the literal placeholder — all replaced.
    expect(res.text).not.toContain('__CSP_NONCE__');
    // The CSP header must contain a nonce-… directive
    const csp = res.headers['content-security-policy'] || '';
    const cspNonceMatch = csp.match(/'nonce-([A-Za-z0-9+/=]+)'/);
    expect(cspNonceMatch).toBeTruthy();
    // The same nonce must appear in the served HTML (on the inline script + style tags)
    const nonce = cspNonceMatch[1];
    expect(res.text).toContain(`nonce="${nonce}"`);
  });

  test('two distinct GET / requests return DIFFERENT nonces (per-request, not pinned)', async () => {
    const a = await request(app).get('/');
    const b = await request(app).get('/');
    const nonceA = (a.headers['content-security-policy'] || '').match(/'nonce-([^']+)'/)[1];
    const nonceB = (b.headers['content-security-policy'] || '').match(/'nonce-([^']+)'/)[1];
    expect(nonceA).not.toBe(nonceB);
  });

  test('SPA catch-all also serves the templated HTML', async () => {
    const res = await request(app).get('/some/spa/route').expect(200);
    expect(res.text).not.toContain('__CSP_NONCE__');
    expect(res.headers['content-type']).toMatch(/html/);
  });
});

// ─── render.yaml deploy invariants (L-3 + L-4) ───────────
describe('render.yaml has lockfile-strict build + auth env vars', () => {
  const renderYaml = fs.readFileSync(path.join(__dirname, '..', 'render.yaml'), 'utf-8');

  test('buildCommand uses npm ci, not npm install', () => {
    expect(renderYaml).toMatch(/buildCommand:\s*npm ci/);
    expect(renderYaml).not.toMatch(/buildCommand:\s*npm install/);
  });

  test('ALLOWED_EMAILS declared with sync:false', () => {
    expect(renderYaml).toMatch(/key:\s*ALLOWED_EMAILS[\s\S]{0,80}sync:\s*false/);
  });

  test('ALLOWED_ORIGINS declared with sync:false', () => {
    expect(renderYaml).toMatch(/key:\s*ALLOWED_ORIGINS[\s\S]{0,80}sync:\s*false/);
  });
});

describe('hover-bg CSS-ified — no dispatcher bridge, no inline data-mouseover/out', () => {
  test('the .hover-bg-tertiary :hover rule exists in the stylesheet', () => {
    expect(indexHtml).toMatch(/\.hover-bg-tertiary:hover\s*\{\s*background:\s*var\(--bg-tertiary\)/);
  });

  test('no data-mouseover / data-mouseout attributes remain in the markup', () => {
    expect(indexHtml).not.toMatch(/data-mouseover\s*=/);
    expect(indexHtml).not.toMatch(/data-mouseout\s*=/);
    expect(indexHtml).not.toMatch(/data-bg-in\s*=/);
    expect(indexHtml).not.toMatch(/data-bg-out\s*=/);
  });

  test('hoverIn / hoverOut are removed from the ACTIONS dispatcher', () => {
    expect(indexHtml).not.toMatch(/hoverIn\s*:/);
    expect(indexHtml).not.toMatch(/hoverOut\s*:/);
  });

  test('the four converted sites carry the hover-bg-tertiary class', () => {
    expect(indexHtml.match(/hover-bg-tertiary/g) || []).toHaveLength(
      // 1 CSS rule + 4 markup sites = 5 occurrences total
      5
    );
  });
});

describe('_runAction must NOT preventDefault unconditionally (sidebar typing regression 2026-05-31)', () => {
  // The dispatcher previously honored `data-prevent="1"` inside _runAction
  // BEFORE delegating to the action handler. For inputs wired with
  // `data-keydown="enterKey" data-prevent="1"` (quick-add, search, tag,
  // person, collection-search), this meant EVERY keystroke called
  // e.preventDefault(), blocking the character from being typed. The
  // enterKey ACTION already calls e.preventDefault() itself after
  // confirming e.key === 'Enter', so unconditional prevention here was
  // both wrong AND redundant.
  test('_runAction does not call e.preventDefault() based on data-prevent', () => {
    // Find the _runAction body and assert it does not contain the buggy
    // unconditional preventDefault line.
    const runActionStart = indexHtml.indexOf('function _runAction(');
    expect(runActionStart).toBeGreaterThan(0);
    const runActionEnd = indexHtml.indexOf('}', runActionStart + 200); // first brace close is enough for a short body
    const body = indexHtml.substring(runActionStart, runActionEnd + 1);
    // Specifically: no `if (el.dataset.prevent) e.preventDefault();` line in _runAction.
    expect(body).not.toMatch(/dataset\.prevent\)\s*e\.preventDefault/);
  });

  test('enterKey ACTION still honors data-prevent (only after Enter check)', () => {
    // The action-handler-internal preventDefault is the correct place — it
    // only runs once we've confirmed the keystroke is Enter.
    const enterKeyStart = indexHtml.indexOf('enterKey:');
    expect(enterKeyStart).toBeGreaterThan(0);
    const body = indexHtml.substring(enterKeyStart, enterKeyStart + 400);
    // Order matters: key check BEFORE preventDefault.
    expect(body).toMatch(/e\.key\s*!==?\s*['"]Enter['"][\s\S]{0,80}dataset\.prevent\)\s*e\.preventDefault/);
  });

  test('all five known data-prevent inputs are keydown+enterKey (no orphans)', () => {
    // If a future change adds data-prevent to a click/input element without
    // also handling preventDefault inside the action, that's the wrong shape.
    // For now, every data-prevent in the markup must sit on a data-keydown="enterKey"
    // element.
    const matches = indexHtml.match(/data-prevent\s*=/g) || [];
    expect(matches.length).toBeGreaterThanOrEqual(5);
    // Each occurrence must be on a line/element that also has data-keydown="enterKey"
    const re = /<[^>]*data-prevent\s*=\s*["']1["'][^>]*>/g;
    let m;
    while ((m = re.exec(indexHtml)) !== null) {
      expect(m[0]).toMatch(/data-keydown\s*=\s*["']enterKey["']/);
    }
  });
});

describe('Sidebar live autocomplete (2026-05-31)', () => {
  test('both inputs carry data-input="liveSearchInput" with livesearch-source', () => {
    expect(indexHtml).toMatch(/id="quick-add-input"[\s\S]{0,400}data-input="liveSearchInput"[\s\S]{0,120}data-livesearch-source="quick-add"/);
    expect(indexHtml).toMatch(/id="map-search-input"[\s\S]{0,400}data-input="liveSearchInput"[\s\S]{0,120}data-livesearch-source="map-search"/);
  });

  test('both inputs still carry enterKey + original arg0 (no regression)', () => {
    expect(indexHtml).toMatch(/id="quick-add-input"[\s\S]{0,400}data-keydown="enterKey"[\s\S]{0,200}data-arg0="quickAddPlace"/);
    expect(indexHtml).toMatch(/id="map-search-input"[\s\S]{0,400}data-keydown="enterKey"[\s\S]{0,200}data-arg0="mapSearch"/);
  });

  test('ACTIONS.liveSearchInput reads livesearchSource and debounces to _runLiveSearch', () => {
    expect(indexHtml).toMatch(/liveSearchInput:\s*\(el\)[\s\S]{0,200}livesearchSource[\s\S]{0,200}clearTimeout\(_liveSearchDebounce\)[\s\S]{0,200}_runLiveSearch\(source\)/);
  });

  test('_runLiveSearch uses getSearchProvider() to branch between providers', () => {
    expect(indexHtml).toMatch(/function _runLiveSearch[\s\S]{0,3000}getSearchProvider\(\)[\s\S]{0,2000}nominatim\.openstreetmap\.org/);
  });

  test('results render with + Add and 📍 (go) buttons wired via dispatcher', () => {
    expect(indexHtml).toMatch(/data-click="liveResultAdd"[\s\S]{0,40}data-arg0="\$\{i\}"/);
    expect(indexHtml).toMatch(/data-click="liveResultGo"[\s\S]{0,40}data-arg0="\$\{i\}"/);
  });

  test('liveResultAdd opens add modal and pre-fills name+address+coords from picker', () => {
    expect(indexHtml).toMatch(/function liveResultAdd[\s\S]{0,800}openAddModal\([\s\S]{0,100}\)[\s\S]{0,600}loc-name[\s\S]{0,80}loc-address/);
  });

  test('liveResultGo pans/zooms map to the picked result', () => {
    expect(indexHtml).toMatch(/function liveResultGo[\s\S]{0,1200}map\.setView\(/);
  });

  test('escapes user/API strings (name + address + error) via esc()', () => {
    expect(indexHtml).toMatch(/_runLiveSearch[\s\S]*?esc\(r\.name\)/);
    expect(indexHtml).toMatch(/_runLiveSearch[\s\S]*?esc\(r\.address\)/);
  });

  test('all data-click in live result rows are dispatcher-pattern (no inline onclick)', () => {
    const start = indexHtml.indexOf('function _runLiveSearch');
    const end = indexHtml.indexOf('function liveResultAdd');
    expect(start).toBeGreaterThan(0);
    expect(end).toBeGreaterThan(start);
    const body = indexHtml.substring(start, end);
    expect(body).not.toMatch(/\bonclick=/);
  });

  test('race protection: input.value.trim() !== q check present in _runLiveSearch', () => {
    const start = indexHtml.indexOf('function _runLiveSearch');
    expect(start).toBeGreaterThan(0);
    const body = indexHtml.substring(start, start + 5000);
    expect(body).toMatch(/input\.value\.trim\(\)\s*!==?\s*q/);
  });
});

describe('Search provider selector + 3-way typeahead (2026-05-31)', () => {
  test('getSearchProvider accepts google/nominatim/photon, defaults google', () => {
    const fn = extractFunction('getSearchProvider');
    expect(fn).toMatch(/'google'/);
    expect(fn).toMatch(/'nominatim'/);
    expect(fn).toMatch(/'photon'/);
    expect(fn).toMatch(/return\s+\[.+?\]\.includes\(v\)\s*\?\s*v\s*:\s*'google'/);
  });

  test('setSearchProvider rejects unknown providers', () => {
    const fn = extractFunction('setSearchProvider');
    expect(fn).toMatch(/\[\s*'google'\s*,\s*'nominatim'\s*,\s*'photon'\s*\]\.includes/);
  });

  test('Account modal contains the search-provider dropdown', () => {
    expect(indexHtml).toMatch(/id="account-search-provider"[\s\S]{0,400}data-change="onSearchProviderChange"/);
    expect(indexHtml).toMatch(/option value="google"[\s\S]{0,200}option value="photon"[\s\S]{0,200}option value="nominatim"/);
  });

  test('_runLiveSearch branches into google / photon / nominatim', () => {
    const fn = extractFunction('_runLiveSearch');
    expect(fn).toMatch(/provider\s*===\s*'google'/);
    expect(fn).toMatch(/provider\s*===\s*'photon'/);
    expect(fn).toMatch(/photon\.komoot\.io/);
    expect(fn).toMatch(/nominatim\.openstreetmap\.org/);
  });

  test('Google path uses Autocomplete (not Text Search) with sessionToken', () => {
    const fn = extractFunction('_runLiveSearch');
    expect(fn).toMatch(/\/places\/autocomplete/);
    expect(fn).toMatch(/_getOrCreateSessionToken\(\)/);
    expect(fn).not.toMatch(/\/places\/search\?q=/); // No Text Search call in typeahead anymore
  });

  test('liveResultAdd resolves Google placeId via /places/sync with same sessionToken', () => {
    const fn = extractFunction('liveResultAdd');
    expect(fn).toMatch(/r\.provider\s*===\s*'google'/);
    expect(fn).toMatch(/\/places\/sync/);
    expect(fn).toMatch(/sessionToken/);
    expect(fn).toMatch(/_resetSessionToken\(\)/);
  });

  test('liveResultGo resolves coordinates for Google placeId via sync', () => {
    const fn = extractFunction('liveResultGo');
    expect(fn).toMatch(/r\.provider\s*===\s*'google'/);
    expect(fn).toMatch(/map\.setView/);
  });
});

describe('Three-provider sync — modal + bulk + settings (2026-05-31)', () => {
  test('edit modal exposes Photon, Nominatim, and Google sync buttons', () => {
    expect(indexHtml).toMatch(/id="loc-photon-sync-btn"[\s\S]{0,300}data-click="syncPhotonFromEditModal"/);
    expect(indexHtml).toMatch(/id="loc-nominatim-sync-btn"[\s\S]{0,300}data-click="syncNominatimFromEditModal"/);
    expect(indexHtml).toMatch(/id="loc-google-sync-btn"[\s\S]{0,300}data-click="syncFromEditModal"/);
  });

  test('syncPhotonFromEditModal hits photon.komoot.io and applies via shared helper', () => {
    const fn = extractFunction('syncPhotonFromEditModal');
    expect(fn).toMatch(/photon\.komoot\.io/);
    expect(fn).toMatch(/_photonSyncedAt/);
    // PUT is now routed through applyEnrichmentUpdates rather than inline.
    expect(fn).toMatch(/applyEnrichmentUpdates\(/);
    expect(fn).toMatch(/osmToCategory\(/);
  });

  test('syncNominatimFromEditModal uses reverse when coords present, forward otherwise', () => {
    const fn = extractFunction('syncNominatimFromEditModal');
    expect(fn).toMatch(/nominatim\.openstreetmap\.org/);
    expect(fn).toMatch(/_nominatimSyncedAt/);
    expect(fn).toMatch(/\/reverse\?format=json/);
    expect(fn).toMatch(/\/search\?format=json/);
  });

  test('modal sync functions route through showEnrichmentConfirm (user confirms overwrites)', () => {
    // Old fill-only behavior was replaced with a user-facing confirm modal that
    // surfaces every returned field as an opt-in/opt-out diff. Bulk sync still
    // uses the old conservative fill-only path (per the bulkEnrichPhoton test below).
    const photon = extractFunction('syncPhotonFromEditModal');
    const nominatim = extractFunction('syncNominatimFromEditModal');
    expect(photon).toMatch(/showEnrichmentConfirm\('Photon'/);
    expect(photon).toMatch(/buildEnrichmentDiffs\(loc,\s*proposed\)/);
    expect(photon).toMatch(/applyEnrichmentUpdates\(loc,[\s\S]{0,80}'_photonSyncedAt'\)/);
    expect(nominatim).toMatch(/showEnrichmentConfirm\('Nominatim'/);
    expect(nominatim).toMatch(/buildEnrichmentDiffs\(loc,\s*proposed\)/);
    expect(nominatim).toMatch(/applyEnrichmentUpdates\(loc,[\s\S]{0,80}'_nominatimSyncedAt'\)/);
  });

  test('bulk toolbar has Photon button alongside existing Nominatim (OSM) + Google', () => {
    expect(indexHtml).toMatch(/data-arg0="bulkEnrichPhoton"[\s\S]{0,200}🌍 Photon/);
    expect(indexHtml).toMatch(/data-arg0="bulkEnrichOSM"[\s\S]{0,200}🗺️ Nominatim/);
    expect(indexHtml).toMatch(/data-arg0="bulkSyncGoogle"[\s\S]{0,200}📍 Google/);
  });

  test('bulkEnrichPhoton iterates targets, polite rate-limit, fill-only, photon stamp', () => {
    const fn = extractFunction('bulkEnrichPhoton');
    expect(fn).toMatch(/photon\.komoot\.io/);
    expect(fn).toMatch(/_photonSyncedAt/);
    expect(fn).toMatch(/setTimeout\(r,\s*100\)/);
    expect(fn).toMatch(/!loc\.address\s*&&/);
  });

  test('Account modal shows three provider explainer cards', () => {
    expect(indexHtml).toMatch(/🌍 Photon[\s\S]{0,200}Free · no key/);
    expect(indexHtml).toMatch(/🗺️ Nominatim[\s\S]{0,300}Free · no key/);
    expect(indexHtml).toMatch(/🔄 Google[\s\S]{0,300}Paid · key required/);
  });

  test('no inline onclick in any of the new sync sites', () => {
    const p = extractFunction('syncPhotonFromEditModal');
    const n = extractFunction('syncNominatimFromEditModal');
    const b = extractFunction('bulkEnrichPhoton');
    expect(p).not.toMatch(/\bonclick=/);
    expect(n).not.toMatch(/\bonclick=/);
    expect(b).not.toMatch(/\bonclick=/);
  });

  test('syncFromEditModal restoration label is "🔄 Google" (not "🔄 Sync Google")', () => {
    const fn = extractFunction('syncFromEditModal');
    expect(fn).toMatch(/'🔄 Google'/);
    expect(fn).not.toMatch(/'🔄 Sync Google'/);
  });
});

describe('_readPositionalArgs "this" sentinel — restores element-passing across CSP refactor (2026-05-31)', () => {
  // The CSP refactor (c9f7ec9) migrated onclick="fn('x', this)" → data-click=fn data-arg0=x data-arg1=this.
  // But dataset reads strings — selectStatus / setStatusFilter / etc. expected the element ref and crashed
  // on "this".classList.add(...). _readPositionalArgs now maps the literal string "this" → el.
  test('_readPositionalArgs delegates to _resolveArgSentinel which maps "this" to el', () => {
    // Refactored 2026-06-03: the "this" mapping moved out of _readPositionalArgs
    // into a sibling _resolveArgSentinel that also handles "this.value",
    // "this.checked", "this.files[0]", "this.dataset.X". See the dedicated
    // _resolveArgSentinel describe-block below for the per-pattern tests.
    const reader = extractFunction('_readPositionalArgs');
    expect(reader).toMatch(/_resolveArgSentinel\(v,\s*el\)/);
    const resolver = extractFunction('_resolveArgSentinel');
    expect(resolver).toMatch(/v\s*===\s*'this'\s*\)\s*return\s*el/);
  });

  test('modal status toggle still uses data-arg1="this" (selectStatus needs the button)', () => {
    expect(indexHtml).toMatch(/data-click="selectStatus"[\s\S]{0,80}data-arg0="bucket"[\s\S]{0,40}data-arg1="this"/);
    expect(indexHtml).toMatch(/data-click="selectStatus"[\s\S]{0,80}data-arg0="been"[\s\S]{0,40}data-arg1="this"/);
  });

  test('sidebar status filter chips use data-arg1="this" (setStatusFilter needs the button)', () => {
    expect(indexHtml).toMatch(/data-click="setStatusFilter"[\s\S]{0,80}data-arg0="all"[\s\S]{0,40}data-arg1="this"/);
    expect(indexHtml).toMatch(/data-click="setStatusFilter"[\s\S]{0,80}data-arg0="bucket"[\s\S]{0,40}data-arg1="this"/);
  });

  test('selectStatus / setStatusFilter receivers still take (value, btn) — sentinel is in the dispatcher, not the receivers', () => {
    const selectStatus = extractFunction('selectStatus');
    const setStatusFilter = extractFunction('setStatusFilter');
    expect(selectStatus).toMatch(/function selectStatus\(status,\s*btn\)/);
    expect(selectStatus).toMatch(/btn\.classList\.add\(/);
    expect(setStatusFilter).toMatch(/function setStatusFilter\(status,\s*btn\)/);
    expect(setStatusFilter).toMatch(/btn\.classList\.add\(/);
  });
});

describe('_resolveArgSentinel "this.X" — fixes silent dropdown breakage (2026-06-03)', () => {
  // The 2026-06-02 audit caught that `data-arg0="this.value"` passed the literal
  // string "this.value" to handlers (the old resolver only mapped bare "this"
  // to el). 9 callsites silently broke: Marker Style / Marker Size Mode / Trip
  // Selector dropdowns; Replay scrubber + Realistic-routes checkbox; FR24 file
  // picker; Attach-search input; renamePerson + removePersonGlobal buttons via
  // `this.dataset.personIdx`. New resolver maps "this", "this.value",
  // "this.checked", "this.files[0]", and "this.dataset.X" to the right ref.

  const vm = require('vm');
  function runResolver(v, el) {
    const fn = extractFunction('_resolveArgSentinel');
    const ctx = vm.createContext({ v, el });
    return vm.runInContext(fn + '\n_resolveArgSentinel(v, el)', ctx);
  }

  test('"this" → el (preserved)', () => {
    const el = { tag: 'EL' };
    expect(runResolver('this', el)).toBe(el);
  });

  test('"this.value" → el.value', () => {
    const el = { value: 'squircle' };
    expect(runResolver('this.value', el)).toBe('squircle');
  });

  test('"this.checked" → el.checked', () => {
    const el = { checked: true };
    expect(runResolver('this.checked', el)).toBe(true);
  });

  test('"this.files[0]" → el.files[0]', () => {
    const f = { name: 'foo.csv' };
    const el = { files: [f] };
    expect(runResolver('this.files[0]', el)).toBe(f);
  });

  test('"this.dataset.personIdx" → el.dataset.personIdx', () => {
    const el = { dataset: { personIdx: '3' } };
    expect(runResolver('this.dataset.personIdx', el)).toBe('3');
  });

  test('unknown literal string falls through unchanged', () => {
    expect(runResolver('plain-string', { value: 'should-not-be-returned' })).toBe('plain-string');
  });

  test('select dropdowns use data-change (not data-click) so the action fires AFTER value updates', () => {
    // Click on a <select> fires when the user opens the dropdown — the value
    // hasn't changed yet. The proper event is `change`. The 3 selects flagged
    // by the audit must use data-change to actually propagate the picked value.
    expect(indexHtml).toMatch(/id="marker-style"[^>]*data-change="setMarkerStyle"/);
    expect(indexHtml).toMatch(/id="marker-size-mode"[^>]*data-change="setMarkerSizeMode"/);
    expect(indexHtml).toMatch(/id="trip-selector"[^>]*data-change="selectTrip"/);
  });

  test('FR24 file input uses data-change (file inputs fire change when a file is picked)', () => {
    expect(indexHtml).toMatch(/id="fr24-file"[^>]*data-change="handleFr24File"/);
  });

  test('replay scrubber + attach-search use data-input for live updates', () => {
    expect(indexHtml).toMatch(/id="replay-scrubber"[^>]*data-input="seekReplay"/);
    expect(indexHtml).toMatch(/placeholder="Search transits…"[^>]*data-input="setAttachSearch"/);
  });
});

describe('Hearts widget duplicate-attribute bug fix (2026-06-03)', () => {
  // Pre-2026-06-03: each heart span had `data-click="setBucketStrength"
  // data-arg0="N"` AND `data-click="handleHeartKey" data-arg0="event"
  // data-arg1="N"` on the same element. Per HTML spec, repeated attrs
  // drop all but the last — so setBucketStrength was silently overridden
  // by handleHeartKey, and arg0 became "event" not the val. Hearts could
  // not be set from the keyboard (and click was also broken). UX agent
  // caught this in the 2026-06-02 audit.

  test('no heart span has duplicate data-click attributes', () => {
    // Extract the bucket-strength container and confirm each .heart has
    // exactly one data-click and one data-keydown (not two data-clicks).
    const bs = indexHtml.match(/<div class="star-rating" id="bucket-strength"[\s\S]*?<\/div>/);
    expect(bs).not.toBeNull();
    const heartLines = bs[0].match(/<span class="heart"[^>]*>/g) || [];
    expect(heartLines.length).toBe(5);
    for (const line of heartLines) {
      const clickCount = (line.match(/data-click=/g) || []).length;
      const keydownCount = (line.match(/data-keydown=/g) || []).length;
      const arg0Count = (line.match(/data-arg0=/g) || []).length;
      expect(clickCount).toBe(1);
      expect(keydownCount).toBe(1);
      expect(arg0Count).toBe(1);
    }
  });

  test('each heart routes click → setBucketStrength(N) and keydown → onHeartKey', () => {
    for (let n = 1; n <= 5; n++) {
      const pat = new RegExp(`<span class="heart" data-val="${n}"[^>]*data-click="setBucketStrength" data-arg0="${n}" data-keydown="onHeartKey"`);
      expect(indexHtml).toMatch(pat);
    }
  });

  test('onHeartKey ACTIONS entry reads val from el.dataset and calls handleHeartKey(e, val)', () => {
    // Find the ACTIONS object's onHeartKey entry; confirm it reads dataset.val.
    expect(indexHtml).toMatch(/onHeartKey:\s*\(el,\s*e\)\s*=>\s*\{[\s\S]{0,300}el\.dataset\.val[\s\S]{0,300}handleHeartKey\(e,\s*val\)/);
  });
});

describe('GPS my-location (2026-05-31)', () => {
  test('Leaflet topright control hosts 📍 locate-me + ✨ discover buttons wired to dispatcher', () => {
    // The buttons moved off the cluttered sidebar onto a Leaflet control
    // (initMap → MapToolsControl). Verify both buttons exist with the right
    // data-click wiring and live inside the map-tools-control container.
    expect(indexHtml).toMatch(/MapToolsControl\s*=\s*L\.Control\.extend/);
    expect(indexHtml).toMatch(/map-tools-control[\s\S]{0,400}id="locate-me-btn"[\s\S]{0,200}data-click="locateMe"/);
    expect(indexHtml).toMatch(/map-tools-control[\s\S]{0,500}id="discover-btn"[\s\S]{0,200}data-click="openDiscoverModal"/);
    // Map drag/zoom must not fire when clicking the buttons
    expect(indexHtml).toMatch(/MapToolsControl[\s\S]{0,1200}L\.DomEvent\.disableClickPropagation/);
  });

  test('sidebar no longer carries the locate-me / discover buttons', () => {
    // The sidebar lost both buttons — confirm via aside scope. If they leak
    // back into the sidebar in a later refactor, this guards the regression.
    const sidebarStart = indexHtml.indexOf('<aside id="sidebar">');
    const sidebarEnd = indexHtml.indexOf('</aside>', sidebarStart);
    expect(sidebarStart).toBeGreaterThan(0);
    expect(sidebarEnd).toBeGreaterThan(sidebarStart);
    const sidebar = indexHtml.substring(sidebarStart, sidebarEnd);
    expect(sidebar).not.toMatch(/id="locate-me-btn"/);
    expect(sidebar).not.toMatch(/id="discover-btn"/);
  });

  test('locateMe handles permission-denied / unavailable / timeout via toast', () => {
    const gps = extractFunction('_getBrowserGPS');
    expect(gps).toMatch(/navigator\.geolocation/);
    expect(gps).toMatch(/PERMISSION_DENIED/);
    expect(gps).toMatch(/POSITION_UNAVAILABLE/);
    expect(gps).toMatch(/TIMEOUT/);
    expect(gps).toMatch(/enableHighAccuracy:\s*true/);
  });

  test('locateMe pans the map, drops a distinctive marker + accuracy circle', () => {
    const fn = extractFunction('locateMe');
    expect(fn).toMatch(/_getBrowserGPS\(\)/);
    expect(fn).toMatch(/L\.circle\(/);
    expect(fn).toMatch(/L\.marker\(/);
    expect(fn).toMatch(/map\.setView\(/);
    // Offers a one-click "Add place here" follow-up in the popup
    expect(fn).toMatch(/data-click="addPlaceAtMyLocation"/);
  });

  test('addPlaceAtMyLocation opens add modal pre-filled with coords', () => {
    const fn = extractFunction('addPlaceAtMyLocation');
    expect(fn).toMatch(/parseFloat\(latStr\)/);
    expect(fn).toMatch(/parseFloat\(lngStr\)/);
    expect(fn).toMatch(/openAddModal\(lat,\s*lng\)/);
  });

  test('no inline onclick in any of the new GPS sites', () => {
    const a = extractFunction('locateMe');
    const b = extractFunction('addPlaceAtMyLocation');
    const c = extractFunction('_getBrowserGPS');
    expect(a).not.toMatch(/\bonclick=/);
    expect(b).not.toMatch(/\bonclick=/);
    expect(c).not.toMatch(/\bonclick=/);
  });
});
