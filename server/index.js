const express = require('express');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3001;
const LOG_LEVEL = (process.env.LOG_LEVEL || 'info').toLowerCase();

// ── Structured logger ────────────────────────────────────
const LOG_LEVELS = { debug: 0, info: 1, warn: 2, error: 3 };
const _logThreshold = LOG_LEVELS[LOG_LEVEL] ?? 1;

function log(level, event, data = {}) {
  if ((LOG_LEVELS[level] ?? 1) < _logThreshold) return;
  const entry = { ts: new Date().toISOString(), level, event, ...data };
  // Mask sensitive fields
  if (entry.key) entry.key = '••••' + String(entry.key).slice(-4);
  if (entry.password) entry.password = '[redacted]';
  const out = level === 'error' ? console.error : level === 'warn' ? console.warn : console.log;
  out(JSON.stringify(entry));
}

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;
const JWT_SECRET = process.env.JWT_SECRET || (process.env.NODE_ENV === 'production' ? null : 'history-map-dev-secret-change-me');
if (!JWT_SECRET) { console.error('FATAL: JWT_SECRET env var required in production'); process.exit(1); }
const GOOGLE_PLACES_KEY = process.env.GOOGLE_PLACES_KEY || '';
// Comma-separated list of allowed emails. Empty = anyone can register/sign in.
const ALLOWED_EMAILS = (process.env.ALLOWED_EMAILS || '').split(',').map(e => e.trim().toLowerCase()).filter(Boolean);
// First email in allowlist is considered admin
const ADMIN_EMAIL = ALLOWED_EMAILS[0] || '';

function audit(event, details, req) {
  const entry = {
    event,
    ...details,
    ip: req?.headers?.['x-forwarded-for'] || req?.ip || 'unknown',
    userAgent: req?.headers?.['user-agent'] || '',
    timestamp: new Date().toISOString(),
  };
  db.auditLog.insert(entry).catch(() => {});
  const level = event.includes('fail') || event.includes('block') ? 'warn' : 'info';
  log(level, 'audit_' + event, { ...details, ip: entry.ip });
}

// Middleware
app.set('trust proxy', 1); // Trust first proxy (Render)
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' }, // Required for Google Sign-In
}));
app.use(cors(process.env.ALLOWED_ORIGINS ? { origin: process.env.ALLOWED_ORIGINS.split(',').map(s => s.trim()) } : undefined));
app.use(express.json({ limit: '10mb' }));

// Rate limiting
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, max: 15 }));
app.use('/api/admin', rateLimit({ windowMs: 60 * 60 * 1000, max: 30 }));
app.use('/api', rateLimit({ windowMs: 60 * 1000, max: 200 }));

// Request logging
app.use('/api', (req, res, next) => {
  const start = Date.now();
  const orig = res.json.bind(res);
  res.json = function (body) {
    const ms = Date.now() - start;
    const userId = req.user?.id;
    log('info', 'http_request', {
      method: req.method, path: req.path, status: res.statusCode,
      ms, userId, ip: req.headers['x-forwarded-for'] || req.ip,
    });
    return orig(body);
  };
  next();
});

// Static files
app.use(express.static(path.join(__dirname, '..', 'public')));

// ── Auth middleware ──────────────────────────────────────
function requireAdmin(req, res, next) {
  if (ADMIN_EMAIL && req.user.username.toLowerCase() !== ADMIN_EMAIL) {
    return res.status(403).json({ error: 'Admin only' });
  }
  next();
}

function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ── Auth routes ──────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    if (password.length < 4) return res.status(400).json({ error: 'Password too short' });
    if (ALLOWED_EMAILS.length > 0 && !ALLOWED_EMAILS.includes(username.toLowerCase())) {
      audit('register_blocked', { username, reason: 'not_in_allowlist' }, req);
      return res.status(403).json({ error: 'Registration is restricted. Contact the admin.' });
    }

    const existing = await db.users.findOne({ username });
    if (existing) {
      audit('register_failed', { username, reason: 'username_taken' }, req);
      return res.status(409).json({ error: 'Username taken' });
    }

    const hash = await bcrypt.hash(password, 10);
    const user = await db.users.insert({ username, password: hash, createdAt: new Date().toISOString() });
    const token = jwt.sign({ id: user._id, username }, JWT_SECRET, { expiresIn: '90d' });
    audit('register_success', { username }, req);
    res.json({ token, username });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await db.users.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      audit('login_failed', { username, reason: 'invalid_credentials' }, req);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user._id, username }, JWT_SECRET, { expiresIn: '90d' });
    audit('login_success', { username }, req);
    res.json({ token, username });
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/auth/me', auth, (req, res) => {
  res.json({ username: req.user.username });
});

// Google OAuth client ID (for frontend)
app.get('/api/auth/google-client-id', (req, res) => {
  res.json({ clientId: GOOGLE_CLIENT_ID || null });
});

app.post('/api/auth/google', async (req, res) => {
  if (!googleClient) return res.status(501).json({ error: 'Google OAuth not configured' });
  try {
    const { credential } = req.body;
    const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    const email = payload.email;
    const googleId = payload.sub;

    // Find or create user by Google ID
    let user = await db.users.findOne({ googleId });
    if (!user) {
      // Check allowlist for new users
      if (ALLOWED_EMAILS.length > 0 && !ALLOWED_EMAILS.includes(email.toLowerCase())) {
        audit('google_login_blocked', { email, reason: 'not_in_allowlist' }, req);
        return res.status(403).json({ error: 'Access restricted. Contact the admin.' });
      }
      // Check if email matches an existing password user — link accounts
      user = await db.users.findOne({ username: email });
      if (user) {
        await db.users.update({ _id: user._id }, { $set: { googleId } });
      } else {
        user = await db.users.insert({
          username: email,
          googleId,
          name: payload.name || email,
          picture: payload.picture || null,
          createdAt: new Date().toISOString(),
        });
      }
    }
    const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, { expiresIn: '90d' });
    audit('google_login_success', { email: user.username }, req);
    res.json({ token, username: user.username, picture: user.picture });
  } catch (err) {
    log('error', 'google_auth_error', { error: err.message });
    audit('google_login_failed', { reason: err.message }, req);
    res.status(401).json({ error: 'Google authentication failed' });
  }
});

// ── Merge accounts (admin only) ───────────────────────────
app.post('/api/admin/merge-accounts', auth, requireAdmin, async (req, res) => {
  try {
    const { fromUsername, toUsername } = req.body;
    if (!fromUsername || !toUsername) return res.status(400).json({ error: 'fromUsername and toUsername required' });

    const fromUser = await db.users.findOne({ username: fromUsername });
    const toUser = await db.users.findOne({ username: toUsername });
    if (!fromUser) return res.status(404).json({ error: `User "${fromUsername}" not found` });
    if (!toUser) return res.status(404).json({ error: `User "${toUsername}" not found` });

    const fromId = fromUser._id;
    const toId = toUser._id;

    // Move all data from source to target
    const locCount = await db.locations.update({ userId: fromId }, { $set: { userId: toId } }, { multi: true });
    const tripCount = await db.trips.update({ userId: fromId }, { $set: { userId: toId } }, { multi: true });
    const colCount = await db.collections.update({ userId: fromId }, { $set: { userId: toId } }, { multi: true });

    // Copy googleId to target if source had one
    if (fromUser.googleId && !toUser.googleId) {
      await db.users.update({ _id: toId }, { $set: { googleId: fromUser.googleId, picture: fromUser.picture } });
    }

    // Delete source user
    await db.users.remove({ _id: fromId });

    audit('account_merge', { from: fromUsername, to: toUsername, locations: locCount, trips: tripCount, collections: colCount }, req);
    res.json({ ok: true, merged: { locations: locCount, trips: tripCount, collections: colCount } });
  } catch (err) {
    res.status(500).json({ error: 'Merge failed: ' + err.message });
  }
});

// ── Reset password (admin only) ───────────────────────────
app.post('/api/admin/reset-password', auth, requireAdmin, async (req, res) => {
  try {
    const { username, newPassword } = req.body;
    if (!username || !newPassword) return res.status(400).json({ error: 'username and newPassword required' });
    const user = await db.users.findOne({ username });
    if (!user) return res.status(404).json({ error: `User "${username}" not found` });
    const hash = await bcrypt.hash(newPassword, 10);
    await db.users.update({ _id: user._id }, { $set: { password: hash } });
    audit('password_reset', { username, by: req.user.username }, req);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── List users (admin only) ──────────────────────────────
app.get('/api/admin/users', auth, requireAdmin, async (req, res) => {
  const users = await db.users.find({});
  res.json(users.map(u => ({ _id: u._id, username: u.username, googleId: u.googleId || null, createdAt: u.createdAt })));
});

// ── Audit log (admin only) ────────────────────────────────
app.get('/api/audit', auth, requireAdmin, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 10000);
  const logs = await db.auditLog.find({}).sort({ timestamp: -1 }).limit(limit);
  res.json(logs);
});

// ── Locations CRUD ───────────────────────────────────────
app.get('/api/locations', auth, async (req, res) => {
  const locs = await db.locations.find({ userId: req.user.id });
  res.json(locs);
});

function validateLocation(body) {
  const { name, lat, lng } = body;
  if (!name || typeof name !== 'string') return 'Name required';
  if (typeof lat !== 'number' || isNaN(lat) || lat < -90 || lat > 90) return 'Invalid latitude';
  if (typeof lng !== 'number' || isNaN(lng) || lng < -180 || lng > 180) return 'Invalid longitude';
  return null;
}

app.post('/api/locations', auth, async (req, res) => {
  const err = validateLocation(req.body);
  if (err) return res.status(400).json({ error: err });
  const loc = { ...req.body, userId: req.user.id, updatedAt: new Date().toISOString() };
  delete loc._id; // let nedb assign
  const saved = await db.locations.insert(loc);
  log('info', 'db_insert', { table: 'locations', id: saved._id, name: saved.name, userId: req.user.id });
  res.json(saved);
});

app.put('/api/locations/:id', auth, async (req, res) => {
  const updates = { ...req.body, updatedAt: new Date().toISOString() };
  delete updates._id;
  delete updates.userId;
  const count = await db.locations.update(
    { _id: req.params.id, userId: req.user.id },
    { $set: updates }
  );
  if (count === 0) return res.status(404).json({ error: 'Not found' });
  const updated = await db.locations.findOne({ _id: req.params.id });
  log('info', 'db_update', { table: 'locations', id: req.params.id, fields: Object.keys(updates), userId: req.user.id });
  res.json(updated);
});

app.delete('/api/locations/:id', auth, async (req, res) => {
  const count = await db.locations.remove({ _id: req.params.id, userId: req.user.id });
  if (count === 0) return res.status(404).json({ error: 'Not found' });
  log('info', 'db_remove', { table: 'locations', id: req.params.id, userId: req.user.id });
  res.json({ ok: true });
});

// Bulk import
app.post('/api/locations/bulk', auth, async (req, res) => {
  const { locations: locs } = req.body;
  if (!Array.isArray(locs)) return res.status(400).json({ error: 'Expected array' });
  const valid = locs.filter(l => l.name && typeof l.lat === 'number' && typeof l.lng === 'number' && !isNaN(l.lat) && !isNaN(l.lng));
  if (valid.length === 0) return res.status(400).json({ error: 'No valid locations' });
  const toInsert = valid.map(l => ({ ...l, userId: req.user.id, updatedAt: new Date().toISOString() }));
  toInsert.forEach(l => delete l._id);
  const saved = await db.locations.insert(toInsert);
  log('info', 'db_bulk_insert', { table: 'locations', count: saved.length, skipped: locs.length - valid.length, userId: req.user.id });
  res.json(saved);
});

// ── Trips CRUD ───────────────────────────────────────────
app.get('/api/trips', auth, async (req, res) => {
  const trips = await db.trips.find({ userId: req.user.id });
  res.json(trips);
});

app.post('/api/trips', auth, async (req, res) => {
  const trip = { ...req.body, userId: req.user.id };
  delete trip._id;
  const saved = await db.trips.insert(trip);
  log('info', 'db_insert', { table: 'trips', id: saved._id, name: saved.name, userId: req.user.id });
  res.json(saved);
});

app.put('/api/trips/:id', auth, async (req, res) => {
  const updates = { ...req.body };
  delete updates._id;
  delete updates.userId;
  const count = await db.trips.update({ _id: req.params.id, userId: req.user.id }, { $set: updates });
  if (count === 0) return res.status(404).json({ error: 'Not found' });
  const updated = await db.trips.findOne({ _id: req.params.id });
  log('info', 'db_update', { table: 'trips', id: req.params.id, fields: Object.keys(updates), userId: req.user.id });
  res.json(updated);
});

app.delete('/api/trips/:id', auth, async (req, res) => {
  const count = await db.trips.remove({ _id: req.params.id, userId: req.user.id });
  if (count === 0) return res.status(404).json({ error: 'Not found' });
  log('info', 'db_remove', { table: 'trips', id: req.params.id, userId: req.user.id });
  res.json({ ok: true });
});

// ── Collections CRUD ─────────────────────────────────────
app.get('/api/collections', auth, async (req, res) => {
  const cols = await db.collections.find({ userId: req.user.id });
  res.json(cols);
});

app.post('/api/collections', auth, async (req, res) => {
  try {
    const col = { ...req.body, userId: req.user.id };
    delete col._id;
    const saved = await db.collections.insert(col);
    log('info', 'db_insert', { table: 'collections', id: saved._id, name: saved.name, userId: req.user.id });
    res.json(saved);
  } catch (err) {
    log('error', 'db_insert_error', { table: 'collections', error: err.message, userId: req.user.id });
    res.status(500).json({ error: 'Failed to create collection: ' + err.message });
  }
});

app.put('/api/collections/:id', auth, async (req, res) => {
  const updates = { ...req.body };
  delete updates._id;
  delete updates.userId;
  const count = await db.collections.update({ _id: req.params.id, userId: req.user.id }, { $set: updates });
  if (count === 0) return res.status(404).json({ error: 'Not found' });
  const updated = await db.collections.findOne({ _id: req.params.id });
  log('info', 'db_update', { table: 'collections', id: req.params.id, fields: Object.keys(updates), userId: req.user.id });
  res.json(updated);
});

app.delete('/api/collections/:id', auth, async (req, res) => {
  const count = await db.collections.remove({ _id: req.params.id, userId: req.user.id });
  if (count === 0) return res.status(404).json({ error: 'Not found' });
  log('info', 'db_remove', { table: 'collections', id: req.params.id, userId: req.user.id });
  res.json({ ok: true });
});

// Bulk import collections
app.post('/api/collections/bulk', auth, async (req, res) => {
  const { collections: cols } = req.body;
  if (!Array.isArray(cols)) return res.status(400).json({ error: 'Expected array' });
  const toInsert = cols.map(c => ({ ...c, userId: req.user.id }));
  toInsert.forEach(c => delete c._id);
  const saved = await db.collections.insert(toInsert);
  log('info', 'db_bulk_insert', { table: 'collections', count: saved.length, userId: req.user.id });
  res.json(saved);
});

// ── Admin-1 boundaries proxy (Natural Earth, cached) ─────
const ADMIN1_CACHE = path.join(__dirname, '..', 'data', 'admin1-simplified.json');
// Try 10m first via jsdelivr (faster CDN), fall back to 50m from GitHub
const NE_ADMIN1_URLS = [
  'https://cdn.jsdelivr.net/gh/nvkelso/natural-earth-vector@master/geojson/ne_50m_admin_1_states_provinces.geojson',
  'https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_50m_admin_1_states_provinces.geojson',
];

app.get('/api/admin1-boundaries', async (req, res) => {
  try {
    // Serve from cache if available
    if (fs.existsSync(ADMIN1_CACHE)) {
      const stat = fs.statSync(ADMIN1_CACHE);
      // Refresh cache if older than 30 days
      if (Date.now() - stat.mtimeMs < 30 * 24 * 60 * 60 * 1000) {
        res.setHeader('Content-Type', 'application/json');
        return fs.createReadStream(ADMIN1_CACHE).pipe(res);
      }
    }

    log('info', 'admin1_fetch_start');
    let geojson = null;
    for (const url of NE_ADMIN1_URLS) {
      try {
        log('debug', 'admin1_fetch_try', { url: url.substring(0, 80) });
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 60000);
        const response = await fetch(url, { signal: controller.signal });
        clearTimeout(timeout);
        if (!response.ok) continue;
        geojson = await response.json();
        log('info', 'admin1_fetch_ok', { features: geojson.features?.length || 0 });
        break;
      } catch (e) { log('warn', 'admin1_fetch_fail', { error: e.message }); }
    }
    if (!geojson) throw new Error('All sources failed');

    // Simplify: keep only essential properties, reduce coordinate precision
    const simplified = {
      type: 'FeatureCollection',
      features: geojson.features.map(f => ({
        type: 'Feature',
        properties: {
          name: f.properties.name || f.properties.NAME || '',
          country: f.properties.admin || f.properties.ADMIN || '',
          iso_country: f.properties.iso_a2 || f.properties.ISO_A2 || '',
          type_en: f.properties.type_en || '',
        },
        geometry: simplifyGeometry(f.geometry, 1), // 1 decimal place ≈ 10km, keeps file small
      })).filter(f => f.geometry && f.properties.name && f.geometry.coordinates?.length > 0),
    };

    fs.writeFileSync(ADMIN1_CACHE, JSON.stringify(simplified));
    log('info', 'admin1_cached', { regions: simplified.features.length });
    res.json(simplified);
  } catch (err) {
    log('error', 'admin1_fetch_error', { error: err.message });
    // Try serving stale cache
    if (fs.existsSync(ADMIN1_CACHE)) {
      res.setHeader('Content-Type', 'application/json');
      return fs.createReadStream(ADMIN1_CACHE).pipe(res);
    }
    res.status(500).json({ error: 'Failed to load boundaries' });
  }
});

function simplifyGeometry(geom, precision) {
  if (!geom || !geom.coordinates) return geom;
  const round = (coords) => {
    if (typeof coords[0] === 'number') {
      return [+coords[0].toFixed(precision), +coords[1].toFixed(precision)];
    }
    return coords.map(round);
  };
  return { type: geom.type, coordinates: round(geom.coordinates) };
}

// ── User settings (API keys etc.) ────────────────────────
app.get('/api/settings', auth, async (req, res) => {
  const user = await db.users.findOne({ _id: req.user.id });
  res.json({ googlePlacesKey: user?.googlePlacesKey ? '••••' + user.googlePlacesKey.slice(-4) : null });
});

app.put('/api/settings', auth, async (req, res) => {
  const { googlePlacesKey } = req.body;
  const updates = {};
  if (googlePlacesKey !== undefined) updates.googlePlacesKey = googlePlacesKey || null;
  await db.users.update({ _id: req.user.id }, { $set: updates });
  audit('settings_update', { fields: Object.keys(updates) }, req);
  res.json({ ok: true });
});

// ── User's own latest backup ─────────────────────────────
app.get('/api/my-backup', auth, async (req, res) => {
  try {
    if (!fs.existsSync(BACKUP_DIR)) return res.status(404).json({ error: 'No backups yet' });
    const username = req.user.username.replace(/[^a-zA-Z0-9._-]/g, '_');
    const userBackups = fs.readdirSync(BACKUP_DIR)
      .filter(f => f.startsWith(username + '_') && f.endsWith('.json'))
      .sort().reverse();
    if (userBackups.length === 0) return res.status(404).json({ error: 'No backups for your account yet' });
    res.download(path.join(BACKUP_DIR, userBackups[0]));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Google Places API (proxied, key never exposed) ───────
async function getPlacesKey(userId) {
  const user = await db.users.findOne({ _id: userId });
  return user?.googlePlacesKey || GOOGLE_PLACES_KEY || '';
}

app.get('/api/places/status', auth, async (req, res) => {
  const key = await getPlacesKey(req.user.id);
  res.json({ enabled: !!key });
});

app.get('/api/places/search', auth, async (req, res) => {
  const placesKey = await getPlacesKey(req.user.id);
  if (!placesKey) return res.status(501).json({ error: 'Google Places API not configured. Add your key in Account settings.' });
  try {
    const { q, lat, lng } = req.query;
    if (!q) return res.status(400).json({ error: 'Query required' });
    let url = `https://maps.googleapis.com/maps/api/place/textsearch/json?query=${encodeURIComponent(q)}&key=${placesKey}`;
    if (lat && lng) url += `&location=${lat},${lng}&radius=50000`;
    const _t0 = Date.now();
    const response = await fetch(url);
    const data = await response.json();
    log('info', 'places_api_call', { endpoint: 'textsearch', query: q, status: data.status, results: (data.results || []).length, ms: Date.now() - _t0, userId: req.user.id });
    if (data.status !== 'OK' && data.status !== 'ZERO_RESULTS') {
      log('warn', 'places_api_error', { endpoint: 'textsearch', status: data.status, error: data.error_message, userId: req.user.id });
      return res.status(502).json({ error: 'Places API: ' + data.status });
    }
    res.json((data.results || []).slice(0, 10).map(p => ({
      name: p.name,
      address: p.formatted_address || '',
      lat: p.geometry?.location?.lat,
      lng: p.geometry?.location?.lng,
      googleRating: p.rating || null,
      priceLevel: p.price_level || null,
      placeId: p.place_id || '',
      types: p.types || [],
      userRatingsTotal: p.user_ratings_total || 0,
    })));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/places/sync', auth, async (req, res) => {
  const placesKey = await getPlacesKey(req.user.id);
  if (!placesKey) return res.status(501).json({ error: 'Google Places API not configured' });
  try {
    const { name, lat, lng } = req.body;
    if (!name) return res.status(400).json({ error: 'Name required' });
    let url = `https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=${encodeURIComponent(name)}&inputtype=textquery&fields=name,rating,price_level,formatted_address,geometry,place_id,user_ratings_total&key=${placesKey}`;
    if (lat && lng) url += `&locationbias=point:${lat},${lng}`;
    const _t0 = Date.now();
    const response = await fetch(url);
    const data = await response.json();
    log('info', 'places_api_call', { endpoint: 'findplace', input: name, status: data.status, found: !!(data.candidates?.length), ms: Date.now() - _t0, userId: req.user.id });
    if (data.status !== 'OK' || !data.candidates?.length) {
      return res.json({ found: false });
    }
    const p = data.candidates[0];
    res.json({
      found: true,
      googleRating: p.rating || null,
      priceLevel: p.price_level || null,
      address: p.formatted_address || '',
      placeId: p.place_id || '',
      userRatingsTotal: p.user_ratings_total || 0,
      lat: p.geometry?.location?.lat,
      lng: p.geometry?.location?.lng,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Bulk sync — accepts array of { id, name, lat, lng }
// Skips locations that already have googleRating (already synced)
// Adds _googleSyncedAt timestamp so we don't re-sync
app.post('/api/places/bulk-sync', auth, async (req, res) => {
  const placesKey = await getPlacesKey(req.user.id);
  if (!placesKey) return res.status(501).json({ error: 'Google Places API not configured' });
  try {
    const { locations } = req.body;
    if (!Array.isArray(locations)) return res.status(400).json({ error: 'Array required' });
    const batch = locations.slice(0, 50); // Cap at 50 per request
    const batchStart = Date.now();
    log('info', 'bulk_sync_start', { count: batch.length, userId: req.user.id });
    const results = [];
    let found = 0, notFound = 0, errors = 0;
    for (const loc of batch) {
      try {
        let url = `https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=${encodeURIComponent(loc.name)}&inputtype=textquery&fields=rating,price_level,formatted_address,place_id,user_ratings_total&key=${placesKey}`;
        if (loc.lat && loc.lng) url += `&locationbias=point:${loc.lat},${loc.lng}`;
        const _t0 = Date.now();
        const response = await fetch(url);
        const data = await response.json();
        const callMs = Date.now() - _t0;
        if (data.status === 'OK' && data.candidates?.length) {
          const p = data.candidates[0];
          const updates = { _googleSyncedAt: new Date().toISOString() };
          if (p.rating) updates.googleRating = p.rating;
          if (p.price_level != null) updates.priceLevel = p.price_level;
          if (p.formatted_address && !loc.address) updates.address = p.formatted_address;
          if (p.place_id) updates._googlePlaceId = p.place_id;
          await db.locations.update({ _id: loc.id, userId: req.user.id }, { $set: updates });
          results.push({ id: loc.id, ...updates, found: true });
          found++;
          log('debug', 'bulk_sync_item', { locId: loc.id, name: loc.name, found: true, rating: p.rating, ms: callMs });
        } else {
          await db.locations.update({ _id: loc.id, userId: req.user.id }, { $set: { _googleSyncedAt: new Date().toISOString() } });
          results.push({ id: loc.id, found: false });
          notFound++;
          log('debug', 'bulk_sync_item', { locId: loc.id, name: loc.name, found: false, status: data.status, ms: callMs });
        }
      } catch (err) {
        results.push({ id: loc.id, found: false });
        errors++;
        log('warn', 'bulk_sync_item_error', { locId: loc.id, name: loc.name, error: err.message });
      }
    }
    log('info', 'bulk_sync_done', { count: batch.length, found, notFound, errors, ms: Date.now() - batchStart, userId: req.user.id });
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Catch-all for SPA ────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// ── Auto-backup (daily, per user) ────────────────────────
const BACKUP_DIR = path.join(process.env.DATA_DIR || (process.env.NODE_ENV === 'production' ? '/data' : path.join(__dirname, '..', 'data')), 'backups');
const MAX_BACKUPS_PER_USER = 7; // Keep last 7 daily backups

async function runBackup() {
  try {
    if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });
    const users = await db.users.find({});
    const date = new Date().toISOString().split('T')[0];

    for (const user of users) {
      const userId = user._id;
      const username = user.username.replace(/[^a-zA-Z0-9._-]/g, '_');
      const backupFile = path.join(BACKUP_DIR, `${username}_${date}.json`);

      // Skip if today's backup already exists
      if (fs.existsSync(backupFile)) continue;

      const [locations, trips, collections] = await Promise.all([
        db.locations.find({ userId }),
        db.trips.find({ userId }),
        db.collections.find({ userId }),
      ]);

      const backup = {
        exportDate: new Date().toISOString(),
        username: user.username,
        locations, trips, collections,
      };

      fs.writeFileSync(backupFile, JSON.stringify(backup));
      log('info', 'backup_created', { username, locations: locations.length, trips: trips.length, collections: collections.length });

      // Prune old backups for this user
      const userBackups = fs.readdirSync(BACKUP_DIR)
        .filter(f => f.startsWith(username + '_') && f.endsWith('.json'))
        .sort().reverse();
      for (const old of userBackups.slice(MAX_BACKUPS_PER_USER)) {
        fs.unlinkSync(path.join(BACKUP_DIR, old));
      }
    }
    // Prune audit log entries older than 90 days
    const cutoff = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString();
    const pruned = await db.auditLog.remove({ timestamp: { $lt: cutoff } }, { multi: true });
    if (pruned > 0) log('info', 'audit_log_pruned', { removed: pruned, olderThan: cutoff });
  } catch (err) {
    log('error', 'backup_failed', { error: err.message });
  }
}

// Admin endpoint to list/download backups
app.get('/api/admin/backups', auth, requireAdmin, async (req, res) => {
  if (!fs.existsSync(BACKUP_DIR)) return res.json([]);
  const files = fs.readdirSync(BACKUP_DIR).filter(f => f.endsWith('.json')).sort().reverse();
  res.json(files.map(f => ({
    name: f,
    size: fs.statSync(path.join(BACKUP_DIR, f)).size,
    date: f.match(/_(\d{4}-\d{2}-\d{2})\.json$/)?.[1] || '',
  })));
});

app.get('/api/admin/backups/:filename', auth, requireAdmin, (req, res) => {
  // Prevent path traversal: resolve to absolute and verify it's inside BACKUP_DIR
  const filePath = path.resolve(path.join(BACKUP_DIR, path.basename(req.params.filename)));
  const normalizedDir = path.resolve(BACKUP_DIR);
  if (!filePath.startsWith(normalizedDir + path.sep) || !fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'Not found' });
  }
  res.download(filePath);
});

if (require.main === module) {
  app.listen(PORT, () => {
    log('info', 'server_start', { port: PORT });
    // Run backup on startup, then every 24h
    runBackup();
    setInterval(runBackup, 24 * 60 * 60 * 1000);
  });
}

module.exports = app;
