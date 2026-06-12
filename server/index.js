const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const dns = require('dns').promises;
const helmet = require('helmet');
const compression = require('compression');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
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
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';
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

// Per-request CSP nonce. Must run BEFORE Helmet so the CSP header generator
// below can reference it via res.locals. Also templated into the served
// index.html so every inline <script> and <style> block carries the matching
// nonce attribute — without it the browser blocks the script and login dies
// (boot.spec.js + a source-grep invariant guard the placeholder presence).
app.use((req, res, next) => {
  res.locals.cspNonce = crypto.randomBytes(16).toString('base64');
  next();
});

// gzip/deflate over the wire. Render doesn't auto-gzip Node responses, and
// index.html alone is ~580 KB raw vs ~140 KB gzipped (~4× win); /api/locations
// JSON compresses similarly. Default threshold (1 KB) skips tiny responses
// where compression overhead exceeds the saving. Clients without
// Accept-Encoding (or with identity) are served uncompressed automatically.
app.use(compression());

app.use(helmet({
  contentSecurityPolicy: {
    // Inline <script> blocks must carry the per-request nonce — 'unsafe-inline'
    // is OFF on script-src, so a stored XSS can no longer ship a
    // <script>alert(1)</script> (the browser will refuse without the
    // unguessable nonce). script-src-attr is now LOCKED to 'none': every
    // former `onclick=…` handler in the codebase has been migrated to
    // `data-click=…` + a document-level dispatcher, so no inline JS attrs
    // remain. A stored XSS that lands `<button onclick="alert(1)">` is
    // silently ignored by the browser.
    //
    // style-src and style-src-attr stay permissive: Leaflet (and other map
    // libs) inject inline <style> blocks at runtime to set cursors / panes /
    // tile transforms with no nonce hook we can supply. Per CSP-3, mixing
    // 'unsafe-inline' with a nonce source causes modern browsers to ignore
    // 'unsafe-inline' — so we can't have both. Style injection is much lower
    // severity than script injection (no code execution), and a strict
    // style-src would block third-party map code without a clear replacement.
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", (req, res) => `'nonce-${res.locals.cspNonce}'`, "https://unpkg.com", "https://cdn.jsdelivr.net", "https://accounts.google.com"],
      scriptSrcAttr: ["'none'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://unpkg.com", "https://fonts.googleapis.com"],
      styleSrcAttr: ["'unsafe-inline'"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: [
        "'self'",
        "https://api.rainviewer.com",  // dynamic overlay: weather radar metadata
        "https://nominatim.openstreetmap.org",
        "https://photon.komoot.io",
        "https://maps.googleapis.com",
        "https://router.project-osrm.org",
        "https://accounts.google.com",
        "https://cdn.jsdelivr.net",
        "https://raw.githubusercontent.com",
      ],
      frameSrc: ["https://accounts.google.com"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
    },
  },
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' }, // Required for Google Sign-In
}));
// CORS: explicit allowlist. When ALLOWED_ORIGINS is unset in production, deny
// all cross-origin requests (origin: false). In dev, allow localhost so the
// frontend served by Express can still call its own API.
const corsAllowed = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(s => s.trim())
  : (process.env.NODE_ENV === 'production' ? false : ['http://localhost:3001', 'http://localhost:3000']);
app.use(cors({ origin: corsAllowed, credentials: false }));
// Bulk-import endpoints handle KML/CSV/Timeline payloads that legitimately run
// into single-digit MBs. Everything else stays at 1MB — authenticated users
// can't DoS the 512MB Render instance with repeated 10MB bodies on regular
// CRUD endpoints. Path-mounted middleware runs before the global; body-parser
// skips re-parsing when req._body is already true, so each request is parsed
// exactly once at the appropriate limit.
app.use(['/api/locations/bulk', '/api/transits/bulk'], express.json({ limit: '10mb' }));
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());

// Rate limiting — disabled in test environment to allow full test suite runs
const isTest = process.env.NODE_ENV === 'test';
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, max: isTest ? 10000 : 15 }));
app.use('/api/admin', rateLimit({ windowMs: 60 * 60 * 1000, max: isTest ? 10000 : 30 }));
app.use('/api', rateLimit({ windowMs: 60 * 1000, max: isTest ? 10000 : 200 }));

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

// Serve the SPA shell with the per-request CSP nonce templated into the
// inline <script>/<style> placeholders. Read once at startup and cached in
// memory — a per-request fs.readFile would be wasteful given index.html
// changes only on deploy. express.static still serves every other static
// asset (favicon, …) — { index: false } keeps it from auto-serving index.html
// for `/`, which would bypass the nonce templating.
const INDEX_HTML_PATH = path.join(__dirname, '..', 'public', 'index.html');
let _indexTemplate = null;
function getIndexTemplate() {
  if (_indexTemplate === null) {
    _indexTemplate = fs.readFileSync(INDEX_HTML_PATH, 'utf-8');
  }
  return _indexTemplate;
}
function serveIndex(req, res) {
  const html = getIndexTemplate().replace(/__CSP_NONCE__/g, res.locals.cspNonce);
  res.type('html').send(html);
}
app.get('/', serveIndex);

// Public share page — serves share.html with nonce injection (same pattern as index.html)
let _shareTemplate = null;
function getShareTemplate() {
  if (!_shareTemplate) _shareTemplate = fs.readFileSync(path.join(__dirname, '..', 'public', 'share.html'), 'utf8');
  return _shareTemplate;
}
app.get('/s/:token', (req, res) => {
  res.type('html').send(getShareTemplate().replace(/__CSP_NONCE__/g, res.locals.cspNonce));
});

// Static files (excluding index.html — see above)
app.use(express.static(path.join(__dirname, '..', 'public'), { index: false }));

// ── JWT lifecycle ────────────────────────────────────────
// Shortened from 90d to 30d after the 4-domain audit (any XSS hands an
// attacker a long-lived full-account token; revocation cuts that window).
const JWT_EXPIRY = '30d';

// In-memory revocation list keyed by jti → exp (seconds). Cleared on restart,
// which is fine: tokens signed under the prior process were anyway tied to a
// secret that may rotate. Pruned every 6h so the set can't grow unbounded
// over a long uptime.
const revokedJtis = new Map();
function isRevoked(jti) {
  if (!jti) return false;
  const exp = revokedJtis.get(jti);
  if (!exp) return false;
  if (Date.now() >= exp * 1000) { revokedJtis.delete(jti); return false; }
  return true;
}
function revokeJti(jti, exp) {
  if (!jti || !exp) return;
  revokedJtis.set(jti, exp);
}
function pruneRevoked() {
  const nowSec = Math.floor(Date.now() / 1000);
  for (const [jti, exp] of revokedJtis) if (exp <= nowSec) revokedJtis.delete(jti);
}
if (!process.env.NODE_ENV || process.env.NODE_ENV !== 'test') {
  setInterval(pruneRevoked, 6 * 60 * 60 * 1000).unref();
}

function signToken(payload) {
  return jwt.sign({ ...payload, jti: crypto.randomUUID() }, JWT_SECRET, { expiresIn: JWT_EXPIRY });
}

// ── HttpOnly session cookie (H-2) ────────────────────────
// The cookie is the primary auth channel for the browser: it's not reachable
// from JS (httpOnly) so an XSS can no longer exfiltrate the bearer. The
// Authorization-header fallback is retained for supertest-driven tests and
// for any non-browser API client (CLI scripts, etc.) — anywhere the token
// has to travel back to the issuing client out-of-band.
//
// SameSite=Strict gives us CSRF protection for free: a third-party site
// can't trigger an authenticated POST because the cookie won't ride along
// on cross-origin navigations. The personal-app context has no embeds /
// federated nav paths that depend on lax cookie behavior.
const COOKIE_NAME = 'hm_token';
const COOKIE_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000; // matches JWT_EXPIRY
function setAuthCookie(res, token) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    maxAge: COOKIE_MAX_AGE_MS,
    path: '/',
  });
}
function clearAuthCookie(res) {
  res.clearCookie(COOKIE_NAME, { path: '/' });
}

// ── Auth middleware ──────────────────────────────────────
function requireAdmin(req, res, next) {
  if (!ADMIN_EMAIL || !req.user?.username || req.user.username.toLowerCase() !== ADMIN_EMAIL) {
    return res.status(403).json({ error: 'Admin only' });
  }
  next();
}

async function auth(req, res, next) {
  // Cookie first (browsers), Authorization header second (CLI / tests).
  const cookieToken = req.cookies?.[COOKIE_NAME];
  const headerMatch = req.headers.authorization?.match(/^Bearer\s+(.+)$/i);
  const token = cookieToken || (headerMatch && headerMatch[1]);
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (isRevoked(decoded.jti)) return res.status(401).json({ error: 'Token revoked' });
    // Prevent deleted users from writing orphaned documents. NeDB is in-memory
    // so this lookup is fast (microseconds) and not a meaningful throughput cost.
    const userExists = await db.users.findOne({ _id: decoded.id });
    if (!userExists) return res.status(401).json({ error: 'Account not found' });
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ── Auth routes ──────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (typeof username !== 'string' || typeof password !== 'string' || !username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
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
    const token = signToken({ id: user._id, username });
    setAuthCookie(res, token);
    audit('register_success', { username }, req);
    res.json({ token, username });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (typeof username !== 'string' || typeof password !== 'string') {
      audit('login_failed', { reason: 'invalid_input' }, req);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const user = await db.users.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      audit('login_failed', { username, reason: 'invalid_credentials' }, req);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = signToken({ id: user._id, username });
    setAuthCookie(res, token);
    audit('login_success', { username }, req);
    res.json({ token, username });
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/auth/me', auth, (req, res) => {
  res.json({ username: req.user.username });
});

// Revoke the current token (server-side blocklist) AND clear the session
// cookie. The frontend also drops any cached session-state flag, but this
// kills the bearer server-side for the rest of its TTL — a copy of the
// token (e.g. exfiltrated before the HttpOnly migration) can no longer
// authenticate. Returns 401 if the token was already invalid/expired
// (auth middleware handles that), 200 on successful revocation.
app.post('/api/auth/logout', auth, (req, res) => {
  revokeJti(req.user.jti, req.user.exp);
  clearAuthCookie(res);
  audit('logout', { username: req.user.username }, req);
  res.json({ ok: true });
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
    if (!payload.email_verified) return res.status(403).json({ error: 'Email not verified' });
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
    const token = signToken({ id: user._id, username: user.username });
    setAuthCookie(res, token);
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
    if (typeof fromUsername !== 'string' || typeof toUsername !== 'string' || !fromUsername || !toUsername) {
      return res.status(400).json({ error: 'fromUsername and toUsername required' });
    }

    const fromUser = await db.users.findOne({ username: fromUsername });
    const toUser = await db.users.findOne({ username: toUsername });
    if (!fromUser) return res.status(404).json({ error: `User "${fromUsername}" not found` });
    if (!toUser) return res.status(404).json({ error: `User "${toUsername}" not found` });
    if (fromUser._id === toUser._id) return res.status(400).json({ error: 'Cannot merge an account into itself' });

    const fromId = fromUser._id;
    const toId = toUser._id;

    // Move all data from source to target
    const locCount = await db.locations.update({ userId: fromId }, { $set: { userId: toId } }, { multi: true });
    const tripCount = await db.trips.update({ userId: fromId }, { $set: { userId: toId } }, { multi: true });
    const colCount = await db.collections.update({ userId: fromId }, { $set: { userId: toId } }, { multi: true });
    const transitCount = await db.transits.update({ userId: fromId }, { $set: { userId: toId } }, { multi: true });

    // Copy googleId to target if source had one
    if (fromUser.googleId && !toUser.googleId) {
      await db.users.update({ _id: toId }, { $set: { googleId: fromUser.googleId, picture: fromUser.picture } });
    }

    // Delete source user
    await db.users.remove({ _id: fromId });

    audit('account_merge', { from: fromUsername, to: toUsername, locations: locCount, trips: tripCount, collections: colCount, transits: transitCount }, req);
    res.json({ ok: true, merged: { locations: locCount, trips: tripCount, collections: colCount, transits: transitCount } });
  } catch (err) {
    log('error', 'merge_accounts_failed', { error: err.message });
    res.status(500).json({ error: 'Merge failed' });
  }
});

// ── Reset password (admin only) ───────────────────────────
app.post('/api/admin/reset-password', auth, requireAdmin, async (req, res) => {
  try {
    const { username, newPassword } = req.body;
    if (typeof username !== 'string' || typeof newPassword !== 'string' || !username || !newPassword) {
      return res.status(400).json({ error: 'username and newPassword required' });
    }
    const user = await db.users.findOne({ username });
    if (!user) return res.status(404).json({ error: `User "${username}" not found` });
    const hash = await bcrypt.hash(newPassword, 10);
    await db.users.update({ _id: user._id }, { $set: { password: hash } });
    audit('password_reset', { username, by: req.user.username }, req);
    res.json({ ok: true });
  } catch (err) {
    log('error', 'password_reset_failed', { error: err.message });
    res.status(500).json({ error: 'Reset failed' });
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
// Cache-Control: no-cache instructs the browser to revalidate on every refresh
// — it stores the response in disk cache + sends If-None-Match on the next GET.
// Express's automatic weak ETag (body-hash) handles the comparison and returns
// 304 with no body when fresh. For the typical 5 k-location user this turns a
// repeated ~140 KB gzip payload into a header-only round-trip. S2 perf 2026-06-04.
app.get('/api/locations', auth, async (req, res) => {
  const locs = await db.locations.find({ userId: req.user.id });
  res.set('Cache-Control', 'private, no-cache');
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
  const loc = sanitizeLocationUpdate(pickLocationFields(req.body));
  loc.userId = req.user.id;
  loc.updatedAt = new Date().toISOString();
  const saved = await db.locations.insert(loc);
  log('info', 'db_insert', { table: 'locations', id: saved._id, name: saved.name, userId: req.user.id });
  res.json(saved);
});

// Allowlist of writable location fields — single source of truth for PUT and bulk POST
// so client- or third-party-supplied (e.g. Nominatim) keys can't write unexpected fields.
// Excludes _id/userId (ownership) and updatedAt (server-stamped). Also blocks __proto__.
const LOCATION_FIELDS = ['name','lat','lng','address','category','status','myRating','googleRating',
  'priceLevel','tripId','tripOrder','collections','people','tags','notes','visits','needsApproval',
  'suggestedCategory','createdAt','_googlePlaceId','_googleUrl','_googleSyncedAt','bucketStrength','iata','media'];

function pickLocationFields(body) {
  const clean = {};
  if (!body || typeof body !== 'object') return clean;
  LOCATION_FIELDS.forEach(f => { if (body[f] !== undefined) clean[f] = body[f]; });
  return clean;
}

// Clamp/validate fields on a location update payload. Shared between POST and PUT
// so a stored value can't bypass the rules set during bulk import.
function sanitizeLocationUpdate(updates) {
  if (updates.bucketStrength !== undefined) {
    const n = parseInt(updates.bucketStrength, 10);
    updates.bucketStrength = isNaN(n) ? 0 : Math.max(0, Math.min(5, n));
  }
  if (updates.iata !== undefined) {
    if (typeof updates.iata === 'string') {
      const v = updates.iata.toUpperCase();
      if (/^[A-Z0-9]{2,4}$/.test(v)) updates.iata = v;
      else delete updates.iata;
    } else {
      delete updates.iata;
    }
  }
  // Block javascript:/data:/vbscript: URI injection via stored _googleUrl —
  // the frontend renders this as <a href="…">. Drop anything that isn't
  // explicitly http(s).
  if (updates._googleUrl !== undefined) {
    if (typeof updates._googleUrl === 'string' && /^https?:\/\//i.test(updates._googleUrl)) {
      // keep as-is
    } else {
      delete updates._googleUrl;
    }
  }
  // media[] — EXIF metadata entries attached via the Photos drop zone.
  // Schema per entry: { source, filename, lat, lon, takenAt, addedAt }.
  // Cap at 100 entries to prevent runaway NeDB doc growth; stamp addedAt
  // server-side so the client can't forge insertion order.
  if (updates.media !== undefined) {
    if (!Array.isArray(updates.media)) {
      delete updates.media;
    } else {
      const VALID_SOURCES = new Set(['manual', 'photo-org']);
      updates.media = updates.media
        .filter(e => e && typeof e === 'object')
        .filter(e => typeof e.filename === 'string' && e.filename.trim().length > 0)
        .map(e => {
          const entry = {};
          entry.source = VALID_SOURCES.has(e.source) ? e.source : 'manual';
          entry.filename = String(e.filename).slice(0, 255);
          if (typeof e.lat === 'number' && isFinite(e.lat) && e.lat >= -90 && e.lat <= 90) entry.lat = e.lat;
          if (typeof e.lon === 'number' && isFinite(e.lon) && e.lon >= -180 && e.lon <= 180) entry.lon = e.lon;
          if (typeof e.takenAt === 'string') entry.takenAt = e.takenAt.slice(0, 40);
          entry.addedAt = typeof e.addedAt === 'string' && e.addedAt ? e.addedAt : new Date().toISOString();
          return entry;
        })
        .slice(0, 100);
    }
  }
  // notes — free-text rendered via esc() everywhere today, but the web-import
  // snippet flow lands attacker-controllable text here (server/import-adapters/
  // llm.js → public/index.html:12133 concat into notes). Defense-in-depth: cap
  // length and strip <script>/<iframe> blocks + javascript:/vbscript: URI
  // schemes server-side so a future render-path regression can't weaponise
  // stored notes. Cybersec MED-3 closeout.
  if (updates.notes !== undefined) {
    if (typeof updates.notes !== 'string') {
      delete updates.notes;
    } else {
      let n = updates.notes;
      // Loop until stable so nested/split patterns like <scr<script>ipt> can't survive one pass
      let prev;
      do {
        prev = n;
        n = n.replace(/<script\b[^>]*>[\s\S]*?<\/script\s*>/gi, '');
        n = n.replace(/<iframe\b[^>]*>[\s\S]*?<\/iframe\s*>/gi, '');
        n = n.replace(/<\/?(?:script|iframe)\b[^>]*>/gi, '');
        n = n.replace(/javascript:/gi, '').replace(/vbscript:/gi, '');
      } while (n !== prev);
      if (n.length > 10000) n = n.slice(0, 10000);
      updates.notes = n;
    }
  }
  return updates;
}

app.put('/api/locations/:id', auth, async (req, res) => {
  const updates = sanitizeLocationUpdate(pickLocationFields(req.body));
  updates.updatedAt = new Date().toISOString();
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
const MAX_LOCATIONS_PER_BULK = 10000;
app.post('/api/locations/bulk', auth, async (req, res) => {
  const { locations: locs } = req.body;
  if (!Array.isArray(locs)) return res.status(400).json({ error: 'Expected array' });
  if (locs.length > MAX_LOCATIONS_PER_BULK) return res.status(400).json({ error: `Too many locations (max ${MAX_LOCATIONS_PER_BULK})` });
  const valid = locs.filter(l => l.name && typeof l.lat === 'number' && typeof l.lng === 'number' && !isNaN(l.lat) && !isNaN(l.lng));
  if (valid.length === 0) return res.status(400).json({ error: 'No valid locations' });
  const toInsert = valid.map(l => {
    const clean = sanitizeLocationUpdate(pickLocationFields(l));
    clean.userId = req.user.id;
    clean.updatedAt = new Date().toISOString();
    return clean;
  });
  const saved = await db.locations.insert(toInsert);
  log('info', 'db_bulk_insert', { table: 'locations', count: saved.length, skipped: locs.length - valid.length, userId: req.user.id });
  res.json(saved);
});

// ── Trips CRUD ───────────────────────────────────────────
app.get('/api/trips', auth, async (req, res) => {
  const trips = await db.trips.find({ userId: req.user.id });
  res.json(trips);
});

// Allowlist + cap for trip writes. Color must be a CSS-safe hex (#RRGGBB / #RGB)
// or a short keyword so it can't break out of an inline style attribute.
const TRIP_FIELDS = ['name', 'color', 'startDate', 'endDate', 'notes'];
const COLOR_RE = /^#[0-9a-fA-F]{3,8}$|^[a-zA-Z]{1,20}$/;
function sanitizeTripUpdate(body) {
  const out = {};
  for (const k of TRIP_FIELDS) {
    if (body[k] === undefined) continue;
    if (k === 'color' && typeof body[k] === 'string' && !COLOR_RE.test(body[k])) continue;
    if (typeof body[k] === 'string' && body[k].length > 2000) continue;
    out[k] = body[k];
  }
  return out;
}

app.post('/api/trips', auth, async (req, res) => {
  const trip = { ...sanitizeTripUpdate(req.body), userId: req.user.id };
  if (!trip.name) return res.status(400).json({ error: 'name required' });
  const saved = await db.trips.insert(trip);
  log('info', 'db_insert', { table: 'trips', id: saved._id, name: saved.name, userId: req.user.id });
  res.json(saved);
});

app.put('/api/trips/:id', auth, async (req, res) => {
  const updates = sanitizeTripUpdate(req.body);
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

// ── Trip share-link generation / revocation ───────────────
app.post('/api/trips/:id/share', auth, async (req, res) => {
  const trip = await db.trips.findOne({ _id: req.params.id, userId: req.user.id });
  if (!trip) return res.status(404).json({ error: 'Not found' });
  const shareToken = crypto.randomBytes(20).toString('hex');
  await db.trips.update({ _id: trip._id }, { $set: { shareToken } });
  log('info', 'trip_share', { tripId: trip._id, userId: req.user.id });
  res.json({ shareToken });
});

app.delete('/api/trips/:id/share', auth, async (req, res) => {
  const count = await db.trips.update(
    { _id: req.params.id, userId: req.user.id },
    { $unset: { shareToken: true } }
  );
  if (count === 0) return res.status(404).json({ error: 'Not found' });
  log('info', 'trip_unshare', { tripId: req.params.id, userId: req.user.id });
  res.json({ ok: true });
});

// ── Public shared-trip data (no auth) ─────────────────────
const SHARE_TOKEN_RE = /^[0-9a-f]{40}$/;
app.get('/api/share/:token', async (req, res) => {
  if (!SHARE_TOKEN_RE.test(req.params.token)) return res.status(404).json({ error: 'Not found' });
  const trip = await db.trips.findOne({ shareToken: req.params.token });
  if (!trip) return res.status(404).json({ error: 'Not found' });
  const rawLocs = await db.locations.find({ userId: trip.userId, tripId: trip._id });
  const locations = rawLocs
    .map(l => ({
      _id: l._id, name: l.name, lat: l.lat, lng: l.lng,
      address: l.address, category: l.category, tripOrder: l.tripOrder,
      visits: (l.visits || []).map(v => ({ date: v.date })),
      tags: l.tags || [],
    }))
    .sort((a, b) => (a.tripOrder ?? 999) - (b.tripOrder ?? 999));
  res.json({
    trip: { _id: trip._id, name: trip.name, color: trip.color, startDate: trip.startDate, endDate: trip.endDate },
    locations,
  });
});

// ── Narrate-a-trip (Haiku-powered NL parsing) ─────────────
// Per-endpoint rate limit — LLM cost ≈ $0.001/call after prompt-cache warmup;
// 200/min global is permissive, cap at 10/min/user to bound runaway behaviour.
// status check is rate-limited too (auth-only, low cost) to keep the surface
// uniform with the web-import limiter scope.
app.use(['/api/trips/narrate', '/api/trips/narrate-status'], rateLimit({ windowMs: 60 * 1000, max: isTest ? 10000 : 10 }));
app.get('/api/trips/narrate-status', auth, async (req, res) => {
  const key = await getAnthropicKey(req.user.id);
  res.json({ enabled: !!key });
});

app.post('/api/trips/narrate', auth, async (req, res) => {
  const apiKey = await getAnthropicKey(req.user.id);
  if (!apiKey) return res.status(501).json({ error: 'Anthropic API not configured. Add your key in Account settings.' });
  const { text } = req.body || {};
  if (!text || typeof text !== 'string' || text.length < 4) return res.status(400).json({ error: 'Trip description required (min 4 chars)' });
  if (text.length > 4000) return res.status(400).json({ error: 'Description too long (max 4000 chars)' });

  let Anthropic;
  try { Anthropic = require('@anthropic-ai/sdk'); }
  catch { return res.status(500).json({ error: 'Anthropic SDK not installed on server' }); }

  const client = new Anthropic.default({ apiKey });
  const today = new Date().toISOString().slice(0, 10);

  const _t0 = Date.now();
  try {
    const response = await client.messages.create({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 1024,
      system: [
        {
          type: 'text',
          text: 'You parse free-form trip descriptions into structured JSON via the parse_trip tool. ' +
                'Today is ' + today + '. Resolve relative dates ("next week", "August", "in 2 weeks") against today. ' +
                'Use ISO format YYYY-MM-DD. If a year is omitted, infer the next occurrence of the month from today. ' +
                'If only nights are given for a stop, leave startDate/endDate null and set nights. ' +
                'If only a date range and stop names are given (no per-stop dates), divide the range evenly across stops. ' +
                'If trip name is not given, generate one from the primary stops, e.g. "Tokyo + Kyoto + Osaka".',
          cache_control: { type: 'ephemeral' },
        },
      ],
      tools: [
        {
          name: 'parse_trip',
          description: 'Emit the structured trip parsed from the user description.',
          input_schema: {
            type: 'object',
            properties: {
              name: { type: 'string', description: 'Trip name. Generate from stops if not given.' },
              startDate: { type: ['string', 'null'], description: 'YYYY-MM-DD or null.' },
              endDate: { type: ['string', 'null'], description: 'YYYY-MM-DD or null.' },
              stops: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    name: { type: 'string', description: 'Place name (city or POI).' },
                    startDate: { type: ['string', 'null'] },
                    endDate: { type: ['string', 'null'] },
                    nights: { type: ['number', 'null'] },
                  },
                  required: ['name'],
                },
              },
            },
            required: ['name', 'stops'],
          },
        },
      ],
      tool_choice: { type: 'tool', name: 'parse_trip' },
      messages: [{ role: 'user', content: text }],
    });
    const ms = Date.now() - _t0;
    const toolUse = response.content.find(c => c.type === 'tool_use');
    if (!toolUse) {
      log('warn', 'narrate_no_tool_use', { userId: req.user.id, ms });
      return res.status(502).json({ error: 'Parser did not produce structured output' });
    }
    log('info', 'narrate_api_call', {
      userId: req.user.id, ms,
      inputTokens: response.usage?.input_tokens || 0,
      outputTokens: response.usage?.output_tokens || 0,
      cacheReadTokens: response.usage?.cache_read_input_tokens || 0,
      cacheCreationTokens: response.usage?.cache_creation_input_tokens || 0,
    });
    res.json(toolUse.input);
  } catch (err) {
    log('warn', 'narrate_api_error', { userId: req.user.id, status: err.status || 0, type: err.error?.type || 'unknown' });
    // Sanitize Anthropic error — never leak full upstream message body
    const status = err.status || 500;
    const msg = err.status === 401 ? 'Anthropic API key rejected' :
                err.status === 429 ? 'Rate limited by Anthropic' :
                err.status === 400 ? 'Bad request to Anthropic' :
                'Anthropic API error';
    res.status(502).json({ error: msg });
  }
});

// ── Website Import ───────────────────────────────────────
const WEBSITE_IMPORT_ADAPTERS = [
  { pattern: /^(www\.)?timeout\./i, name: 'timeout', parse: require('./import-adapters/timeout').parseTimeoutArticle },
];
const { parseVenuesLLM } = require('./import-adapters/llm');

const SSRF_BLOCK = [
  /^localhost$/i,
  /^127\./,
  /^0\.0\.0\.0$/,
  /^::1$/,
  /^::$/,  // IPv6 unspecified — routes to loopback on Linux
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  // Link-local + cloud metadata endpoints (AWS/GCP/Azure use 169.254.169.254;
  // GCP also resolves metadata.google.internal). Without these an attacker
  // with an Anthropic key could hit the Render host's metadata service.
  /^169\.254\./,
  /^metadata\.google\.internal$/i,
  // IPv6 link-local (fe80::/10) + Unique Local Addresses (fc00::/7 → fc/fd).
  /^fe80:/i,
  /^fc[0-9a-f]{2}:/i,
  /^fd[0-9a-f]{2}:/i,
];

// Node's WHATWG URL preserves `[...]` around IPv6 hostnames AND converts
// IPv4-mapped IPv6 (`::ffff:127.0.0.1`) to hex form (`::ffff:7f00:1`). Both
// would defeat the regex blocklist above. Normalise here so the blocklist
// sees a bare hostname and any IPv4-mapped address resurfaces in dotted form
// for the existing IPv4 regexes.
function normalizeHostForSSRF(rawHost) {
  if (typeof rawHost !== 'string' || !rawHost) return '';
  let host = rawHost.replace(/^\[|\]$/g, '');
  // IPv4-mapped IPv6: `::ffff:XXXX:YYYY` where XXXX,YYYY are 16-bit hex groups.
  // Decode to a.b.c.d so /^127\./ etc still fire. Tolerate Node's short-form
  // omission of leading zeros within each group ("a00" instead of "0a00").
  const m = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(host);
  if (m) {
    const hi = parseInt(m[1], 16);
    const lo = parseInt(m[2], 16);
    const a = (hi >> 8) & 0xff, b = hi & 0xff, c = (lo >> 8) & 0xff, d = lo & 0xff;
    return `${a}.${b}.${c}.${d}`;
  }
  return host;
}

const IMPORT_MAX_BYTES = 5 * 1024 * 1024;

// GET /api/anthropic/status — drives the engine-attribution UX on the import
// view. enabled=true unlocks the "Smart parsing" hint + any-host fetching;
// enabled=false shows the "Basic mode — only Time Out is supported" hint and
// keeps the request gated to hosts in WEBSITE_IMPORT_ADAPTERS.
app.get('/api/anthropic/status', auth, async (req, res) => {
  const key = await getAnthropicKey(req.user.id);
  res.json({ enabled: !!key, mode: key ? 'smart' : 'basic' });
});

// Per-endpoint rate limit — each LLM-path import call hits Anthropic and
// burns ~$0.002. The global 200/min/user cap is too permissive: 200 LLM
// calls/min ≈ $24/hr per user, and env-key fallback would amortise the
// hit across all users. Cap at 10/min/user, generous enough for a real
// session of paste-paste-paste imports but tight enough that runaway
// behaviour is bounded. Bypassed in test mode like the other limits.
app.use('/api/import/website', rateLimit({ windowMs: 60 * 1000, max: isTest ? 10000 : 10 }));

app.post('/api/import/website', auth, async (req, res) => {
  const _t0 = Date.now();
  let host = '(unknown)';
  try {
    const { url } = req.body || {};
    if (!url || typeof url !== 'string') {
      return res.status(400).json({ error: 'invalid_url' });
    }
    let parsed;
    try { parsed = new URL(url); } catch {
      return res.status(400).json({ error: 'invalid_url' });
    }
    if (parsed.protocol !== 'https:') {
      return res.status(400).json({ error: 'invalid_url' });
    }
    host = parsed.hostname;
    const ssrfTarget = normalizeHostForSSRF(host);
    if (SSRF_BLOCK.some(re => re.test(ssrfTarget))) {
      return res.status(400).json({ error: 'invalid_url' });
    }
    // DNS-rebinding defence: resolve the hostname to an IP and re-apply the
    // SSRF blocklist. A CNAME chain that ultimately points to 169.254.169.254
    // or an RFC-1918 address would pass the string check above but fail here.
    try {
      const { address } = await dns.lookup(host);
      const resolvedTarget = normalizeHostForSSRF(address);
      if (SSRF_BLOCK.some(re => re.test(resolvedTarget))) {
        return res.status(400).json({ error: 'invalid_url' });
      }
    } catch {
      // DNS resolution failure = hostname doesn't exist; block it.
      return res.status(400).json({ error: 'invalid_url' });
    }
    // Adapter selection: prefer LLM when an Anthropic key is configured
    // (works on any host that passes the SSRF guard); otherwise fall back
    // to the per-site regex registry (currently just Time Out). The
    // host_not_supported error only fires when there's NO LLM key AND
    // the host isn't in the registry.
    const apiKey = await getAnthropicKey(req.user.id);
    const regexAdapter = WEBSITE_IMPORT_ADAPTERS.find(a => a.pattern.test(host));
    if (!apiKey && !regexAdapter) {
      return res.status(400).json({ error: 'host_not_supported' });
    }
    const engine = apiKey ? 'llm' : 'regex';
    let fetchRes;
    try {
      fetchRes = await fetch(url, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; Oikumene/1.0; +https://history-map.onrender.com)',
          'Accept': 'text/html',
        },
        // SSRF defence: reject redirects so a 301/302 from an attacker-
        // controlled host cannot be used to bounce us into a private/metadata
        // IP that already passed our SSRF_BLOCK hostname check.
        redirect: 'error',
        signal: AbortSignal.timeout(10000),
      });
    } catch {
      const ms = Date.now() - _t0;
      log('warn', 'import_website_call', { userId: req.user.id, host, engine, status: 'fetch_failed', errorType: 'network', ms });
      return res.status(502).json({ error: 'fetch_failed' });
    }
    if (!fetchRes.ok) {
      const ms = Date.now() - _t0;
      log('warn', 'import_website_call', { userId: req.user.id, host, engine, status: 'fetch_failed', errorType: `http_${fetchRes.status}`, ms });
      // Encode HTTP status into the error string so the existing api() error
      // contract (single `error` string field) carries it to the client toast.
      // Time Out reshuffles URLs frequently and a 404 should read as "page
      // moved", not generic "we couldn't reach the site".
      return res.status(502).json({ error: `fetch_failed_${fetchRes.status}` });
    }
    const buf = await fetchRes.arrayBuffer();
    if (buf.byteLength > IMPORT_MAX_BYTES) {
      const ms = Date.now() - _t0;
      log('warn', 'import_website_call', { userId: req.user.id, host, engine, status: 'response_too_large', errorType: 'too_large', ms });
      return res.status(413).json({ error: 'response_too_large' });
    }
    const html = Buffer.from(buf).toString('utf-8');

    let city, articleTitle, venues, sourceName, usage = null;
    if (engine === 'llm') {
      try {
        const parsed = await parseVenuesLLM(html, url, apiKey);
        city = parsed.city;
        articleTitle = parsed.articleTitle;
        venues = parsed.venues;
        usage = parsed.usage;
        sourceName = 'llm';
      } catch (err) {
        const ms = Date.now() - _t0;
        log('warn', 'import_website_call', { userId: req.user.id, host, engine, status: 'llm_error', errorType: err.code || 'llm_error', ms });
        // Sanitised single-string error contract — never leak upstream body.
        const msg = err.code === 'llm_error_401' ? 'llm_key_rejected'
          : err.code === 'llm_error_429' ? 'llm_rate_limited'
          : err.code === 'llm_no_tool_use' ? 'llm_no_output'
          : err.code === 'llm_sdk_missing' ? 'llm_unavailable'
          : 'llm_error';
        return res.status(err.status || 502).json({ error: msg });
      }
    } else {
      const parsed = regexAdapter.parse(html, url);
      city = parsed.city;
      articleTitle = parsed.articleTitle;
      venues = parsed.venues;
      sourceName = regexAdapter.name;
    }

    const ms = Date.now() - _t0;
    if (venues.length === 0) {
      log('warn', 'import_parse_zero', { userId: req.user.id, host, engine, source: sourceName });
    }
    log('info', 'import_website_call', {
      userId: req.user.id, host, engine, status: 'success', venueCount: venues.length, source: sourceName, ms,
      ...(usage ? { inputTokens: usage.input_tokens || 0, outputTokens: usage.output_tokens || 0, cacheReadTokens: usage.cache_read_input_tokens || 0 } : {}),
    });
    res.json({ city, articleTitle, source: sourceName, engine, venues });
  } catch (err) {
    const ms = Date.now() - _t0;
    log('warn', 'import_website_call', { userId: req.user.id, host, status: 'error', errorType: 'internal', ms });
    res.status(500).json({ error: 'internal_error' });
  }
});

// ── Collections CRUD ─────────────────────────────────────
app.get('/api/collections', auth, async (req, res) => {
  const cols = await db.collections.find({ userId: req.user.id });
  res.json(cols);
});

const COLLECTION_FIELDS = ['name', 'emoji', 'description', 'totalItems'];
const MAX_COLLECTIONS_PER_BULK = 500;
function sanitizeCollectionUpdate(body) {
  const out = {};
  if (!body || typeof body !== 'object') return out;
  for (const k of COLLECTION_FIELDS) {
    if (body[k] === undefined) continue;
    if (typeof body[k] === 'string' && body[k].length > 5000) continue;
    if (k === 'totalItems') {
      const n = parseInt(body[k], 10);
      if (Number.isFinite(n) && n >= 0 && n <= 1e6) out[k] = n;
      continue;
    }
    if (k === 'emoji') {
      // Rendered into client HTML — keep short and free of angle brackets (defense-in-depth with client esc()).
      if (typeof body[k] !== 'string' || body[k].length > 16 || /[<>]/.test(body[k])) continue;
    }
    out[k] = body[k];
  }
  return out;
}

app.post('/api/collections', auth, async (req, res) => {
  try {
    const col = { ...sanitizeCollectionUpdate(req.body), userId: req.user.id };
    if (!col.name) return res.status(400).json({ error: 'name required' });
    const saved = await db.collections.insert(col);
    log('info', 'db_insert', { table: 'collections', id: saved._id, name: saved.name, userId: req.user.id });
    res.json(saved);
  } catch (err) {
    log('error', 'db_insert_error', { table: 'collections', error: err.message, userId: req.user.id });
    res.status(500).json({ error: 'Failed to create collection' });
  }
});

app.put('/api/collections/:id', auth, async (req, res) => {
  const updates = sanitizeCollectionUpdate(req.body);
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

// Bulk import collections — sanitized + length-capped to prevent unbounded inserts.
app.post('/api/collections/bulk', auth, async (req, res) => {
  const { collections: cols } = req.body;
  if (!Array.isArray(cols)) return res.status(400).json({ error: 'Expected array' });
  if (cols.length > MAX_COLLECTIONS_PER_BULK) return res.status(400).json({ error: `Too many collections (max ${MAX_COLLECTIONS_PER_BULK})` });
  const toInsert = cols.map(c => ({ ...sanitizeCollectionUpdate(c), userId: req.user.id })).filter(c => c.name);
  const saved = await db.collections.insert(toInsert);
  log('info', 'db_bulk_insert', { table: 'collections', count: saved.length, userId: req.user.id });
  res.json(saved);
});

// ── Transits ─────────────────────────────────────────────
const TRANSIT_MODES = ['flight', 'car', 'train', 'ferry'];
const TRANSIT_STRING_FIELDS = ['date', 'fromName', 'fromLocationId', 'fromIata', 'toName', 'toLocationId', 'toIata', 'flightNumber', 'airline', 'aircraft', 'seat', 'tripId', 'notes'];
const MAX_TRANSITS_PER_BULK = 1000;

function sanitizeTransitUpdate(body) {
  const out = {};
  if (!body || typeof body !== 'object') return out;
  // Allow explicit clearing of tripId (empty string or null → null)
  if (body && (body.tripId === '' || body.tripId === null)) out.tripId = null;
  if (TRANSIT_MODES.includes(body.mode)) out.mode = body.mode;
  for (const k of ['fromLat', 'toLat']) {
    if (body[k] !== undefined && body[k] !== null) {
      const n = parseFloat(body[k]);
      if (Number.isFinite(n) && Math.abs(n) <= 90) out[k] = n;
    }
  }
  for (const k of ['fromLng', 'toLng']) {
    if (body[k] !== undefined && body[k] !== null) {
      const n = parseFloat(body[k]);
      if (Number.isFinite(n) && Math.abs(n) <= 180) out[k] = n;
    }
  }
  for (const k of ['distanceKm', 'durationMin']) {
    if (body[k] !== undefined && body[k] !== null) {
      const n = parseFloat(body[k]);
      if (Number.isFinite(n) && n >= 0 && n <= 1e6) out[k] = n;
    }
  }
  for (const k of TRANSIT_STRING_FIELDS) {
    const v = body[k];
    if (typeof v === 'string' && v.length > 0 && v.length <= 5000) out[k] = v;
  }
  return out;
}

app.get('/api/transits', auth, async (req, res) => {
  const transits = await db.transits.find({ userId: req.user.id });
  res.json(transits);
});

app.post('/api/transits', auth, async (req, res) => {
  try {
    const t = { ...sanitizeTransitUpdate(req.body), userId: req.user.id };
    if (!t.mode) return res.status(400).json({ error: 'mode required (flight|car|train|ferry)' });
    if (typeof t.fromLat !== 'number' || typeof t.fromLng !== 'number' || typeof t.toLat !== 'number' || typeof t.toLng !== 'number') {
      return res.status(400).json({ error: 'from/to coordinates required and must be valid' });
    }
    const saved = await db.transits.insert(t);
    log('info', 'db_insert', { table: 'transits', id: saved._id, mode: saved.mode, userId: req.user.id });
    res.json(saved);
  } catch (err) {
    log('error', 'db_insert_error', { table: 'transits', error: err.message, userId: req.user.id });
    res.status(500).json({ error: 'Failed to create transit' });
  }
});

app.put('/api/transits/:id', auth, async (req, res) => {
  const updates = sanitizeTransitUpdate(req.body);
  const count = await db.transits.update({ _id: req.params.id, userId: req.user.id }, { $set: updates });
  if (count === 0) return res.status(404).json({ error: 'Not found' });
  const updated = await db.transits.findOne({ _id: req.params.id });
  log('info', 'db_update', { table: 'transits', id: req.params.id, fields: Object.keys(updates), userId: req.user.id });
  res.json(updated);
});

app.delete('/api/transits/:id', auth, async (req, res) => {
  const count = await db.transits.remove({ _id: req.params.id, userId: req.user.id });
  if (count === 0) return res.status(404).json({ error: 'Not found' });
  log('info', 'db_remove', { table: 'transits', id: req.params.id, userId: req.user.id });
  res.json({ ok: true });
});

app.post('/api/transits/bulk', auth, async (req, res) => {
  const { transits } = req.body;
  if (!Array.isArray(transits)) return res.status(400).json({ error: 'Expected array' });
  if (transits.length > MAX_TRANSITS_PER_BULK) return res.status(400).json({ error: `Too many transits (max ${MAX_TRANSITS_PER_BULK})` });
  const toInsert = transits
    .map(t => ({ ...sanitizeTransitUpdate(t), userId: req.user.id }))
    .filter(t => t.mode && typeof t.fromLat === 'number' && typeof t.fromLng === 'number' && typeof t.toLat === 'number' && typeof t.toLng === 'number');
  const saved = toInsert.length ? await db.transits.insert(toInsert) : [];
  log('info', 'db_bulk_insert', { table: 'transits', count: Array.isArray(saved) ? saved.length : 0, userId: req.user.id });
  res.json(Array.isArray(saved) ? saved : [saved]);
});

// ── Admin-1 boundaries proxy (Natural Earth, cached) ─────
const ADMIN1_CACHE = path.join(__dirname, '..', 'data', 'admin1-simplified.json');
// Try 10m first via jsdelivr (faster CDN), fall back to 50m from GitHub
const NE_ADMIN1_URLS = [
  'https://cdn.jsdelivr.net/gh/nvkelso/natural-earth-vector@master/geojson/ne_50m_admin_1_states_provinces.geojson',
  'https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_50m_admin_1_states_provinces.geojson',
];

app.get('/api/admin1-boundaries', auth, async (req, res) => {
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
  res.json({
    googlePlacesKey: user?.googlePlacesKey ? '••••' + user.googlePlacesKey.slice(-4) : null,
    anthropicKey: user?.anthropicKey ? '••••' + user.anthropicKey.slice(-4) : null,
  });
});

app.put('/api/settings', auth, async (req, res) => {
  const { googlePlacesKey, anthropicKey } = req.body;
  for (const [k, v] of [['googlePlacesKey', googlePlacesKey], ['anthropicKey', anthropicKey]]) {
    if (v !== undefined && v !== null && (typeof v !== 'string' || v.length > 256)) {
      return res.status(400).json({ error: `${k}: must be null or a string ≤ 256 characters` });
    }
  }
  const updates = {};
  if (googlePlacesKey !== undefined) updates.googlePlacesKey = googlePlacesKey || null;
  if (anthropicKey !== undefined) updates.anthropicKey = anthropicKey || null;
  await db.users.update({ _id: req.user.id }, { $set: updates });
  audit('settings_update', { fields: Object.keys(updates) }, req);
  res.json({ ok: true });
});

// ── User's own backup list ───────────────────────────────
app.get('/api/my-backups', auth, async (req, res) => {
  try {
    if (!fs.existsSync(BACKUP_DIR)) return res.json([]);
    const userBackups = fs.readdirSync(BACKUP_DIR)
      .filter(f => f.startsWith(req.user.id + '_') && f.endsWith('.json'))
      .sort().reverse();
    const list = userBackups.map(name => {
      const stats = fs.statSync(path.join(BACKUP_DIR, name));
      const dateMatch = name.match(/_(\d{4}-\d{2}-\d{2})\.json$/);
      return { name, date: dateMatch ? dateMatch[1] : '', size: stats.size };
    });
    res.json(list);
  } catch (err) {
    log('error', 'my_backups_list_failed', { userId: req.user.id, error: err.message });
    res.status(500).json({ error: 'Internal error' });
  }
});

// ── User's own latest backup ─────────────────────────────
app.get('/api/my-backup', auth, async (req, res) => {
  try {
    if (!fs.existsSync(BACKUP_DIR)) return res.status(404).json({ error: 'No backups yet' });
    const userBackups = fs.readdirSync(BACKUP_DIR)
      .filter(f => f.startsWith(req.user.id + '_') && f.endsWith('.json'))
      .sort().reverse();
    if (userBackups.length === 0) return res.status(404).json({ error: 'No backups for your account yet' });
    res.download(path.join(BACKUP_DIR, userBackups[0]));
  } catch (err) {
    log('error', 'my_backup_download_failed', { userId: req.user.id, error: err.message });
    res.status(500).json({ error: 'Internal error' });
  }
});

app.get('/api/my-backup/:filename', auth, (req, res) => {
  const filename = path.basename(req.params.filename);
  if (!filename.startsWith(req.user.id + '_') || !filename.endsWith('.json')) {
    return res.status(403).json({ error: 'Access denied' });
  }
  const filePath = path.resolve(BACKUP_DIR, filename);
  const normalizedDir = path.resolve(BACKUP_DIR);
  if (!filePath.startsWith(normalizedDir + path.sep)) return res.status(403).json({ error: 'Invalid path' });
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Backup not found' });
  res.download(filePath);
});

// ── Google Places API (New) — proxied, key never in URL ──
async function getPlacesKey(userId) {
  const user = await db.users.findOne({ _id: userId });
  return user?.googlePlacesKey || GOOGLE_PLACES_KEY || '';
}

// ── Anthropic API — key per user, env fallback ────────────
async function getAnthropicKey(userId) {
  const user = await db.users.findOne({ _id: userId });
  return user?.anthropicKey || ANTHROPIC_API_KEY || '';
}

// Price level enum → integer (Places API New returns string enums)
const PRICE_LEVEL_MAP = {
  PRICE_LEVEL_FREE: 0,
  PRICE_LEVEL_INEXPENSIVE: 1,
  PRICE_LEVEL_MODERATE: 2,
  PRICE_LEVEL_EXPENSIVE: 3,
  PRICE_LEVEL_VERY_EXPENSIVE: 4,
};
// PRICE_LEVEL_UNSPECIFIED, undefined, or any unknown enum → null
function mapPriceLevel(val) {
  if (val == null) return null;
  return PRICE_LEVEL_MAP[val] ?? null;
}

// Fetch place details by Place ID (Places API New — GET /v1/places/{id})
async function fetchPlaceByPlaceId(placeId, placesKey, sessionToken) {
  let url = `https://places.googleapis.com/v1/places/${encodeURIComponent(placeId)}`;
  if (sessionToken && typeof sessionToken === 'string' && sessionToken.length <= 100) {
    url += `?sessionToken=${encodeURIComponent(sessionToken)}`;
  }
  const _t0 = Date.now();
  const response = await fetch(url, {
    method: 'GET',
    headers: {
      'X-Goog-Api-Key': placesKey,
      'X-Goog-FieldMask': 'id,displayName,formattedAddress,location,rating,priceLevel,userRatingCount',
    },
  });
  const data = await response.json();
  const ms = Date.now() - _t0;
  if (response.ok && data.id) {
    return {
      found: true,
      rating: data.rating ?? null,
      price_level: mapPriceLevel(data.priceLevel),
      formatted_address: data.formattedAddress ?? '',
      place_id: data.id || placeId,
      user_ratings_total: data.userRatingCount ?? 0,
      lat: data.location?.latitude,
      lng: data.location?.longitude,
      ms,
      apiStatus: 'OK',
    };
  }
  // Structured error: { error: { code, message, status } }
  const apiStatus = data.error?.status || `HTTP_${response.status}`;
  return { found: false, ms, apiStatus };
}

// Fetch place by text search (Places API New — POST /v1/places:searchText)
// The `fields` param is accepted for signature compatibility but ignored;
// we always send a sensible default FieldMask covering all downstream-needed fields.
async function fetchPlaceByText(name, lat, lng, placesKey, fields) { // eslint-disable-line no-unused-vars
  const url = 'https://places.googleapis.com/v1/places:searchText';
  const body = { textQuery: name };
  if (lat && lng) {
    body.locationBias = {
      circle: {
        center: { latitude: parseFloat(lat), longitude: parseFloat(lng) },
        radius: 50000,
      },
    };
  }
  const _t0 = Date.now();
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'X-Goog-Api-Key': placesKey,
      'X-Goog-FieldMask': 'places.id,places.displayName,places.formattedAddress,places.location,places.rating,places.priceLevel,places.userRatingCount',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  const data = await response.json();
  const ms = Date.now() - _t0;
  if (response.ok && data.places?.length) {
    const p = data.places[0];
    return {
      found: true,
      rating: p.rating ?? null,
      price_level: mapPriceLevel(p.priceLevel),
      formatted_address: p.formattedAddress ?? '',
      place_id: p.id ?? '',
      user_ratings_total: p.userRatingCount ?? 0,
      lat: p.location?.latitude,
      lng: p.location?.longitude,
      ms,
      apiStatus: 'OK',
    };
  }
  // Zero results: HTTP 200 + empty/missing places array — not an error
  if (response.ok) return { found: false, ms, apiStatus: 'ZERO_RESULTS' };
  // API error
  const apiStatus = data.error?.status || `HTTP_${response.status}`;
  return { found: false, ms, apiStatus };
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
    const reqBody = { textQuery: q };
    if (lat !== undefined && lng !== undefined) {
      const fLat = parseFloat(lat);
      const fLng = parseFloat(lng);
      if (!Number.isFinite(fLat) || !Number.isFinite(fLng) || Math.abs(fLat) > 90 || Math.abs(fLng) > 180) {
        return res.status(400).json({ error: 'Invalid coordinates' });
      }
      reqBody.locationBias = {
        circle: {
          center: { latitude: fLat, longitude: fLng },
          radius: 50000,
        },
      };
    }
    const _t0 = Date.now();
    const response = await fetch('https://places.googleapis.com/v1/places:searchText', {
      method: 'POST',
      headers: {
        'X-Goog-Api-Key': placesKey,
        'X-Goog-FieldMask': 'places.id,places.displayName,places.formattedAddress,places.location,places.rating,places.priceLevel,places.userRatingCount,places.types',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(reqBody),
    });
    const data = await response.json();
    const ms = Date.now() - _t0;
    const places = data.places || [];
    log('info', 'places_api_call', { endpoint: 'searchText', query: q, httpStatus: response.status, results: places.length, ms, userId: req.user.id });
    if (!response.ok) {
      const apiStatus = data.error?.status || `HTTP_${response.status}`;
      log('warn', 'places_api_error', { endpoint: 'searchText', status: apiStatus, userId: req.user.id });
      return res.status(502).json({ error: 'Places API: ' + apiStatus });
    }
    res.json(places.slice(0, 10).map(p => ({
      name: p.displayName?.text || '',
      address: p.formattedAddress || '',
      lat: p.location?.latitude,
      lng: p.location?.longitude,
      googleRating: p.rating || null,
      priceLevel: mapPriceLevel(p.priceLevel),
      placeId: p.id || '',
      types: p.types || [],
      userRatingsTotal: p.userRatingCount || 0,
    })));
  } catch (err) {
    log('error', 'places_search_failed', { userId: req.user.id, error: err.message });
    res.status(500).json({ error: 'Internal error' });
  }
});

// Autocomplete (Essentials tier) — way cheaper than Text Search Pro for live
// typeahead. Pair with sessionToken: bundle all autocomplete calls + the
// final Place Details lookup as ONE session billing event.
app.post('/api/places/autocomplete', auth, async (req, res) => {
  const placesKey = await getPlacesKey(req.user.id);
  if (!placesKey) return res.status(501).json({ error: 'Google Places API not configured' });
  try {
    const { input, lat, lng, sessionToken } = req.body || {};
    if (!input || typeof input !== 'string' || input.length < 1) return res.status(400).json({ error: 'Input required' });
    if (input.length > 200) return res.status(400).json({ error: 'Input too long' });

    const body = { input };
    if (sessionToken && typeof sessionToken === 'string' && sessionToken.length <= 100) {
      body.sessionToken = sessionToken;
    }
    if (lat !== undefined && lng !== undefined) {
      const fLat = parseFloat(lat);
      const fLng = parseFloat(lng);
      if (!Number.isFinite(fLat) || !Number.isFinite(fLng) || Math.abs(fLat) > 90 || Math.abs(fLng) > 180) {
        return res.status(400).json({ error: 'Invalid coordinates' });
      }
      body.locationBias = {
        circle: { center: { latitude: fLat, longitude: fLng }, radius: 50000 },
      };
    }
    const _t0 = Date.now();
    const response = await fetch('https://places.googleapis.com/v1/places:autocomplete', {
      method: 'POST',
      headers: {
        'X-Goog-Api-Key': placesKey,
        'X-Goog-FieldMask': 'suggestions.placePrediction.placeId,suggestions.placePrediction.text,suggestions.placePrediction.structuredFormat',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });
    const data = await response.json();
    const ms = Date.now() - _t0;
    log('info', 'places_api_call', { endpoint: 'autocomplete', input: input.slice(0, 50), hasSession: !!sessionToken, httpStatus: response.status, results: (data.suggestions || []).length, ms, userId: req.user.id });
    if (!response.ok) {
      const apiStatus = data.error?.status || `HTTP_${response.status}`;
      log('warn', 'places_api_error', { endpoint: 'autocomplete', status: apiStatus, userId: req.user.id });
      return res.status(502).json({ error: 'Places API: ' + apiStatus });
    }
    const suggestions = (data.suggestions || [])
      .map(s => s.placePrediction)
      .filter(p => p && p.placeId)
      .slice(0, 10)
      .map(p => ({
        placeId: p.placeId,
        mainText: p.structuredFormat?.mainText?.text || p.text?.text || '',
        secondaryText: p.structuredFormat?.secondaryText?.text || '',
        fullText: p.text?.text || '',
      }));
    res.json(suggestions);
  } catch (err) {
    log('error', 'places_autocomplete_failed', { userId: req.user.id, error: err.message });
    res.status(500).json({ error: 'Internal error' });
  }
});

app.post('/api/places/sync', auth, async (req, res) => {
  const placesKey = await getPlacesKey(req.user.id);
  if (!placesKey) return res.status(501).json({ error: 'Google Places API not configured' });
  try {
    const { name, lat, lng, placeId, sessionToken } = req.body;
    if (!name && !placeId) return res.status(400).json({ error: 'Name or placeId required' });

    // Prefer Place ID lookup (exact match, same cost)
    const result = placeId
      ? await fetchPlaceByPlaceId(placeId, placesKey, sessionToken)
      : await fetchPlaceByText(name, lat, lng, placesKey);

    log('info', 'places_api_call', { endpoint: placeId ? 'placeDetails' : 'searchText', input: placeId || name, found: result.found, ms: result.ms, userId: req.user.id });

    if (!result.found) return res.json({ found: false });
    res.json({
      found: true,
      googleRating: result.rating || null,
      priceLevel: result.price_level || null,
      address: result.formatted_address || '',
      placeId: result.place_id || '',
      userRatingsTotal: result.user_ratings_total || 0,
      lat: result.lat,
      lng: result.lng,
    });
  } catch (err) {
    log('error', 'places_sync_failed', { userId: req.user.id, error: err.message });
    res.status(500).json({ error: 'Internal error' });
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
    let found = 0, notFound = 0, errors = 0, byPlaceId = 0;
    for (const loc of batch) {
      try {
        // Prefer Place ID lookup when available (exact match, same cost)
        const hasPlaceId = loc.placeId || loc._googlePlaceId;
        const result = hasPlaceId
          ? await fetchPlaceByPlaceId(hasPlaceId, placesKey)
          : await fetchPlaceByText(loc.name, loc.lat, loc.lng, placesKey, 'rating,price_level,formatted_address,place_id,user_ratings_total');
        if (hasPlaceId) byPlaceId++;

        if (result.found) {
          const updates = { _googleSyncedAt: new Date().toISOString() };
          if (result.rating) updates.googleRating = result.rating;
          if (result.price_level != null) updates.priceLevel = result.price_level;
          if (result.formatted_address && !loc.address) updates.address = result.formatted_address;
          if (result.place_id) updates._googlePlaceId = result.place_id;
          await db.locations.update({ _id: loc.id, userId: req.user.id }, { $set: updates });
          results.push({ id: loc.id, ...updates, found: true });
          found++;
          log('debug', 'bulk_sync_item', { locId: loc.id, name: loc.name, found: true, rating: result.rating, via: hasPlaceId ? 'placeId' : 'text', ms: result.ms });
        } else {
          await db.locations.update({ _id: loc.id, userId: req.user.id }, { $set: { _googleSyncedAt: new Date().toISOString() } });
          results.push({ id: loc.id, found: false });
          notFound++;
          log('debug', 'bulk_sync_item', { locId: loc.id, name: loc.name, found: false, status: result.apiStatus, via: hasPlaceId ? 'placeId' : 'text', ms: result.ms });
        }
      } catch (err) {
        results.push({ id: loc.id, found: false });
        errors++;
        log('warn', 'bulk_sync_item_error', { locId: loc.id, name: loc.name, error: err.message });
      }
    }
    log('info', 'bulk_sync_done', { count: batch.length, found, notFound, errors, byPlaceId, byText: batch.length - byPlaceId, ms: Date.now() - batchStart, userId: req.user.id });
    res.json(results);
  } catch (err) {
    log('error', 'places_bulk_sync_failed', { userId: req.user.id, error: err.message });
    res.status(500).json({ error: 'Internal error' });
  }
});

// Internal category → Google Places (New) included type.
// Only categories with a clean Google type are queryable.
const CATEGORY_TO_PLACE_TYPE = {
  restaurant: 'restaurant',
  hotel: 'hotel',
  bar: 'bar',
  club: 'night_club',
  monument: 'tourist_attraction',
  museum: 'museum',
  park: 'park',
  stadium: 'stadium',
  shopping: 'shopping_mall',
  cafe: 'cafe',
};

// Per-endpoint rate limit for discover — Google Places Text Search Pro is
// ~$0.032/call; 200/min global = ~$384/hr worst case per user. Cap at
// 30/min/user — generous for genuine browsing, tight enough to bound cost.
app.use('/api/places/discover', rateLimit({ windowMs: 60 * 1000, max: isTest ? 10000 : 30 }));

app.post('/api/places/discover', auth, async (req, res) => {
  const placesKey = await getPlacesKey(req.user.id);
  if (!placesKey) return res.status(501).json({ error: 'Google Places API not configured' });
  try {
    const { lat, lng, category, radius, minRatings } = req.body;
    const fLat = parseFloat(lat);
    const fLng = parseFloat(lng);
    if (!Number.isFinite(fLat) || !Number.isFinite(fLng) || Math.abs(fLat) > 90 || Math.abs(fLng) > 180) {
      return res.status(400).json({ error: 'Invalid coordinates' });
    }
    const placeType = CATEGORY_TO_PLACE_TYPE[category];
    if (!placeType) return res.status(400).json({ error: 'Unsupported category for discovery' });
    const fRadius = Math.min(Math.max(parseInt(radius, 10) || 5000, 100), 50000);
    const fMinRatings = Math.max(parseInt(minRatings, 10) || 1000, 0);

    const body = {
      textQuery: `top rated ${category}`,
      includedType: placeType,
      locationBias: {
        circle: { center: { latitude: fLat, longitude: fLng }, radius: fRadius },
      },
    };
    const _t0 = Date.now();
    const response = await fetch('https://places.googleapis.com/v1/places:searchText', {
      method: 'POST',
      headers: {
        'X-Goog-Api-Key': placesKey,
        'X-Goog-FieldMask': 'places.id,places.displayName,places.formattedAddress,places.location,places.rating,places.priceLevel,places.userRatingCount,places.types',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });
    const data = await response.json();
    const ms = Date.now() - _t0;
    const allPlaces = data.places || [];
    log('info', 'places_api_call', { endpoint: 'discover', category, lat: fLat, lng: fLng, radius: fRadius, minRatings: fMinRatings, httpStatus: response.status, results: allPlaces.length, ms, userId: req.user.id });
    if (!response.ok) {
      const apiStatus = data.error?.status || `HTTP_${response.status}`;
      log('warn', 'places_api_error', { endpoint: 'discover', status: apiStatus, userId: req.user.id });
      return res.status(502).json({ error: 'Places API: ' + apiStatus });
    }
    const filtered = allPlaces
      .filter(p => (p.userRatingCount || 0) >= fMinRatings)
      .sort((a, b) => (b.userRatingCount || 0) - (a.userRatingCount || 0) || (b.rating || 0) - (a.rating || 0))
      .slice(0, 20)
      .map(p => ({
        name: p.displayName?.text || '',
        address: p.formattedAddress || '',
        lat: p.location?.latitude,
        lng: p.location?.longitude,
        googleRating: p.rating || null,
        priceLevel: mapPriceLevel(p.priceLevel),
        placeId: p.id || '',
        types: p.types || [],
        userRatingsTotal: p.userRatingCount || 0,
      }));
    res.json(filtered);
  } catch (err) {
    log('error', 'places_discover_failed', { userId: req.user.id, error: err.message });
    res.status(500).json({ error: 'Internal error' });
  }
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
      const backupFile = path.join(BACKUP_DIR, `${userId}_${date}.json`);

      // Skip if today's backup already exists
      if (fs.existsSync(backupFile)) continue;

      const [locations, trips, collections, transits] = await Promise.all([
        db.locations.find({ userId }),
        db.trips.find({ userId }),
        db.collections.find({ userId }),
        db.transits.find({ userId }),
      ]);

      const backup = {
        exportDate: new Date().toISOString(),
        username: user.username,
        locations, trips, collections, transits,
      };

      fs.writeFileSync(backupFile, JSON.stringify(backup));
      log('info', 'backup_created', { username, locations: locations.length, trips: trips.length, collections: collections.length, transits: transits.length });

      // Prune old backups for this user
      const userBackups = fs.readdirSync(BACKUP_DIR)
        .filter(f => f.startsWith(userId + '_') && f.endsWith('.json'))
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

// ── Terminal error handler ───────────────────────────────
app.use((err, req, res, next) => {
  log('error', 'unhandled_route_error', { method: req.method, path: req.path, error: err.message });
  res.status(500).json({ error: 'Internal server error' });
});

// ── Catch-all for SPA ────────────────────────────────────
// MUST be the last route — anything defined after this is dead code.
// Same serveIndex handler as `/` so SPA-routed URLs get the CSP nonce too.
app.get('*', serveIndex);

if (require.main === module) {
  app.listen(PORT, () => {
    log('info', 'server_start', { port: PORT });
    // Run backup on startup, then every 24h
    runBackup();
    setInterval(runBackup, 24 * 60 * 60 * 1000);
  });
}

module.exports = app;
