const express = require('express');
const path = require('path');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'history-map-dev-secret-change-me';

// Middleware
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Rate limiting
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, max: 15 }));
app.use('/api', rateLimit({ windowMs: 60 * 1000, max: 200 }));

// Static files
app.use(express.static(path.join(__dirname, '..', 'public')));

// ── Auth middleware ──────────────────────────────────────
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

    const existing = await db.users.findOne({ username });
    if (existing) return res.status(409).json({ error: 'Username taken' });

    const hash = await bcrypt.hash(password, 10);
    const user = await db.users.insert({ username, password: hash, createdAt: new Date().toISOString() });
    const token = jwt.sign({ id: user._id, username }, JWT_SECRET, { expiresIn: '90d' });
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
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user._id, username }, JWT_SECRET, { expiresIn: '90d' });
    res.json({ token, username });
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/auth/me', auth, (req, res) => {
  res.json({ username: req.user.username });
});

// ── Locations CRUD ───────────────────────────────────────
app.get('/api/locations', auth, async (req, res) => {
  const locs = await db.locations.find({ userId: req.user.id });
  res.json(locs);
});

app.post('/api/locations', auth, async (req, res) => {
  const loc = { ...req.body, userId: req.user.id, updatedAt: new Date().toISOString() };
  delete loc._id; // let nedb assign
  const saved = await db.locations.insert(loc);
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
  res.json(updated);
});

app.delete('/api/locations/:id', auth, async (req, res) => {
  const count = await db.locations.remove({ _id: req.params.id, userId: req.user.id });
  if (count === 0) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// Bulk import
app.post('/api/locations/bulk', auth, async (req, res) => {
  const { locations: locs } = req.body;
  if (!Array.isArray(locs)) return res.status(400).json({ error: 'Expected array' });
  const toInsert = locs.map(l => ({ ...l, userId: req.user.id, updatedAt: new Date().toISOString() }));
  toInsert.forEach(l => delete l._id);
  const saved = await db.locations.insert(toInsert);
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
  res.json(saved);
});

app.put('/api/trips/:id', auth, async (req, res) => {
  const updates = { ...req.body };
  delete updates._id;
  delete updates.userId;
  await db.trips.update({ _id: req.params.id, userId: req.user.id }, { $set: updates });
  const updated = await db.trips.findOne({ _id: req.params.id });
  res.json(updated);
});

app.delete('/api/trips/:id', auth, async (req, res) => {
  await db.trips.remove({ _id: req.params.id, userId: req.user.id });
  res.json({ ok: true });
});

// ── Catch-all for SPA ────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`History Map server running on port ${PORT}`);
});
