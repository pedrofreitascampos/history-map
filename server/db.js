const Datastore = require('nedb-promises');
const path = require('path');

// Use /data on Render (persistent disk mount), local ./data for dev, override with DATA_DIR for tests
const dataDir = process.env.DATA_DIR || (process.env.NODE_ENV === 'production' ? '/data' : path.join(__dirname, '..', 'data'));

const users = Datastore.create({ filename: path.join(dataDir, 'users.db'), autoload: true });
const locations = Datastore.create({ filename: path.join(dataDir, 'locations.db'), autoload: true });
const trips = Datastore.create({ filename: path.join(dataDir, 'trips.db'), autoload: true });
const collections = Datastore.create({ filename: path.join(dataDir, 'collections.db'), autoload: true });

const auditLog = Datastore.create({ filename: path.join(dataDir, 'audit.db'), autoload: true });

users.ensureIndex({ fieldName: 'username', unique: true });

module.exports = { users, locations, trips, collections, auditLog };
