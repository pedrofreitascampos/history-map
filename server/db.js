const Datastore = require('nedb-promises');
const path = require('path');

const dataDir = path.join(__dirname, '..', 'data');

const users = Datastore.create({ filename: path.join(dataDir, 'users.db'), autoload: true });
const locations = Datastore.create({ filename: path.join(dataDir, 'locations.db'), autoload: true });
const trips = Datastore.create({ filename: path.join(dataDir, 'trips.db'), autoload: true });
const collections = Datastore.create({ filename: path.join(dataDir, 'collections.db'), autoload: true });

users.ensureIndex({ fieldName: 'username', unique: true });

module.exports = { users, locations, trips, collections };
