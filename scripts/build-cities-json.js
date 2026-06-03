#!/usr/bin/env node
/*
 * Builds public/cities.json from the `all-the-cities` GeoNames dataset.
 *
 * Output format — compact arrays to minimise bytes over the wire:
 *   { generatedAt, count, minPop, cities: [[lat, lng, name, iso2, pop], ...] }
 *
 * Sorted by population descending. Coordinates rounded to 4 decimal places
 * (~11m precision — more than enough for snap-to-nearest-city).
 */
const fs = require('fs');
const path = require('path');
const cities = require('all-the-cities');

const MIN_POP = parseInt(process.env.MIN_POP, 10) || 1000;
const OUT_PATH = path.join(__dirname, '..', 'public', 'cities.json');

// GeoNames feature codes to KEEP (real cities / admin seats / generic populated places).
// Excludes: PPLX (city section/neighborhood — e.g. Tiergarten inside Berlin),
//           PPLL (locality / non-city populated area — e.g. "The Rocks" inside Sydney),
//           PPLH/PPLQ/PPLW (historical/abandoned/destroyed),
//           PPLCH/PPLR/STLMT (historical capital / religious / Israeli settlement).
// Without this filter, snap-to-nearest-city picks up neighborhoods on top of
// landmark coordinates and labels Empire State as "Gramercy Park" etc.
const KEEP_CODES = new Set(['PPL','PPLC','PPLA','PPLA2','PPLA3','PPLA4','PPLA5','PPLS','PPLF','PPLG']);

const filtered = cities
  .filter(c => c.population >= MIN_POP && c.loc && Array.isArray(c.loc.coordinates) && KEEP_CODES.has(c.featureCode))
  .sort((a, b) => b.population - a.population);

const round4 = n => Math.round(n * 10000) / 10000;

const out = {
  generatedAt: new Date().toISOString(),
  source: 'all-the-cities (GeoNames cities1000 derivative)',
  count: filtered.length,
  minPop: MIN_POP,
  cities: filtered.map(c => [
    round4(c.loc.coordinates[1]),
    round4(c.loc.coordinates[0]),
    c.name,
    c.country,
    c.population,
  ]),
};

fs.writeFileSync(OUT_PATH, JSON.stringify(out));
const sizeMB = (fs.statSync(OUT_PATH).size / 1024 / 1024).toFixed(2);
console.log(`Wrote ${OUT_PATH} — ${out.count} cities (pop >= ${MIN_POP}), ${sizeMB} MB`);
