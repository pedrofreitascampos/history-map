// "Seen" feature, frontend pure functions: computeSeenIndex, computeSeenBadges,
// mergeLocationVisits, the real parseJSON passthrough of visits[].seen, and the
// wiring pins (nav tab, view hash, map filter, modal dispatcher actions).
// Functions are extracted from public/index.html and run with vm.runInContext.

const path = require('path');
const fs = require('fs');
const vm = require('vm');

const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');

function walk(start, openFirst) {
  let depth = 0, i = start, found = false;
  for (; i < html.length; i++) {
    const ch = html[i];
    if (ch === '{') { depth++; found = true; }
    if (ch === '}') depth--;
    if (openFirst ? (ch === ';' && depth === 0 && found) : (found && depth === 0)) break;
  }
  return html.substring(start, i + 1);
}
function extractFunction(name) {
  const start = html.indexOf(`function ${name}(`);
  if (start === -1) throw new Error(`Function ${name} not found`);
  return walk(start, false);
}
function extractConst(name) {
  const start = html.indexOf(`const ${name}`);
  if (start === -1) throw new Error(`Const ${name} not found`);
  return walk(start, true);
}

const code = [
  extractConst('OSM_CATEGORY_MAP'),
  extractConst('CATEGORIES'),
  extractFunction('osmToCategory'),
  extractFunction('inferCategory'),
  extractConst('SEEN_TYPES'),
  extractFunction('seenTypeOf'),
  extractFunction('seenNormName'),
  extractFunction('seenVisitEntries'),
  extractFunction('locationHasSeen'),
  extractFunction('computeSeenIndex'),
  extractFunction('seenYearsBetween'),
  extractFunction('computeSeenBadges'),
  extractFunction('mergeLocationVisits'),
  extractFunction('parseJSON'),
].join('\n');
const ctx = vm.createContext({ console, state: {} });
vm.runInContext(code, ctx);
const run = (expr) => JSON.parse(vm.runInContext(`JSON.stringify(${expr})`, ctx));

const loc = (id, name, visits, extra) => ({ id, name, status: 'been', category: 'location', address: 'X, Portugal', visits, ...extra });
const V = (date, seen, notes) => ({ date, notes: notes || '', seen });
const S = (type, name, extra) => Object.assign({ type, name }, extra);

describe('computeSeenIndex', () => {
  test('groups by (type, name) case-insensitively and whitespace-normalised', () => {
    const locs = [
      loc('a', 'Altice Arena', [V('2019-06-01', [S('artist', 'Foo Fighters')]), V('2024-07-12', [S('artist', '  foo   FIGHTERS ')])]),
      loc('b', 'Rock in Rio', [V('2022-06-18', [S('artist', 'foo fighters'), S('artist', 'Muse')])]),
    ];
    const { rows } = run(`computeSeenIndex(${JSON.stringify(locs)})`);
    expect(rows).toHaveLength(2);
    expect(rows[0]).toMatchObject({ type: 'artist', name: 'Foo Fighters', times: 3, first: '2019-06-01', last: '2024-07-12' });
    expect(rows[0].dates).toEqual(['2019-06-01', '2022-06-18', '2024-07-12']);
    expect(rows[0].places.map(p => p.name)).toEqual(['Altice Arena', 'Rock in Rio']);
    expect(rows[1]).toMatchObject({ name: 'Muse', times: 1 });
  });

  test('same name under different types stays separate; a name listed twice in one visit counts once', () => {
    const locs = [loc('a', 'Zoo', [V('2024-01-01', [S('animal', 'Panda'), S('animal', 'panda'), S('other', 'Panda')])])];
    const { rows } = run(`computeSeenIndex(${JSON.stringify(locs)})`);
    expect(rows).toHaveLength(2);
    expect(rows.find(r => r.type === 'animal').times).toBe(1);
  });

  test('sorted by times desc, then most recent, then name', () => {
    const locs = [loc('a', 'P', [
      V('2020-01-01', [S('artist', 'Old Once')]),
      V('2024-01-01', [S('artist', 'New Once')]),
      V('2021-01-01', [S('artist', 'Twice')]), V('2021-02-01', [S('artist', 'Twice')]),
    ])];
    const { rows } = run(`computeSeenIndex(${JSON.stringify(locs)})`);
    expect(rows.map(r => r.name)).toEqual(['Twice', 'New Once', 'Old Once']);
  });

  test('counters: artists, concerts, species, celebrities, sport events', () => {
    const locs = [
      loc('a', 'Arena', [
        V('2020-01-01', [S('artist', 'A'), S('artist', 'B')]),   // 1 concert, 2 artists
        V('2021-01-01', [S('artist', 'A')]),                      // 1 concert
        V('2022-01-01', [S('comedian', 'C')]),                    // not a concert
      ]),
      loc('b', 'Safari', [V('2023-01-01', [S('animal', 'Lion', { count: 3 }), S('animal', 'Zebra'), S('celebrity', 'Someone')])]),
      loc('c', 'Stadium', [V('2023-05-01', [S('sport', 'Benfica 2-1 Porto')]), V('2023-06-01', [S('sport', 'Benfica 0-0 Sporting')])]),
    ];
    const { counters } = run(`computeSeenIndex(${JSON.stringify(locs)})`);
    expect(counters).toMatchObject({ artists: 2, concerts: 2, comedians: 1, species: 2, celebrities: 1, sportEvents: 2 });
  });

  test('animal totals sum counts; unapproved locations and malformed entries are ignored', () => {
    const locs = [
      loc('a', 'Safari', [V('2023-01-01', [S('animal', 'Elephant', { count: 4 })]), V('2024-01-01', [S('animal', 'elephant', { count: 2 })])]),
      loc('b', 'Hidden', [V('2023-01-01', [S('artist', 'Ghost')])], { needsApproval: true }),
      loc('c', 'Junk', [{ date: '2023-01-01', seen: [null, 5, { type: 'artist' }, { type: 'artist', name: '   ' }, { type: '__proto__', name: 'Odd' }] }]),
    ];
    const { rows } = run(`computeSeenIndex(${JSON.stringify(locs)})`);
    expect(rows.find(r => r.norm === 'elephant').totalCount).toBe(6);
    expect(rows.some(r => r.name === 'Ghost')).toBe(false);
    // hostile type falls back to "other", never an inherited prototype member
    expect(rows.find(r => r.name === 'Odd').type).toBe('other');
  });

  test('empty / missing visits yield no rows', () => {
    expect(run('computeSeenIndex([])').rows).toEqual([]);
    expect(run(`computeSeenIndex(${JSON.stringify([loc('a', 'N', undefined)])})`).rows).toEqual([]);
  });
});

describe('locationHasSeen', () => {
  const l = loc('a', 'N', [V('2020-01-01', [S('animal', 'Lion')])]);
  test('matches by type, _any, and rejects others', () => {
    expect(run(`locationHasSeen(${JSON.stringify(l)}, 'animal')`)).toBe(true);
    expect(run(`locationHasSeen(${JSON.stringify(l)}, '_any')`)).toBe(true);
    expect(run(`locationHasSeen(${JSON.stringify(l)}, 'artist')`)).toBe(false);
    expect(run(`locationHasSeen(${JSON.stringify(loc('b', 'N', []))}, '_any')`)).toBe(false);
  });
});

describe('computeSeenBadges', () => {
  const badges = (locs) => {
    const arr = run(`computeSeenBadges(${JSON.stringify(locs)})`);
    return Object.fromEntries(arr.map(b => [b.name, b]));
  };
  const gig = (id, date, artist, extra) => loc(id, 'Venue ' + id, [V(date, [S('artist', artist)])], extra);

  test('returns the 19 event badges with thresholds', () => {
    const b = badges([]);
    expect(Object.keys(b)).toHaveLength(19);
    expect(b['First Gig'].threshold).toBe(1);
    expect(b['Veteran'].threshold).toBe(50);
    expect(Object.values(b).every(x => x.current === 0)).toBe(true);
  });

  test('concert-visit ladder: First Gig / Regular / Veteran', () => {
    const locs = Array.from({ length: 12 }, (_, i) => gig('g' + i, `2020-01-${String(i + 1).padStart(2, '0')}`, 'Band ' + i));
    const b = badges(locs);
    expect(b['First Gig'].current).toBe(12);
    expect(b['Regular'].current).toBe(12);
    expect(b['Veteran'].current).toBe(12);
    expect(b['Hundred Acts'].current).toBe(12);
  });

  test('Encore / Superfan count distinct DATES of the same artist, not entries', () => {
    const same = [loc('a', 'A', [V('2020-01-01', [S('artist', 'Muse'), S('artist', 'MUSE')])]), gig('b', '2021-01-01', 'muse')];
    expect(badges(same)['Encore'].current).toBe(2);
    expect(badges(same)['Superfan'].current).toBe(2);
    const three = same.concat([gig('c', '2022-01-01', 'Muse')]);
    expect(badges(three)['Superfan'].current).toBe(3);
  });

  test('Gig Tourist / Festival Nomad / Away Days count distinct regions (last address segment)', () => {
    const regions = ['Portugal', 'Spain', 'France', 'Italy', 'Germany', 'Portugal'];
    const locs = regions.map((r, i) => loc('r' + i, 'V' + i, [V('2020-0' + (i + 1) + '-01', [S('artist', 'X' + i), S('sport', 'Match ' + i)])], { address: 'Somewhere, ' + r, category: 'festival' }));
    const b = badges(locs);
    expect(b['Gig Tourist'].current).toBe(5);
    expect(b['Festival Nomad'].current).toBe(5);
    expect(b['Festival-goer'].current).toBe(6);
    expect(b['Away Days'].current).toBe(5);
    expect(b['Matchday'].current).toBe(6);
  });

  test('Festival-goer counts visits to category=festival places only', () => {
    const locs = [loc('f', 'Fest', [V('2020-01-01'), V('2021-01-01')], { category: 'festival' }), loc('o', 'Other', [V('2020-01-01')])];
    expect(badges(locs)['Festival-goer'].current).toBe(2);
  });

  test('Two Decades = whole years between first and last concert', () => {
    expect(badges([gig('a', '2004-06-01', 'A'), gig('b', '2024-06-01', 'B')])['Two Decades'].current).toBe(20);
    expect(badges([gig('a', '2004-06-02', 'A'), gig('b', '2024-06-01', 'B')])['Two Decades'].current).toBe(19);
    expect(badges([gig('a', '2004-06-01', 'A')])['Two Decades'].current).toBe(0);
  });

  test('Stand-up Fan counts comedian visits', () => {
    const locs = ['1', '2', '3'].map(i => loc('c' + i, 'Club' + i, [V('2020-01-0' + i, [S('comedian', 'Joke ' + i)])]));
    expect(badges(locs)['Stand-up Fan'].current).toBe(3);
  });

  test('animals: Spotter species, Big Five by substring, Ocean Giant', () => {
    const names = ['African elephant', 'Cape buffalo', 'Lion', 'Leopard', 'Black rhinoceros', 'Humpback whale', 'Zebra'];
    const b = badges([loc('s', 'Safari', [V('2023-01-01', names.map(n => S('animal', n)))])]);
    expect(b['Spotter'].current).toBe(7);
    expect(b['Big Five'].current).toBe(5);
    expect(b['Ocean Giant'].current).toBe(1);
    const partial = badges([loc('s', 'Safari', [V('2023-01-01', [S('animal', 'Lion'), S('animal', 'African Elephant')])])]);
    expect(partial['Big Five'].current).toBe(2);
    expect(partial['Ocean Giant'].current).toBe(0);
    // a celebrity named "whale" must not unlock the animal badge
    expect(badges([loc('s', 'X', [V('2023-01-01', [S('celebrity', 'Whale Watcher')])])])['Ocean Giant'].current).toBe(0);
  });

  test('celebrities and sport', () => {
    const locs = [loc('a', 'A', [V('2020-01-01', [S('celebrity', 'One'), S('celebrity', 'Two')]), V('2021-01-01', [S('sport', 'M1')])])];
    const b = badges(locs);
    expect(b['Star-struck'].current).toBe(2);
    expect(b['Paparazzo'].current).toBe(2);
    expect(b['Season Ticket'].current).toBe(1);
  });
});

describe('mergeLocationVisits', () => {
  const merge = (existing, incoming) => run(`mergeLocationVisits(${JSON.stringify(existing)}, ${JSON.stringify(incoming)})`);

  test('adds visits on new dates and reports them', () => {
    const r = merge({ visits: [V('2020-01-01', undefined, 'old')] }, { visits: [V('2021-05-05', [S('artist', 'A')])] });
    expect(r.visits.map(v => v.date)).toEqual(['2020-01-01', '2021-05-05']);
    expect(r.visits[1].seen).toEqual([S('artist', 'A')]);
    expect(r.changedVisits).toBe(1);
    expect(r.newVisits.map(v => v.date)).toEqual(['2021-05-05']);
    expect(r.changed).toBe(true);
  });

  test('same-date visits union seen lists, deduped by type + normalised name', () => {
    const r = merge(
      { visits: [V('2020-01-01', [S('artist', 'Foo Fighters')])] },
      { visits: [V('2020-01-01', [S('artist', ' foo  fighters '), S('artist', 'Muse'), S('comedian', 'Foo Fighters')])] }
    );
    expect(r.visits).toHaveLength(1);
    expect(r.visits[0].seen.map(s => s.type + ':' + s.name)).toEqual(['artist:Foo Fighters', 'artist:Muse', 'comedian:Foo Fighters']);
    expect(r.seenAdded).toBe(2);
    expect(r.newVisits).toEqual([]);
    expect(r.touchedDates).toEqual(['2020-01-01']);
  });

  test('keeps existing notes; appends different incoming notes on a new line; no duplicate append', () => {
    const e = { visits: [V('2020-01-01', undefined, 'mine')] };
    expect(merge(e, { visits: [V('2020-01-01', undefined, 'theirs')] }).visits[0].notes).toBe('mine\ntheirs');
    expect(merge(e, { visits: [V('2020-01-01', undefined, 'mine')] }).changed).toBe(false);
    expect(merge({ visits: [V('2020-01-01', undefined, '')] }, { visits: [V('2020-01-01', undefined, 'theirs')] }).visits[0].notes).toBe('theirs');
    const twice = merge({ visits: merge(e, { visits: [V('2020-01-01', undefined, 'theirs')] }).visits }, { visits: [V('2020-01-01', undefined, 'theirs')] });
    expect(twice.changed).toBe(false);
  });

  test('idempotent: merging the same incoming twice changes nothing the second time', () => {
    const inc = { tags: ['live'], visits: [V('2020-01-01', [S('artist', 'A')], 'n')] };
    const first = merge({ visits: [] }, inc);
    const second = merge({ visits: first.visits, tags: first.tags }, inc);
    expect(first.changed).toBe(true);
    expect(second.changed).toBe(false);
    expect(second.visits).toEqual(first.visits);
  });

  test('unions tags, preserving existing order', () => {
    const r = merge({ tags: ['b', 'a'], visits: [] }, { tags: ['a', ' c ', '', 5, 'd'], visits: [] });
    expect(r.tags).toEqual(['b', 'a', 'c', 'd']);
    expect(r.tagsChanged).toBe(true);
    expect(r.changed).toBe(true);
    expect(merge({ tags: ['a'], visits: [] }, { tags: ['a'], visits: [] }).changed).toBe(false);
  });

  test('does not mutate its inputs; ignores incoming visits without a date', () => {
    const existing = { visits: [V('2020-01-01', [S('artist', 'A')])] };
    const incoming = { visits: [V('2020-01-01', [S('artist', 'B')]), { notes: 'no date', seen: [S('artist', 'Z')] }] };
    const e0 = JSON.stringify(existing), i0 = JSON.stringify(incoming);
    const r = merge(existing, incoming);
    expect(JSON.stringify(existing)).toBe(e0);
    expect(JSON.stringify(incoming)).toBe(i0);
    expect(r.visits).toHaveLength(1);
  });
});

describe('real parseJSON: Oikumene location array with visits[].seen', () => {
  const shape = [{
    name: 'Altice Arena', address: 'Parque das Nações, Lisboa, Portugal', lat: 38.7684, lng: -9.0942,
    category: 'stadium', status: 'been', tags: ['concert'], notes: 'Great acoustics',
    visits: [
      { date: '2019-06-01', notes: 'Row 5', seen: [{ type: 'artist', name: 'Foo Fighters', note: 'encore x3' }] },
      { date: '2024-07-12', notes: '', seen: [{ type: 'animal', name: 'Swallow', count: 12, wild: true }] },
    ],
  }, {
    name: 'Zoo', address: 'Lisboa, Portugal', lat: 38.74, lng: -9.17, category: 'definitely-not-a-category', status: 'bucket',
  }];

  test('keeps visits (with seen untouched), tags, notes, status and a valid category', () => {
    const out = run(`parseJSON(${JSON.stringify(JSON.stringify(shape))})`);
    expect(out).toHaveLength(2);
    expect(out[0]).toMatchObject({ name: 'Altice Arena', category: 'stadium', status: 'been', tags: ['concert'], notes: 'Great acoustics' });
    expect(out[0].visits).toEqual(shape[0].visits);
    expect(out[1].status).toBe('bucket');
    expect(Object.keys(vm.runInContext('CATEGORIES', ctx))).toContain(out[1].category); // invalid category falls back to inference
    expect(out[1].visits).toBeUndefined();
  });

  test('also accepted inside a { locations: [...] } wrapper (no exportDate)', () => {
    const out = run(`parseJSON(${JSON.stringify(JSON.stringify({ locations: shape }))})`);
    expect(out[0].visits[0].seen[0].name).toBe('Foo Fighters');
  });

  test('plain [{name,lat,lng}] arrays still import as before (no visits key)', () => {
    const out = run(`parseJSON(${JSON.stringify(JSON.stringify([{ name: 'Cafe', lat: 1, lng: 2 }]))})`);
    expect(out[0]).toMatchObject({ name: 'Cafe', status: 'been', lat: 1, lng: 2 });
    expect(out[0].visits).toBeUndefined();
  });
});

describe('wiring', () => {
  test('Seen is registered like the other views (nav tab, view, hash, switchView, mobile label span)', () => {
    expect(html).toMatch(/data-view="seen-view" data-click="switchView" data-arg0="seen-view"/);
    expect(html).toMatch(/<span class="tab-label">Seen<\/span>/);
    expect(html).toContain('id="seen-view"');
    expect(html).toMatch(/'seen-view': 'seen'/);
    expect(extractFunction('switchView')).toContain("viewId === 'seen-view'");
  });
  test('map filter: select + state + getFilteredLocations + applyFilters', () => {
    expect(html).toContain('id="seen-filter"');
    expect(extractFunction('getFilteredLocations')).toContain('locationHasSeen(loc, state.filters.seen)');
    expect(extractFunction('applyFilters')).toContain("getElementById('seen-filter')");
  });
  test('modal controls are dispatched via data-click, never inline handlers', () => {
    const fn = extractFunction('_buildSeenBlock');
    expect(fn).not.toMatch(/onclick|innerHTML/);
    expect(fn).toContain("dataset.click = 'modalSeenToggle'");
    expect(html).toMatch(/modalSeenAdd: \(el\) => seenModalAdd\(el\)/);
  });
  test('Seen view and modal escape user strings (no raw name interpolation)', () => {
    const fn = extractFunction('renderSeenView');
    expect(fn).toContain('esc(r.name)');
    expect(fn).toContain('esc(p.name');
    expect(extractFunction('_buildSeenBlock')).not.toMatch(/innerHTML/);
  });
});

// jsdom: the modal editor really renders chips as text and add/remove mutate state.modalVisits.
let JSDOM;
try { JSDOM = require('jsdom').JSDOM; } catch { JSDOM = null; }
(JSDOM ? describe : describe.skip)('edit-modal seen editor (jsdom)', () => {
  function make() {
    const dom = new JSDOM(`<!DOCTYPE html><body>
      <span id="loc-visits-summary-text"></span><div id="loc-visits-list"></div></body>`);
    const c = vm.createContext({
      document: dom.window.document, console, Date, Array, Object, JSON, Math, Number,
      state: { modalVisits: [], locations: [] }, stateIndex: { generation: 0 }, toasts: [],
      showToast: (m) => c.toasts.push(m),
    });
    vm.runInContext([
      'let _seenAddOpenDate = null; let _seenLastType = "artist"; let _seenIdxCache = null; let _seenIdxGen = -1;',
      extractConst('SEEN_TYPES'), extractFunction('seenTypeOf'), extractFunction('seenNormName'),
      extractFunction('seenVisitEntries'), extractFunction('computeSeenIndex'), extractFunction('getSeenIndex'),
      extractFunction('_seenChipText'), extractFunction('_buildSeenBlock'), extractFunction('_buildSeenDatalists'),
      extractFunction('_focusSeenName'), extractFunction('renderVisitFields'),
      extractFunction('seenModalToggle'), extractFunction('seenModalTypeChange'), extractFunction('seenModalAdd'), extractFunction('seenModalRemove'),
    ].join('\n'), c);
    return { c, doc: dom.window.document };
  }

  test('chips render hostile text inertly and remove works', () => {
    const { c, doc } = make();
    c.state.modalVisits = [{ date: '2024-01-01', notes: '', seen: [{ type: 'artist', name: '<img src=x onerror=alert(1)>', note: '"><b>x</b>' }, { type: 'animal', name: 'Lion', count: 3, wild: true }] }];
    vm.runInContext('renderVisitFields()', c);
    const list = doc.getElementById('loc-visits-list');
    expect(list.querySelector('img')).toBeNull();
    expect(list.querySelector('b')).toBeNull();
    const chips = [...list.querySelectorAll('.seen-chip')];
    expect(chips).toHaveLength(2);
    expect(chips[0].textContent).toContain('<img src=x onerror=alert(1)>');
    expect(chips[1].textContent).toContain('🐾 Lion ×3 · wild');
    // remove the first chip via the same handler the dispatcher calls
    c.removeEl = list.querySelector('.seen-chip-x');
    vm.runInContext('seenModalRemove(removeEl)', c);
    expect(c.state.modalVisits[0].seen.map(s => s.name)).toEqual(['Lion']);
    c.removeEl = list.querySelector('.seen-chip-x');
    vm.runInContext('seenModalRemove(removeEl)', c);
    expect(c.state.modalVisits[0].seen).toBeUndefined();
  });

  test('toggle opens the form (datalist per type), add pushes a trimmed entry, duplicates are refused', () => {
    const { c, doc } = make();
    c.state.modalVisits = [{ date: '2024-01-01', notes: '' }];
    c.state.locations = [{ id: 'z', name: 'Zoo', visits: [{ date: '2020-01-01', seen: [{ type: 'animal', name: 'Okapi' }] }] }];
    vm.runInContext('renderVisitFields()', c);
    c.toggleEl = doc.querySelector('.seen-toggle');
    vm.runInContext('seenModalToggle(toggleEl)', c);
    const form = doc.querySelector('.seen-add-form');
    expect(form).not.toBeNull();
    // autocomplete source: names already in the user's data
    expect([...doc.querySelectorAll('#seen-names-animal option')].map(o => o.value)).toEqual(['Okapi']);

    form.querySelector('.seen-type').value = 'animal';
    c.typeEl = form.querySelector('.seen-type');
    vm.runInContext('seenModalTypeChange(typeEl)', c);
    expect(form.querySelector('.seen-extras').style.display).toBe('inline-flex');
    expect(form.querySelector('.seen-name').getAttribute('list')).toBe('seen-names-animal');

    form.querySelector('.seen-name').value = '   African   elephant ';
    form.querySelector('.seen-count').value = '12';
    form.querySelector('.seen-wild').checked = true;
    c.addEl = form.querySelector('.add-small-btn');
    vm.runInContext('seenModalAdd(addEl)', c);
    expect(c.state.modalVisits[0].seen).toEqual([{ type: 'animal', name: 'African elephant', count: 12, wild: true }]);

    // form is re-rendered open; adding the same (type, normalised name) again is refused
    const form2 = doc.querySelector('.seen-add-form');
    form2.querySelector('.seen-name').value = 'african ELEPHANT';
    c.addEl = form2.querySelector('.add-small-btn');
    vm.runInContext('seenModalAdd(addEl)', c);
    expect(c.state.modalVisits[0].seen).toHaveLength(1);
    expect(c.toasts.join()).toMatch(/Already listed/);
  });

  test('empty name is refused', () => {
    const { c, doc } = make();
    c.state.modalVisits = [{ date: '2024-01-01', notes: '' }];
    vm.runInContext('renderVisitFields()', c);
    c.toggleEl = doc.querySelector('.seen-toggle');
    vm.runInContext('seenModalToggle(toggleEl)', c);
    c.addEl = doc.querySelector('.seen-add-form .add-small-btn');
    vm.runInContext('seenModalAdd(addEl)', c);
    expect(c.state.modalVisits[0].seen).toBeUndefined();
  });
});
