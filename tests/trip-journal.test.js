// LLM trip-journal: POST /api/trips/:id/journal → AI prose from trip stops.

const fs = require('fs');
const path = require('path');
const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');
const serverSrc = fs.readFileSync(path.join(__dirname, '..', 'server', 'index.js'), 'utf-8');

// ── Server route ──────────────────────────────────────────────────────────────
describe('Trip journal — server route', () => {
  test('POST /api/trips/:id/journal route exists', () => {
    expect(serverSrc).toMatch(/app\.post\(['"]\/api\/trips\/:id\/journal['"]/);
  });

  test('route is auth-gated', () => {
    const idx = serverSrc.indexOf("app.post('/api/trips/:id/journal'");
    const slice = serverSrc.slice(idx, idx + 60);
    expect(slice).toContain('auth');
  });

  test('route has rate limit middleware', () => {
    expect(serverSrc).toMatch(/rateLimit[\s\S]{0,50}trips\/:id\/journal|trips\/:id\/journal[\s\S]{0,200}rateLimit/);
  });

  test('route fetches trip from DB and checks ownership', () => {
    const idx = serverSrc.indexOf("app.post('/api/trips/:id/journal'");
    const slice = serverSrc.slice(idx, idx + 400);
    expect(slice).toContain('db.trips.findOne');
    expect(slice).toContain('userId');
    expect(slice).toContain('404');
  });

  test('route checks for Anthropic API key', () => {
    const idx = serverSrc.indexOf("app.post('/api/trips/:id/journal'");
    const slice = serverSrc.slice(idx, idx + 500);
    expect(slice).toContain('getAnthropicKey');
    expect(slice).toContain('501');
  });

  test('route validates stops array', () => {
    const idx = serverSrc.indexOf("app.post('/api/trips/:id/journal'");
    const slice = serverSrc.slice(idx, idx + 700);
    expect(slice).toContain('stops');
    expect(slice).toMatch(/Array\.isArray|typeof stops/);
    expect(slice).toContain('400');
  });

  test('route limits stops to 100', () => {
    const idx = serverSrc.indexOf("app.post('/api/trips/:id/journal'");
    const slice = serverSrc.slice(idx, idx + 800);
    expect(slice).toContain('100');
  });

  test('route calls claude-haiku with prose prompt', () => {
    const idx = serverSrc.indexOf("app.post('/api/trips/:id/journal'");
    const slice = serverSrc.slice(idx, idx + 2500);
    expect(slice).toContain('claude-haiku');
    expect(slice).toContain('travel writer');
  });

  test('route returns { journal } in response', () => {
    const idx = serverSrc.indexOf("app.post('/api/trips/:id/journal'");
    const slice = serverSrc.slice(idx, idx + 2500);
    expect(slice).toMatch(/res\.json\(\{[^}]*journal/);
  });

  test('route logs journal_api_call on success', () => {
    const idx = serverSrc.indexOf("app.post('/api/trips/:id/journal'");
    const slice = serverSrc.slice(idx, idx + 2500);
    expect(slice).toContain('journal_api_call');
  });

  test('stop notes are capped at 200 chars before sending', () => {
    const idx = serverSrc.indexOf("app.post('/api/trips/:id/journal'");
    const slice = serverSrc.slice(idx, idx + 2000);
    expect(slice).toContain('200');
  });
});

// ── Frontend modal ────────────────────────────────────────────────────────────
describe('Trip journal — frontend modal', () => {
  test('#journal-modal exists with role=dialog', () => {
    expect(html).toContain('id="journal-modal"');
    expect(html).toMatch(/id="journal-modal"[^>]*role="dialog"/);
  });

  test('#journal-modal uses .modal-overlay', () => {
    const idx = html.indexOf('id="journal-modal"');
    expect(html.slice(idx - 5, idx + 60)).toContain('modal-overlay');
  });

  test('#journal-modal-title element exists', () => {
    expect(html).toContain('id="journal-modal-title"');
  });

  test('#journal-modal-body element exists', () => {
    expect(html).toContain('id="journal-modal-body"');
  });

  test('modal has Copy button calling copyJournalText', () => {
    expect(html).toContain('data-click="copyJournalText"');
  });

  test('modal has close button', () => {
    expect(html).toContain('data-click="closeJournalModal"');
  });
});

// ── Frontend functions ────────────────────────────────────────────────────────
describe('Trip journal — frontend functions', () => {
  test('generateTripJournal is defined', () => {
    expect(html).toContain('async function generateTripJournal(');
  });

  test('openJournalModal is defined', () => {
    expect(html).toContain('function openJournalModal(');
  });

  test('closeJournalModal is defined', () => {
    expect(html).toContain('function closeJournalModal(');
  });

  test('copyJournalText is defined', () => {
    expect(html).toContain('function copyJournalText(');
  });

  test('generateTripJournal POSTs to /trips/:id/journal', () => {
    const fnStart = html.indexOf('async function generateTripJournal(');
    const fnSlice = html.slice(fnStart, fnStart + 1000);
    expect(fnSlice).toContain('/trips/');
    expect(fnSlice).toContain('/journal');
    expect(fnSlice).toContain("'POST'");
  });

  test('generateTripJournal sends stops array with name/category/visitDate', () => {
    const fnStart = html.indexOf('async function generateTripJournal(');
    const fnSlice = html.slice(fnStart, fnStart + 1000);
    expect(fnSlice).toContain('stops');
    expect(fnSlice).toContain('name:');
    expect(fnSlice).toContain('category');
    expect(fnSlice).toContain('visitDate');
  });

  test('generateTripJournal shows toast on empty trip', () => {
    const fnStart = html.indexOf('async function generateTripJournal(');
    const fnSlice = html.slice(fnStart, fnStart + 500);
    expect(fnSlice).toContain('showToast');
    expect(fnSlice).toContain('No stops');
  });

  test('generateTripJournal disables button during request', () => {
    const fnStart = html.indexOf('async function generateTripJournal(');
    const fnSlice = html.slice(fnStart, fnStart + 1200);
    expect(fnSlice).toContain('btn.disabled = true');
    expect(fnSlice).toContain('btn.disabled = false');
  });

  test('openJournalModal sets title and body text', () => {
    const fnStart = html.indexOf('function openJournalModal(');
    const fnSlice = html.slice(fnStart, fnStart + 400);
    expect(fnSlice).toContain('journal-modal-title');
    expect(fnSlice).toContain('journal-modal-body');
    expect(fnSlice).toContain('classList.add');
  });

  test('closeJournalModal removes open class and restores focus', () => {
    const fnStart = html.indexOf('function closeJournalModal(');
    const fnSlice = html.slice(fnStart, fnStart + 150);
    expect(fnSlice).toContain('classList.remove');
    expect(fnSlice).toContain('restoreFocus');
  });

  test('copyJournalText uses clipboard API', () => {
    const fnStart = html.indexOf('function copyJournalText(');
    const fnSlice = html.slice(fnStart, fnStart + 200);
    expect(fnSlice).toContain('clipboard.writeText');
  });
});

// ── Button in trip detail ─────────────────────────────────────────────────────
describe('Trip journal — UI trigger', () => {
  test('✍️ button with data-click="generateTripJournal" exists in renderTripDetail', () => {
    expect(html).toContain('data-click="generateTripJournal"');
    const idx = html.indexOf('data-click="generateTripJournal"');
    const slice = html.slice(idx - 20, idx + 200);
    expect(slice).toMatch(/✍/);
  });

  test('Escape handler closes journal-modal', () => {
    const escIdx = html.indexOf("e.key !== 'Escape'");
    const slice = html.slice(escIdx, escIdx + 1300);
    expect(slice).toContain('journal-modal');
    expect(slice).toContain('closeJournalModal');
  });
});
