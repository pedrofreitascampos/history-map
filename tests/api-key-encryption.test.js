// Per-user API key encryption at rest (AES-256-GCM).
// Also verifies that shared env-key fallback is restricted to admins.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const serverSrc = fs.readFileSync(path.join(__dirname, '..', 'server', 'index.js'), 'utf-8');

describe('API key encryption helpers', () => {
  test('_encryptApiKey and _decryptApiKey are defined', () => {
    expect(serverSrc).toContain('function _encryptApiKey(');
    expect(serverSrc).toContain('function _decryptApiKey(');
  });

  test('_encryptApiKey produces enc: prefix', () => {
    const fnStart = serverSrc.indexOf('function _encryptApiKey(');
    const fnSlice = serverSrc.slice(fnStart, fnStart + 300);
    expect(fnSlice).toContain("'enc:'");
  });

  test('_decryptApiKey returns null on legacy plaintext (startsWith enc: guard)', () => {
    const fnStart = serverSrc.indexOf('function _decryptApiKey(');
    const fnSlice = serverSrc.slice(fnStart, fnStart + 300);
    expect(fnSlice).toMatch(/startsWith\(['"]enc:['"]\)/);
    // Legacy values (no prefix) are returned as-is (fallback path)
    expect(fnSlice).toMatch(/return stored/);
  });

  test('_decryptApiKey wraps AES-256-GCM decipheriv in try/catch', () => {
    const fnStart = serverSrc.indexOf('function _decryptApiKey(');
    const fnSlice = serverSrc.slice(fnStart, fnStart + 700);
    expect(fnSlice).toContain('aes-256-gcm');
    expect(fnSlice).toContain('try {');
    expect(fnSlice).toContain('catch');
    expect(fnSlice).toContain('return null');
  });

  test('encryption key is derived from JWT_SECRET with a domain-specific label', () => {
    expect(serverSrc).toContain('_apiKeyEncKey');
    expect(serverSrc).toContain('api-key-enc-v1');
    expect(serverSrc).toMatch(/createHash\(['"]sha256['"]\)/);
  });
});

describe('AES-256-GCM round-trip (live crypto)', () => {
  // Inline the encrypt/decrypt logic to verify correctness independently of the
  // server module (which binds to a port on require).
  const key = crypto.createHash('sha256').update('test-secret:api-key-enc-v1').digest();

  function encryptApiKey(plaintext) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    return 'enc:' + [iv.toString('hex'), enc.toString('hex'), cipher.getAuthTag().toString('hex')].join(':');
  }

  function decryptApiKey(stored) {
    if (!stored) return null;
    if (!stored.startsWith('enc:')) return stored;
    try {
      const parts = stored.slice(4).split(':');
      if (parts.length !== 3) return null;
      const [ivHex, encHex, tagHex] = parts;
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivHex, 'hex'));
      decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
      return decipher.update(Buffer.from(encHex, 'hex')).toString('utf8') + decipher.final('utf8');
    } catch { return null; }
  }

  test('round-trip: encrypt then decrypt returns original value', () => {
    const original = 'AIzaSyABC123def456';
    expect(decryptApiKey(encryptApiKey(original))).toBe(original);
  });

  test('encrypted form starts with enc:', () => {
    expect(encryptApiKey('test-key')).toMatch(/^enc:/);
  });

  test('two encryptions of the same value produce different ciphertexts (random IV)', () => {
    const a = encryptApiKey('same-key');
    const b = encryptApiKey('same-key');
    expect(a).not.toBe(b);
    expect(decryptApiKey(a)).toBe('same-key');
    expect(decryptApiKey(b)).toBe('same-key');
  });

  test('legacy plaintext (no enc: prefix) passes through unchanged', () => {
    expect(decryptApiKey('AIzaSyLEGACY123')).toBe('AIzaSyLEGACY123');
  });

  test('null/empty stored value returns null', () => {
    expect(decryptApiKey(null)).toBeNull();
    expect(decryptApiKey('')).toBeNull();
  });

  test('tampered ciphertext returns null (GCM auth tag check)', () => {
    const encrypted = encryptApiKey('secret');
    const tampered = encrypted.slice(0, -4) + 'ffff';
    expect(decryptApiKey(tampered)).toBeNull();
  });
});

describe('Admin-only env fallback (multi-user mode)', () => {
  test('getPlacesKey checks ADMIN_EMAIL and username for env key access', () => {
    const fnStart = serverSrc.indexOf('async function getPlacesKey(');
    const fnSlice = serverSrc.slice(fnStart, fnStart + 600);
    expect(fnSlice).toContain('ADMIN_EMAIL');
    expect(fnSlice).toContain('GOOGLE_PLACES_KEY');
    // Single-user mode (!ADMIN_EMAIL) bypasses restriction
    expect(fnSlice).toContain('!ADMIN_EMAIL');
  });

  test('getAnthropicKey checks ADMIN_EMAIL and username for env key access', () => {
    const fnStart = serverSrc.indexOf('async function getAnthropicKey(');
    const fnSlice = serverSrc.slice(fnStart, fnStart + 600);
    expect(fnSlice).toContain('ADMIN_EMAIL');
    expect(fnSlice).toContain('ANTHROPIC_API_KEY');
    expect(fnSlice).toContain('!ADMIN_EMAIL');
  });

  test('getPlacesKey calls _decryptApiKey on stored value', () => {
    const fnStart = serverSrc.indexOf('async function getPlacesKey(');
    const fnSlice = serverSrc.slice(fnStart, fnStart + 300);
    expect(fnSlice).toContain('_decryptApiKey(');
  });
});

describe('Settings routes use encryption', () => {
  test('PUT /api/settings calls _encryptApiKey before storing', () => {
    const routeIdx = serverSrc.indexOf("app.put('/api/settings'");
    const routeSlice = serverSrc.slice(routeIdx, routeIdx + 600);
    expect(routeSlice).toContain('_encryptApiKey(');
  });

  test('GET /api/settings calls _decryptApiKey before masking', () => {
    const routeIdx = serverSrc.indexOf("app.get('/api/settings'");
    const routeSlice = serverSrc.slice(routeIdx, routeIdx + 400);
    expect(routeSlice).toContain('_decryptApiKey(');
  });
});
