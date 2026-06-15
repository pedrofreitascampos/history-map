// Google Maps share-target + bookmarklet.

const fs = require('fs');
const path = require('path');
const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');
const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'public', 'manifest.json'), 'utf-8'));
const sw = fs.readFileSync(path.join(__dirname, '..', 'public', 'sw.js'), 'utf-8');

describe('Google Maps share-target — manifest', () => {
  test('manifest has share_target field', () => {
    expect(manifest).toHaveProperty('share_target');
  });

  test('share_target action is /share-target', () => {
    expect(manifest.share_target.action).toBe('/share-target');
  });

  test('share_target method is GET', () => {
    expect(manifest.share_target.method).toBe('GET');
  });

  test('share_target params include url', () => {
    expect(manifest.share_target.params).toHaveProperty('url');
  });

  test('share_target params include title', () => {
    expect(manifest.share_target.params).toHaveProperty('title');
  });
});

describe('Google Maps share-target — service worker', () => {
  test('sw.js handles /share-target path', () => {
    expect(sw).toContain('/share-target');
  });

  test('sw.js falls back to cached root on offline', () => {
    expect(sw).toMatch(/share-target[\s\S]{0,200}caches\.match\(['"]\/['"]\)/);
  });
});

describe('Google Maps share-target — JS functions', () => {
  test('_parseGoogleMapsCoords is defined', () => {
    expect(html).toContain('function _parseGoogleMapsCoords(');
  });

  test('_parseGoogleMapsCoords extracts @lat,lng pattern', () => {
    const fnStart = html.indexOf('function _parseGoogleMapsCoords(');
    const fnSlice = html.substring(fnStart, fnStart + 200);
    expect(fnSlice).toMatch(/@.*lat.*lng|@.*\(-\?\\d/);
  });

  test('_handleGoogleMapsShare is defined', () => {
    expect(html).toContain('function _handleGoogleMapsShare(');
  });

  test('_handleGoogleMapsShare calls openAddModal', () => {
    const fnStart = html.indexOf('function _handleGoogleMapsShare(');
    const fnSlice = html.substring(fnStart, fnStart + 500);
    expect(fnSlice).toContain('openAddModal');
  });

  test('_handleGoogleMapsShare geocodes when no coords', () => {
    const fnStart = html.indexOf('function _handleGoogleMapsShare(');
    const fnSlice = html.substring(fnStart, fnStart + 600);
    expect(fnSlice).toContain('geocodeNarratedStop');
  });

  test('_initGoogleMapsShareTarget is defined', () => {
    expect(html).toContain('function _initGoogleMapsShareTarget(');
  });

  test('_initGoogleMapsShareTarget reads url param', () => {
    const fnStart = html.indexOf('function _initGoogleMapsShareTarget(');
    const fnSlice = html.substring(fnStart, fnStart + 400);
    expect(fnSlice).toContain("URLSearchParams");
    expect(fnSlice).toContain("'url'");
  });

  test('_initGoogleMapsShareTarget strips Google Maps suffix from title', () => {
    const fnStart = html.indexOf('function _initGoogleMapsShareTarget(');
    const fnSlice = html.substring(fnStart, fnStart + 500);
    expect(fnSlice).toContain('Google Maps');
  });

  test('_initGoogleMapsShareTarget cleans URL after processing', () => {
    const fnStart = html.indexOf('function _initGoogleMapsShareTarget(');
    const fnSlice = html.substring(fnStart, fnStart + 500);
    expect(fnSlice).toContain('replaceState');
  });

  test('_setBookmarkletHref is defined', () => {
    expect(html).toContain('function _setBookmarkletHref(');
  });

  test('_setBookmarkletHref uses window.location.origin', () => {
    const fnStart = html.indexOf('function _setBookmarkletHref(');
    const fnSlice = html.substring(fnStart, fnStart + 300);
    expect(fnSlice).toContain('location.origin');
  });

  test('_setBookmarkletHref sets href to javascript:', () => {
    const fnStart = html.indexOf('function _setBookmarkletHref(');
    const fnSlice = html.substring(fnStart, fnStart + 400);
    expect(fnSlice).toContain('javascript:');
  });
});

describe('Google Maps share-target — startApp wiring', () => {
  test('startApp calls _initGoogleMapsShareTarget', () => {
    expect(html).toContain('_initGoogleMapsShareTarget()');
  });

  test('startApp calls _setBookmarkletHref', () => {
    expect(html).toContain('_setBookmarkletHref(');
  });
});

describe('Google Maps share-target — import guide UI', () => {
  test('gmaps-bookmarklet link exists', () => {
    expect(html).toContain('id="gmaps-bookmarklet"');
  });

  test('bookmarklet link is in import view', () => {
    const importStart = html.indexOf('id="import-view"');
    const importEnd = html.indexOf('id="stats-view"');
    const importSection = html.substring(importStart, importEnd);
    expect(importSection).toContain('id="gmaps-bookmarklet"');
  });

  test('bookmarklet section mentions Android PWA share', () => {
    const chipStart = html.indexOf('id="gmaps-bookmarklet"');
    const context = html.substring(chipStart - 500, chipStart + 100);
    expect(context).toContain('Android');
  });

  test('bookmarklet section mentions desktop bookmarklet', () => {
    const chipStart = html.indexOf('id="gmaps-bookmarklet"');
    const context = html.substring(chipStart - 500, chipStart + 100);
    expect(context.toLowerCase()).toContain('bookmarklet');
  });
});
