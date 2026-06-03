'use strict';

const CONTENT_CATEGORIES = new Set([
  'restaurants', 'bars', 'hotels', 'things-to-do', 'news', 'nightlife',
  'arts-culture', 'film', 'music', 'theatre', 'travel', 'shopping',
  'food-drink', 'attractions', 'experiences', 'guides', 'best',
]);

function decodeEntities(str) {
  return str
    .replace(/&amp;/g, '&')
    .replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/&nbsp;/g, ' ')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/\s+/g, ' ')
    .trim();
}

function stripTags(str) {
  return str.replace(/<[^>]*>/g, '');
}

function detectCity(url) {
  try {
    const pathname = new URL(url).pathname;
    const segments = pathname.split('/').filter(Boolean);
    const candidate = segments[0];
    if (!candidate || CONTENT_CATEGORIES.has(candidate.toLowerCase())) return null;
    return candidate
      .split('-')
      .map(w => w.charAt(0).toUpperCase() + w.slice(1))
      .join(' ');
  } catch {
    return null;
  }
}

function detectArticleTitle(html) {
  const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
  if (titleMatch) return decodeEntities(titleMatch[1]);
  const h1Match = html.match(/<h1[^>]*>([\s\S]*?)<\/h1>/i);
  if (h1Match) return decodeEntities(stripTags(h1Match[1]));
  return null;
}

function parseJsonLd(html) {
  const venues = [];
  const scriptRe = /<script[^>]*type="application\/ld\+json"[^>]*>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = scriptRe.exec(html)) !== null) {
    let parsed;
    try { parsed = JSON.parse(m[1]); } catch { continue; }
    const candidates = Array.isArray(parsed) ? parsed : [parsed];
    for (const obj of candidates) {
      const type = obj['@type'];
      const isItemList = type === 'ItemList' || (Array.isArray(type) && type.includes('ItemList'));
      if (!isItemList || !Array.isArray(obj.itemListElement)) continue;
      for (const el of obj.itemListElement) {
        const item = el.item || el;
        const name = item.name;
        if (!name) continue;
        const addr = item.address;
        const address = addr
          ? (typeof addr === 'string' ? addr : (addr.streetAddress || null))
          : null;
        venues.push({ name: decodeEntities(String(name)), ...(address ? { address: decodeEntities(address) } : {}) });
      }
      if (venues.length > 0) return venues;
    }
  }
  return null;
}

function parseNumberedHeadings(html) {
  const venues = [];
  const headingRe = /<h[23][^>]*>([\s\S]*?)<\/h[23]>/gi;
  let m;
  while ((m = headingRe.exec(html)) !== null) {
    // Decode entities BEFORE the regex check — Time Out wraps numbers in
    // <span> and uses &nbsp; between number and name, so the raw inner is
    // "<span>1.</span>&nbsp;Miga". stripTags leaves "1.&nbsp;Miga"; only
    // after decode does the leading "1. Miga" match /^\d+\.\s+/.
    // (decodeEntities also collapses whitespace, so &nbsp; → normal space.)
    const inner = decodeEntities(stripTags(m[1]));
    if (!/^\d+\.\s+/.test(inner)) continue;
    const name = inner.replace(/^\d+\.\s+/, '').trim();
    if (!name) continue;
    const afterHeading = html.slice(m.index + m[0].length, m.index + m[0].length + 800);
    const addrMatch = afterHeading.match(/<address[^>]*>([\s\S]*?)<\/address>/i);
    if (addrMatch) {
      venues.push({ name, address: decodeEntities(stripTags(addrMatch[1])) });
      continue;
    }
    const pMatch = afterHeading.match(/<p[^>]*>([\s\S]*?)<\/p>/i);
    if (pMatch) {
      const snippet = decodeEntities(stripTags(pMatch[1])).slice(0, 200);
      venues.push({ name, snippet });
      continue;
    }
    venues.push({ name });
  }
  return venues;
}

function parseTimeoutArticle(html, url) {
  const city = detectCity(url);
  const articleTitle = detectArticleTitle(html);

  let venues = parseJsonLd(html);
  if (!venues || venues.length === 0) {
    venues = parseNumberedHeadings(html);
  }

  return { city, articleTitle, venues: venues.slice(0, 100) };
}

module.exports = { parseTimeoutArticle };
