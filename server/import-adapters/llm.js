'use strict';

// LLM-powered web-import adapter. Parses any list-style article into the
// canonical {city, articleTitle, venues:[{name,address,snippet}]} shape via
// Anthropic Haiku 4.5 with a cached system prompt + forced tool use.
//
// Wire-in (server/index.js): when a per-user or env Anthropic key is
// configured, this adapter runs for *any* https host that passed the SSRF
// guard — the brittle per-site regex registry (timeout.js) becomes the
// fallback when no key is set.
//
// Security notes:
//   - HTML body is untrusted attacker-controlled text. Forced tool use
//     constrains the model output to the schema below, so prompt-injection
//     attempts inside the page can at worst fabricate venue rows — which
//     the user reviews in the modal before any place is created.
//   - We strip <script>/<style>/<noscript>/<iframe>/HTML comments BEFORE
//     sending so the model focuses on visible text and we avoid leaking
//     any inline tokens from the page.
//   - Input text is capped at HTML_TEXT_CAP chars (~10k tokens for Haiku)
//     so a malicious or oversized page can't blow up our token bill.
//   - Errors thrown carry `.code` and `.status` so the route handler can
//     translate them to sanitised user-facing messages without leaking
//     upstream Anthropic body content.

const HTML_TEXT_CAP = 30000; // ~10k tokens of input; Haiku context easily fits.
const MAX_VENUES = 100;

function stripHtmlForLLM(html) {
  if (typeof html !== 'string') return '';
  let out = html;
  out = out.replace(/<!--[\s\S]*?-->/g, ' ');
  out = out.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ');
  out = out.replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ');
  out = out.replace(/<noscript\b[^>]*>[\s\S]*?<\/noscript>/gi, ' ');
  out = out.replace(/<iframe\b[^>]*>[\s\S]*?<\/iframe>/gi, ' ');
  out = out.replace(/<svg\b[^>]*>[\s\S]*?<\/svg>/gi, ' ');
  // Replace any remaining tags with a single space so adjacent text doesn't
  // mash together (e.g. "<h3>1.</h3><span>Miga</span>" → " 1. Miga").
  out = out.replace(/<[^>]+>/g, ' ');
  // Decode the most common entities so the model sees readable text.
  out = out
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>');
  // Collapse whitespace.
  out = out.replace(/\s+/g, ' ').trim();
  if (out.length > HTML_TEXT_CAP) out = out.slice(0, HTML_TEXT_CAP);
  return out;
}

const PARSE_VENUES_TOOL = {
  name: 'parse_venues',
  description:
    'Emit the venues listed in the article as structured JSON. Only include real venues that are part of the main list — skip ads, related-content sidebars, author bios, and navigation links.',
  input_schema: {
    type: 'object',
    properties: {
      city: {
        type: ['string', 'null'],
        description: 'City the article is about, if clearly identifiable from the URL or title. Null otherwise.',
      },
      articleTitle: {
        type: ['string', 'null'],
        description: 'The article headline/title. Null if not identifiable.',
      },
      venues: {
        type: 'array',
        description: 'List of venues (restaurants, bars, hotels, attractions, etc.) extracted from the article.',
        items: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'Venue name, cleaned (no leading numbering like "1.", no trailing taglines).' },
            address: { type: ['string', 'null'], description: 'Street address if present, else null. Do not invent.' },
            snippet: { type: ['string', 'null'], description: 'Short editorial blurb (≤200 chars) if present, else null. Do not invent.' },
          },
          required: ['name'],
        },
      },
    },
    required: ['venues'],
  },
};

const SYSTEM_PROMPT =
  'You extract venues from list-style travel/lifestyle articles. ' +
  'Input is the visible text of a single article (HTML stripped). ' +
  'Use the parse_venues tool to emit ONLY venues that are part of the main numbered/ranked list in the article. ' +
  'Skip ads, "related reading" sidebars, author bios, footer links, and navigation. ' +
  'Names must be cleaned: drop leading "N." or "#N" numbering and trailing punctuation. ' +
  'Addresses are optional — leave null rather than invent one. ' +
  'Snippets are optional editorial blurbs, capped at 200 chars; leave null rather than invent. ' +
  'Return at most ' + MAX_VENUES + ' venues. If the page has no recognisable venue list, return an empty venues array.';

async function parseVenuesLLM(html, url, apiKey, opts = {}) {
  if (!apiKey) {
    const err = new Error('llm_no_key');
    err.code = 'llm_no_key';
    err.status = 501;
    throw err;
  }
  let Anthropic;
  try { Anthropic = require('@anthropic-ai/sdk'); }
  catch {
    const err = new Error('llm_sdk_missing');
    err.code = 'llm_sdk_missing';
    err.status = 500;
    throw err;
  }
  const client = new (Anthropic.default || Anthropic)({ apiKey });
  const text = stripHtmlForLLM(html);
  const userContent =
    'URL: ' + String(url || '(unknown)') + '\n\n' +
    'Article text (HTML stripped, may be truncated):\n' + text;

  let response;
  try {
    response = await client.messages.create({
      model: opts.model || 'claude-haiku-4-5-20251001',
      max_tokens: 2048,
      system: [
        {
          type: 'text',
          text: SYSTEM_PROMPT,
          cache_control: { type: 'ephemeral' },
        },
      ],
      tools: [PARSE_VENUES_TOOL],
      tool_choice: { type: 'tool', name: 'parse_venues' },
      messages: [{ role: 'user', content: userContent }],
    });
  } catch (err) {
    // Sanitise + re-throw so the route can return a generic message.
    const code = err.status === 401 ? 'llm_error_401'
      : err.status === 429 ? 'llm_error_429'
      : err.status === 400 ? 'llm_error_400'
      : 'llm_error';
    const out = new Error(code);
    out.code = code;
    out.status = err.status || 502;
    out.upstreamMs = 0;
    throw out;
  }

  const toolUse = (response.content || []).find(c => c.type === 'tool_use');
  if (!toolUse) {
    const err = new Error('llm_no_tool_use');
    err.code = 'llm_no_tool_use';
    err.status = 502;
    throw err;
  }
  const out = toolUse.input || {};
  const rawVenues = Array.isArray(out.venues) ? out.venues : [];
  // Defensive: clean the model output again on our side.
  const venues = rawVenues
    .filter(v => v && typeof v.name === 'string' && v.name.trim())
    .slice(0, MAX_VENUES)
    .map(v => {
      const cleaned = { name: v.name.trim() };
      if (typeof v.address === 'string' && v.address.trim()) cleaned.address = v.address.trim();
      if (typeof v.snippet === 'string' && v.snippet.trim()) cleaned.snippet = v.snippet.trim().slice(0, 200);
      return cleaned;
    });
  return {
    city: typeof out.city === 'string' && out.city.trim() ? out.city.trim() : null,
    articleTitle: typeof out.articleTitle === 'string' && out.articleTitle.trim() ? out.articleTitle.trim() : null,
    venues,
    usage: response.usage || null,
  };
}

module.exports = {
  parseVenuesLLM,
  stripHtmlForLLM,
  HTML_TEXT_CAP,
  MAX_VENUES,
  PARSE_VENUES_TOOL,
  SYSTEM_PROMPT,
};
