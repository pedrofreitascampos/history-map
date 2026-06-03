# Oikumene Roadmap

Project-specific backlog for the Oikumene history map app.

Convention (defined in `~/projects/ai/companion/docs/architecture.md`):
- **Top-level** (this file) — Oikumene-specific concerns
- **Personal life** — `~/.claude/personal/roadmap.md` (gitignored, never in repo)

Session-log detail (commit chronology, test counts) lives in the memory roadmap
at `~/.claude/projects/C--Users-pedro-projects-software-history-map/memory/project_roadmap.md`.

## Open

**Canonical "what's next" lives in [Audit 2026-06-02](#audit-2026-06-02-full-multi-domain) below.** It groups everything by 🔴 Now (P0, 1-2 days) → 🟠 Next (P1, 1-2 weeks) → 🟡 Later (P2 polish) → ✨ Power features. Start there.

**Status as of 2026-06-04:** **10 of 10 original P0s shipped + 5 of 7 S2 P1 "Security finishing touches" closed in one batch.** Audit P0 close-out complete (data-arg0 dispatcher ✅, hearts duplicate attr ✅, web-import bug ✅, regions-view interaction ✅ partial, gzip compression ✅, LLM web-import adapter + engine attribution UX ✅, SSRF blocklist + redirect bypass ✅, err.message leak across 7 catch blocks ✅, marker-style in-place setIcon ✅, mobile-UX batch ✅). S2 P1 hardening batch 2026-06-04 (+16 jest, 986+3skip green, 8/8 e2e green): narrate+discover rate limits ✅, CSP photon.komoot.io ✅, render.yaml ANTHROPIC_API_KEY ✅, exact-pin @anthropic-ai/sdk ✅, notes server-side sanitisation ✅. Next: ETag on /api/locations, initMap-first + CDN defers, DNS-rebinding SSRF.

This Open section only carries items NOT covered by the latest audit (longer-term roadmap that pre-dates it):

### Carry-over from prior backlog

- **Bootstrap from sources without an export API** — Playwright/headless-browser scraper pattern. Adapter slot in `WEBSITE_IMPORT_ADAPTERS` is open for per-target use. Targets to be picked case-by-case (beliapp.co is blocked, see Dropped below).

### Wishlist (P1+, lower priority)

- **Direct share-from-Google-Maps → Oikumene** (user request 2026-06-03). Two
  ingestion surfaces, both bypass the current Takeout/Timeline-export friction:
  - **Mobile (Android/iOS PWA share-target).** Register Oikumene as a Web Share
    Target via `manifest.json` (`share_target` member). When the user taps Share
    in Google Maps → "Oikumene" appears in the sheet → Maps sends `title + text +
    url` to our PWA. The shared URL is a `maps.app.goo.gl/...` short-link OR a
    full `google.com/maps/place/<name>/@lat,lng,zoom/data=...` deep-link. Server
    endpoint `POST /api/import/google-maps-link` accepts `{url}`, expands shortlinks
    via a HEAD (with the same SSRF guard + 10s timeout we use for web-import),
    extracts `lat,lng,name,placeId` from the canonical URL, and either: (a) opens
    the Add modal pre-filled when it's a single place, or (b) treats it as a
    saved-list link and imports the list. Requires the PWA manifest to be
    installed — depends on Oikumene becoming installable (Service Worker, see
    Power feature #7).
  - **Web browser (bookmarklet).** A one-line `javascript:` bookmarklet the user
    drags to their bookmarks bar. On any `google.com/maps/...` page, click the
    bookmarklet → it reads `window.location.href` + the page title → opens
    `https://history-map.onrender.com/#add?url=<encoded>` in a new tab → the app
    auto-routes that hash into the Add modal (or list importer). No browser
    extension required, works on desktop Chrome/Firefox/Safari/Edge today. Hosted
    install page under Account modal: "Drag this button to your bookmarks bar."
  - Both surfaces share the server endpoint + URL parser. Implementation tree:
    (1) URL parser regex/grammar (single place vs list vs short link), (2)
    shortlink expander with SSRF guard, (3) `#add?url=` hash handler in
    `switchView` + `init()`, (4) PWA manifest `share_target` + Service Worker
    (overlaps with Power feature #7), (5) bookmarklet install card in Account
    modal.
- **Bootstrap preset collections** (user request 2026-06-03). Add a library of famous, ready-made collections users can opt into rather than building from scratch: **UNESCO World Heritage Sites** (~1200 sites, GeoJSON from whc.unesco.org), **National Parks** (per-country: NPS for US, ICNF for PT, …), **Airports** (OurAirports CSV, ~50k, IATA-coded), **Stadiums / Arenas** (Wikidata SPARQL by `instance of (P31) = stadium/arena`), **Wonders of the World** (curated lists — 7 ancient, 7 new, 7 natural), **Michelin Guide** (scrape — ToS-grey, defer), **Blue Flag beaches** (annual list per country). Sketch: a `/api/collections/presets` endpoint serves a metadata catalog (name, source, count, description, sample); user clicks "Subscribe" and the preset's locations bulk-insert with `presetId` tag (filterable, removable). Each preset = adapter file in `server/preset-collections/` analogous to `import-adapters/`. Versioned (re-fetch yearly for UNESCO updates etc.). Open question: do preset locations live in user's `state.locations` (cluttering wishlist/been views) or as a separate overlay layer toggled per-collection? Probably overlay-first to keep the personal list clean.
- **Google Data Portability API OAuth flow** — blocked on Google's Restricted-scope verification for personal apps. Monitor for relaxation. Sharable-list scraper NOT to be built (ToS + low value).
- **Google Photos — Path 2 (photo-org bridge)** — Path 3 (manual EXIF drop) ✅ shipped 2026-05-31 in `c417584`. Path 2 requires repaired photo-org (DB columns + NAS path pivot since Google scope removal). Queued.
- **`style-src` strict CSP** (deferred) — Leaflet injects nonceless inline styles; per CSP-3, mixing `'unsafe-inline'` + nonce makes browsers ignore `'unsafe-inline'`. Accepted defense-in-depth gap until strict-dynamic-for-CSS story or migration off Leaflet inline styles. Lower severity than script injection.

## ⛔ Blocked / Dropped

- **beliapp.co import** — architecturally blocked. `https://beliapp.co/app/<username>` is install-marketing only (redirects to App Store; no web profile, no JSON, no SPA bootstrap). Gmail search across 9 angles found no exports. Investigated 2026-05-31; user-confirmed skip. Practical paths if revisited: in-app export feature (status unknown), or 2-3 day Playwright+credentials scraper (ToS-grey + brittle + Chromium dep).
- **Sync to Google Maps Saved Lists** — no public write API exists.
- **Google Photos Library API (Path 1)** — dead since 2025-03-31 (scope removed; Picker API interactive-only; GPS never in API schema). Confirmed via photo-org's own `_parse_media_item` hardcoding `lat,lon=None,None`.

## Audit 2026-06-02 (full multi-domain)

Pedrow-commissioned full audit mirroring the Fortuna run. 4 parallel specialist agents (cybersec / code+perf / UX/UI / live functionality). All 4 returned full reports. **Headline:** security baseline holds (zero CRITICAL — the 12-finding May 30 fix bundle kept its value) but the live agent surfaced a CRITICAL the static audits missed, and the UX agent found a real keyboard-accessibility bug.

### 🔴 P0 — Ship this week (1-2 days)

| Sev | Finding | File:Line | Fix |
|---|---|---|---|
| CRIT-BUG | ~~**Web import (Time Out, etc.) reported broken by user 2026-06-03.**~~ ✅ **Shipped 2026-06-03.** Root cause: Time Out updated list-item markup from `<h3>1. Name</h3>` to `<h3><span>1.</span>&nbsp;Name</h3>`. `stripTags` left `1.&nbsp;Name`; the regex `^\d+\.\s+` ran *before* entity decode, so `&nbsp;` (not `\s`) failed the match → 0 venues. Fix: decode entities BEFORE the regex (`server/import-adapters/timeout.js`). Live re-test against `timeout.com/london/restaurants/best-restaurants-in-london` now extracts 10 of 50 venues (rest lazy-load via JS — addressed by the LLM-adapter row below). **Bonus shipped:** HTTP failure code surfaces in error string (`fetch_failed_404`, `fetch_failed_503`, `fetch_failed_403`) + 4 client toast variants so users get "page moved" vs "site blocking us" vs "temporarily down" instead of generic. +5 jest server (incl. 3 regression for the new shape) + 3 jest client mapper variants. **Verdict on regex adapters: still brittle to site reshuffles, hence the LLM-adapter ship below is the long-term answer.** |
| HIGH-FEAT | ~~**Replace regex-based web-import adapters with a server-side Haiku LLM parser.**~~ ✅ **Shipped 2026-06-03.** `server/import-adapters/llm.js` — Haiku 4.5 with cached system prompt + forced `parse_venues` tool use + 30k-char HTML cap (~10k tokens, ~$0.002/parse). `server/index.js` adapter selection: when `getAnthropicKey(userId)` returns a key the LLM runs for ANY https host that passed the SSRF guard; without a key, falls back to the regex registry (Time Out only) and 400s with `host_not_supported` on other hosts. Errors sanitised at boundary (401 → `llm_key_rejected`, 429 → `llm_rate_limited`, no tool use → `llm_no_output`). `GET /api/anthropic/status` returns `{enabled, mode}` driving the engine-attribution UX. **Pre-fetch hint** mounted under URL input — refreshes on view-switch into Import + on Account-modal Save/Remove (via `_resetWebImportEngineCache`). **Post-parse chip** rendered in the review modal: `🤖 Parsed by Claude Haiku` (violet pill) vs `📋 Parsed by Time Out adapter (regex)` (neutral). Server response carries `engine:'llm'\|'regex'`. +24 jest in `tests/import-website-llm.test.js`: stripHtmlForLLM unit (script/style/iframe/svg/comment strip, entity decode, cap, defensive null), parseVenuesLLM unit (happy/cap/empty-name-defense/snippet-cap/no-key/401/429/no-tool-use), route wiring (any-host with key, timeout.com via LLM not regex, SSRF before engine selection, 401 sanitisation, 429 mapping, engine field always present), `/api/anthropic/status` (enabled+mode+key-leak guard + 401), 4 static markup pins. Cost ~$0.001-0.003/parse after cache warmup. |
| CRIT-LIVE | ~~**3 select dropdowns silently broken** via `data-arg0="this.value"`.~~ ✅ **Shipped 2026-06-03.** Extended `_readPositionalArgs` via new `_resolveArgSentinel(v, el)` that maps `"this"` → `el`, `"this.value"` → `el.value`, `"this.checked"` → `el.checked`, `"this.files[0]"` → `el.files[0]`, `"this.dataset.X"` → `el.dataset[X]`. Also switched the 3 broken selects + FR24 file picker to `data-change`, and replay scrubber + attach-search to `data-input` (proper event semantics). +9 jest in `tests/import.test.js`. **Unblocks: Marker Style toggle, Marker Size Mode, Trip Selector — all functional from the sidebar dropdown.** |
| CRIT-UX-BUG | ~~**Hearts not keyboard-settable** — `data-click="handleHeartKey"` duplicate attribute on each heart span silently overrides `setBucketStrength` (HTML spec: last attribute wins).~~ ✅ **Shipped 2026-06-03.** Replaced duplicate `data-click` with `data-keydown="onHeartKey"` (new ACTIONS entry reading val from `el.dataset.val`); click handler `data-click="setBucketStrength" data-arg0="N"` now wins cleanly. Both click-to-set and keyboard nav (↑/↓/Enter/Space) work. +3 jest pins. |
| HIGH-SEC | ~~**SSRF blocklist missing link-local + IPv6 private ranges** in `POST /api/import/website`.~~ ✅ **Shipped 2026-06-03** alongside the LLM adapter (the LLM path expanded host coverage to any-https, making this finding bite harder). SSRF_BLOCK now includes `169.254.0.0/16`, `metadata.google.internal`, IPv6 link-local `fe80::/10`, IPv6 ULA `fc00::/7` (fc + fd prefixes). New `normalizeHostForSSRF(host)` helper strips `[ ]` from IPv6 hostnames AND decodes IPv4-mapped IPv6 (`::ffff:7f00:1`) back to dotted form (`127.0.0.1`) so the existing IPv4 regexes still fire — Node's WHATWG URL parser was defeating both. Also closed the **MED-1 redirect bypass** found in cybersec review of the LLM ship: `fetch(url, {…, redirect:'error'})` so an attacker can't 301 us into a metadata IP after the hostname check passes. **Still open:** `dns.lookup(host)` + re-apply blocklist for DNS-rebinding / CNAME chain defence — moved to P1. +7 regression jest in `tests/import-website.test.js`. |
| HIGH-SEC | ~~**`err.message` leaked to clients on 500** in 7 catch blocks across Places + backup endpoints.~~ ✅ **Shipped 2026-06-03.** All 7 callsites (`/api/my-backups`, `/api/my-backup`, `/api/places/search`, `/api/places/autocomplete`, `/api/places/sync`, `/api/places/bulk-sync`, `/api/places/discover`) now mirror the narrate pattern: `log('error', '<endpoint>_failed', { userId, error: err.message })` server-side + `res.status(500).json({ error: 'Internal error' })` to client. Upstream Google API error bodies (incl. key hints / URLs / quota info) and `fs` paths no longer reach the wire. +8 jest in `tests/error-sanitization.test.js` (1 per route × 7 + 1 static pin asserting `res.status(500).json({error: err.message})` never re-appears in `server/index.js`). |
| CRIT-PERF | ~~**No HTTP compression middleware.** `index.html` ships at 576 KB raw.~~ ✅ **Shipped 2026-06-03.** `compression@^1.8.1` added; `app.use(compression())` mounted right after the CSP-nonce middleware (early enough to wrap every downstream response, late enough to skip the static `res.locals.cspNonce` set). Default threshold (1 KB) leaves tiny JSON error bodies uncompressed; `index.html` (~580 KB raw → ~140 KB gzip) and `/api/locations` bulk payloads get the win. `Vary: Accept-Encoding` is set by the middleware so caches don't cross-serve gzip ↔ identity copies. +6 jest in `tests/compression.test.js` (dependency pin, gzip on `/`, identity on `/`, Vary header, sub-threshold skip, large-JSON path). |
| HIGH-PERF | ~~**Marker-style toggle does full rebuild** instead of `marker.setIcon()` in place. 1000 markers = 300-600ms main-thread stall.~~ ✅ **Shipped 2026-06-03.** New `updateAllMarkerIcons()` iterates `_renderState.markerById` and calls `marker.setIcon(createMarkerIcon(loc))` in place — reuses L.marker instances, no cluster layer churn, no handler re-binding. Both `setMarkerStyle` and `setMarkerSizeMode` now: in cluster mode + populated registry, take the in-place path (returns true); heat mode and first-paint fall back to `renderMarkers`. Old `_renderState.markerStyle = null` cache-bust gone. +7 jest in `tests/marker-icon-inplace.test.js` (setIcon per marker in cluster, no clearLayers/addLayers, heat fallback, empty-registry fallback, invalid-style coerce, missing-loc skip, static pins) + 4 refreshed tests in `tests/marker-style.test.js` aligned with the new contract. |
| HIGH-LIVE | ~~**Save modal silently fails when lat/lng empty + fields are hidden.**~~ ✅ **Shipped 2026-06-03.** New `_autoGeocodeAddModalIfNeeded()` fires Photon forward-geocode from `quickAddPlace` after the name is set — fills lat/lng/address in place, never clobbers values the user typed during the fetch. `_unhideLocCoordsRow()` flips the (now id'd) `#loc-coords-row` to visible + `scrollIntoView` + `focus` on the lat input when `saveLocation` hits the coords-missing path. Toast copy split: "Please fill in a name." (when name missing) vs "Could not find coordinates. Please enter latitude and longitude." (when name present but geocode missed). +11 jest in `tests/mobile-ux-batch.test.js` (autoGeocode happy/skipped-when-editing/skipped-when-coords-present/skipped-when-empty/network-fail/no-features/no-address-clobber + unhide flips display & focuses + 3 static pins). |
| HIGH-LIVE | ~~**Mobile sidebar covers entire 375px viewport.**~~ ✅ **Shipped 2026-06-03.** `init()` now reads `matchMedia('(max-width: 480px)').matches` and collapses the sidebar by default on first load when the user has no saved `hm_sidebar` preference. Explicit user toggle (`hm_sidebar` = `'0'` or `'1'`) still wins thereafter — desktop default stays "open", and once a mobile user opens the sidebar manually it stays open across reloads. The existing `@media (max-width: 480px)` rules (sidebar `width: 100vw`, toggle slides to `calc(100vw - 44px)` when open) already covered the layout; the missing piece was the auto-collapse default. +3 jest in `tests/mobile-ux-batch.test.js` (CSS rule preserved, init reads matchMedia, explicit-pref precedence). |

### 🟠 P1 — Ship this month (~1 week)

**Security finishing touches** — **5 of 7 closed in S2 hardening batch 2026-06-04 (+16 jest, full suite 986+3skip green, 8/8 e2e green).**
- ~~**Per-endpoint rate limits** on expensive routes — web-import (LLM cost) ✅ **10/min/user shipped 2026-06-03**; narrate + discover still on global 200/min only.~~ ✅ **Closed 2026-06-04** — narrate + narrate-status capped at 10/min/user (LLM cost shape matches web-import); discover capped at 30/min/user (Places Text Search Pro ~$0.032/call → 200/min global = ~$384/hr worst-case → 30/min ≈ $58/hr bound).
- **DNS-rebinding / CNAME-chain SSRF defence** — `dns.lookup(host)` + re-apply blocklist to the resolved IP. The current regex blocklist trusts the WHATWG hostname, so an attacker-controlled DNS name that resolves to a private IP would still pass. Lower priority now that the redirect bypass and direct-IP cases are closed.
- ~~**Web-import snippet → notes server-side sanitisation** (cybersec MED-3 deferred 2026-06-03).~~ ✅ **Closed 2026-06-04** — `sanitizeLocationUpdate` now strips `<script>`/`<iframe>` blocks (case-insensitive, multi-line) + `javascript:`/`vbscript:` URI schemes + caps at 10 000 chars. 9 jest pins covering lowercase/uppercase script, iframe, unclosed-tag, javascript:, vbscript:, length cap, type drop, and legitimate prose unchanged.
- ~~**`photon.komoot.io` missing from CSP `connectSrc`** despite 4 client-side fetches to it~~ ✅ **Closed 2026-06-04** — added next to `nominatim.openstreetmap.org` in the `connectSrc` array. Actual fetch site count = 6 (public/index.html: 4502 / 4757 / 5106 / 9577 / 9792 / 11928 — forward search, reverse, edit-modal enrich, Photon discover). Pinned via Helmet header inspection test.
- ~~**`ANTHROPIC_API_KEY` missing from `render.yaml`** — add `- key: ANTHROPIC_API_KEY\n  sync: false`.~~ ✅ **Closed 2026-06-04.**
- ~~**`@anthropic-ai/sdk: ^0.30.1`** caret on a 0.x → pin exact `0.30.1` + `npm ci`.~~ ✅ **Closed 2026-06-04** — `package.json` + `package-lock.json` both flipped to exact `0.30.1`. `npm install` regenerated cleanly (no concrete version churn — the lockfile was already serving 0.30.1; this prevents a future 0.30.2 from auto-loading).
- **`more.onclick` direct assignment** in 5 callsites (`public/index.html:3925, 4029, 4888, 6723, 10585`) — migrate to `data-click` dispatcher; inconsistent with the project's CSP-compatible pattern.

**Perf round 2**
- **`GET /api/locations` no ETag / no `?since=`** — 5k locations = ~2MB JSON re-shipped on every refresh. Add ETag (max `updatedAt` hash) + 304; later `?updatedSince=`. (`server/index.js:444-446`)
- **`initMap()` blocked by `loadFromServer()`** — swap order so tiles begin fetching immediately. (`public/index.html:10880-10891`)
- **8 CDN script tags render-blocking** (Leaflet, MarkerCluster ×2, Heat, Chart.js, TopoJSON, JSZip, exifr). Defer Chart.js / TopoJSON / JSZip / exifr (~300 KB blocking). (`public/index.html:11-18`)
- **`rebuildIndexes()` O(n) called 28 times/session** including on every modal close. Surgical update on insert/update/delete instead of full rebuild. (`public/index.html` global)
- **`buildTagFilters()` clears+rebuilds whole DOM on every tag click** — toggle `.active` class instead. (`public/index.html:3925, 4015-4045`)
- **`getFilteredLocations()` memo** keyed on `state.filters` + `stateIndex.generation` — skip re-filter when unchanged.
- **`markerHash()` allocates new array + string join per loc per diff pass** — field-by-field compare on registry entry instead.
- **RainViewer frame-list cache** — 5 min TTL; toggling off+on doesn't re-fetch.

**Live functionality fixes**
- **Weather overlay state never persisted to localStorage on toggle ON** (only persists OFF). Confirmed: `activeOverlays: "[]"` even after toggle on. Investigate `_persistActiveOverlays` call site.
- **Photon "not configured" leftover error** — `#search-note` still shows "Google Places not configured" even after user selects Photon provider. Update via `_refreshGoogleChromeVisibility` extension.
- **Quick-add → Add modal no geocoding shortcut** — auto-run Photon search on modal open when name filled but coords empty (overlaps with HIGH-LIVE above).
- **Trip narrate button** — no key warning until submit; show inline warning if `user.anthropicKey` unset and no `ANTHROPIC_API_KEY` env.
- **Password inputs not inside `<form>`** — browser warns + blocks password-manager autofill on Places + Anthropic key fields.

**UX P1 (from UX audit)**
- **Collapse 10-tab nav to 5 + overflow drawer** (Linear pattern). Primary: `Map · Explore · Journal · Trips · Transits`. Overflow `···`: Collections / Regions / Stats / Bulk Edit / Import / Settings. "Explore" = Wishlist + Discover merged; "Journal" = Chronology + Stats. (`public/index.html:1553-1584`)
- **Numeric stats in mono font** — `.stat-value` uses Playfair Display (editorial serif). Switch to `DM Mono` / `JetBrains Mono` per spec. One CSS change. (`public/index.html:6021`)
- **Sidebar twin inputs ("Add place" / "Search place") are confusable** — replace with single search-or-create input OR a floating "+ Add" FAB in bottom-right of map.
- **Map tiles upgrade to Stadia Alidade Smooth Dark** + per-theme tile swap (free for low-volume / personal). Stadia URL: `https://tiles.stadiamaps.com/tiles/{style}/{z}/{x}/{y}.png`. Wires existing theme system to tile choice.

### 🟡 P2 — Polish backlog

Lower-priority findings worth tracking but not blocking:

**Security INFO/LOW (5)** — `revokedJtis` in-memory only (acceptable for personal app; persist to nedb if tightening); dev fallback JWT secret hardcoded (warn in non-prod, randomize per startup); KMZ zip-slip belt-and-suspenders guard (`!n.includes('..')`); `express ^4.18.2` transitive `path-to-regexp` HIGH + `qs` MODERATE — `npm update express` should clear; missing `.env.example`.

**Code-quality (4)** — `loadFromServer` blocks `initMap` (also P1 perf); `render.yaml` free tier wipes data on deploy (upgrade Starter + persistent disk); no ESLint with `no-undef` to catch implicit globals; `logout` swallows errors silently.

**UX MEDIUM/LOW (~12)**
- **Theme switch needs preview** — single 🌙 button cycles themes blind; no `prefers-color-scheme` integration.
- **Category colors not part of theme swap** — `--cat-restaurant: #ff6b6b` stays constant; in Volcano theme red accent + red restaurant marker = no separation.
- **Playfair at 13px uppercase** in `.filter-section h4` strains legibility — switch UI chrome to DM Sans.
- **Stats view = 800px vertical scroll dump** — KPI ribbon + tab-within-stats (Strava pattern).
- **Wishlist actions row always visible** — show on hover/focus only (Things 3 / Linear).
- **Wishlist no `+ Add` in header** when list has items.
- **Trips view 50/50 split hardcoded**; no drag-to-reorder stops; no full-screen map for planning.
- ~~**Regions view zero interaction** beyond color scheme; clicking a country does nothing.~~ ✅ **Partly addressed 2026-06-03** by the Country/Region/City switcher ship (see §"Shipped 2026-06-03" below). Country + Region clicks open a popup listing all visited places in that area; City clicks open the same shape per snapped city. Still open: filter map view by region click, drill-down zoom.
- **Transit legend inline hex colors** not linked to `--success`/`--warning`/`--danger` semantic vars.
- **Two `🏛️` categories** (Monument + Museum) — emoji collision.
- **`#map-search-results` persists** with stale text after sidebar input loses focus.
- **Ad-hoc spacing** (8/10/12/14/16/20/24px) — no 4px-base grid declared.

**Live functionality LOW (5)** — drag-drop has no undo, narrate button no key indicator, wishlist sort on keyboard nav, autocomplete persistence after blur, category emoji collision (overlap with UX above).

### ✨ Power-feature suggestions (synthesized from UX + live agents)

Ranked by impact-vs-effort:

1. **🎁 "Year in Review" auto-story** (Spotify Wrapped / Strava YIR) — full-screen card deck on Jan 1 or on-demand: countries, km traveled, best restaurant, first new country, top travel buddy. Pure frontend, zero new data.
2. **🗺️ Stadia tiles + theme-aware tile swap** — instant premium feel; OSS-friendly.
3. **🏘️ Spatial cluster "Neighborhoods" detector** (Foursquare Swarm) — auto-cluster nearby Been places into named micro-areas ("9 places in Alfama") at zoom ≥13.
4. **📷 Photo timeline** — photos already attached via EXIF; render them on a chronological view alongside visits.
5. **🛣️ Plan-a-Day trip builder from Wishlist** (Google "Plan a day out") — select 3-5 wishlist items → auto walking-order route (Haversine + OSRM) → named Day Trip ready to convert.
6. **🔗 Share trip via public read-only link** (Wanderlog / TripIt) — no account needed to view a shared itinerary.
7. **📡 Offline / PWA mode** — Service Worker + tile cache. Travel app unusable on planes / remote areas today.
8. **🔍 Smart import deduplication** (Notion "this page exists") — fuzzy-match incoming names vs existing locations (Levenshtein <0.2 + within 500m) before commit.
9. **⏱️ Time-of-day heatmap** (Strava activity heatmap) — "you visit restaurants mostly Fri-Sat 8-10pm". Uses existing `visits[].date`.
10. **🧭 Context-aware Discover** — when viewing a trip, default-seed Discover at the trip's centroid + suggest categories the trip is missing (no museums → suggest museums near route).
11. **💱 Currency overlay** for Regions view — local currency symbol + FX rate per country. Trip-budgeting aid.
12. **👥 "People lens" in Chronology** (Tripit companions) — toggle showing each person as a colored lane covering the dates they appear.
13. **📥 Direct Google Maps Saved Places import** (Takeout CSV adapter) — primary first-run seeding source for most users.
14. **🎯 Isochrones / travel-time rings** — concentric "X min by car/walk/transit" from a pinned location. Accommodation + activity planning.
15. **🚫 "Already been" detection on Timeline import** — fuzzy-match vs existing `been` items by placeId or proximity; flag as "update date?" instead of duplicating.
16. **🕸️ Graph view on a renamed "Atlas" tab** (user request 2026-06-03). The current Regions tab is misnamed — it already does Country / Region / City, and a graph view doesn't fit "regions". Rename to **Atlas** / **Geography** / **Spatial**. Add a 4th segmented-control option: **🕸️ Graph** — node-link diagram with one node per visited place (positioned by lat/lng over the dark basemap) and directed edges connecting consecutive chronological visits. Node size = visit count (reuse City-view `sqrt(pop)` shape); edge weight = visit count per pair; edge color by transit mode when a matching `transits` record exists, else neutral. Hover edge → tooltip with date+mode. Variant toggles: **Time window** (all-time / per-year / per-trip) + **Density** (all edges vs top-N busiest). Pure client-side over existing `state.locations` + `state.visits` + `state.transits` indexes — no new endpoints. Lean Leaflet `L.polyline` over SVG for consistency with the other Atlas modes.
17. **🌉 Bifrost ↔ Oikumene bridge** — bidirectional location/trip exchange with the Bifrost travel planner (`projects/ai/travel_planner`). **Oikumene → Bifrost**: "Send to travel plan" action on a location or selection → creates POIs in a Bifrost tour. **Bifrost → Oikumene**: import a Bifrost tour back as a trip with its POIs as locations. Bifrost-side counterparts (sync, location field, "add to tour from marker") tracked in Bifrost's roadmap, not here. No design spike yet.
18. **🌐 Dynamic overlays — Tier 2+.** RainViewer ✅ shipped 2026-06-02 in `20e00d7` (registry pattern + first overlay). Remaining: **USGS earthquakes** (free GeoJSON, lowest-cost ship next), **FlightRadar live** (needs ADS-B Exchange or FR24 key, viewport-bounded refresh), **ISS ground track**, **wind/jet-stream** (Earth Nullschool style), **marine AIS**. Architecture in place — each new overlay is ~30 lines (label + icon + attach/detach) via the `DYNAMIC_OVERLAYS` registry, no toggle-handler changes.

### Sequenced ship plan

| Sprint | Theme | Items | ~Effort |
|---|---|---|---|
| **S1 (this week)** | ✅ **Done 2026-06-03 — all 10 P0s shipped.** data-arg0 dispatcher, hearts duplicate attr, web-import bug, regions interaction (partial), gzip compression, LLM web-import + engine UX, SSRF link-local + redirect bypass, err.message leak, marker-style in-place setIcon, mobile-UX batch (auto-geocode + lat/lng unhide + sidebar auto-collapse). | 0 |
| **S2** | Hardening + perf round 2 | ~~Per-endpoint rate limits, CSP `photon.komoot.io`~~ ✅ + 3 more (SDK pin / render.yaml / notes sanitisation) shipped 2026-06-04. Remaining: ETag on /api/locations, initMap-first, lazy non-map CDNs, surgical rebuildIndexes, RainViewer persist fix, Photon-provider error label, DNS-rebinding SSRF | 3-4 days |
| **S3** | UX redesign batch | Collapse nav to 5+overflow, mono font on stats, FAB add-place, Stadia tiles + theme swap, KPI ribbon for Stats, sidebar command-panel collapse | 1 week |
| **S4+** | Power features | Pick 2-3: Year-in-Review, Neighborhoods cluster, Plan-a-Day, Stadia tiles + theme map, Share-trip link | 1-2 weeks each |

### Cross-audit notes

- **What was already in good shape** (per cybersec agent): server hygiene (Helmet CSP+nonce, HttpOnly+Strict+Secure cookies, ALLOWED_EMAILS fail-closed, ALLOWED_ORIGINS CORS, JWT revocation, rate limiting, sanitizeDoc, path-traversal guard, RainViewer URL allowlist, recent enrichment confirm + Wishlist all clean from XSS).
- **What the static audits missed but live caught:** the `data-arg0="this.value"` dispatcher gap. Recommend adding a Playwright sweep test that exercises every dropdown in the app + asserts state mutation per `change`.
- **What live missed but static caught:** the `data-click="handleHeartKey"` duplicate-attribute keyboard accessibility bug — silently broken keyboard heart-setting was not exercised in live testing because the agent used mouse clicks.

## Resolved (audit 2026-05-30 → reconciled)

| Finding | Resolution |
|---|---|
| **[H-1]** Admin bypass when `ALLOWED_EMAILS` unset | ✅ Phase A `0d2c74c`. `requireAdmin` (`server/index.js:160`) fail-closes when `ADMIN_EMAIL` empty. |
| **[H-3]** `path-to-regexp` ReDoS via Express 4.18.2 | ✅ Lockfile already resolves `express@4.22.1` + `path-to-regexp@0.1.12` (the patched 0.1.x release). |
| **[M-1]** CSP disabled + 7 CDN no SRI | ✅ Phase B `c9f35aa` enabled Helmet CSP with explicit `scriptSrcAttr`/`styleSrcAttr`; `1b10643` added SRI sha384 to 9 pinned CDN URLs. |
| **[M-2]** CORS wildcard when `ALLOWED_ORIGINS` unset | ✅ Phase B `c9f35aa`. `server/index.js:95-98` fail-closes in production (`origin: false`). |
| **[M-4]** `loc.address` rendered unescaped at 4961/5630 | ✅ Phase A. Audit line numbers are stale; current render sites (`4529`, `6689`) use `esc()`. |
| **[L-1]** Password min length 4 | ✅ Phase B `c9f35aa`. `server/index.js:188` checks `< 8`. |
| **[L-2]** `data/admin1-simplified.json` not in `.gitignore` | ✅ Already present (`.gitignore:3`). |
| **[M-3]** `_googleUrl` `javascript:` URI via `getGoogleMapsUrl` | ✅ `e4d0b4f`. `getGoogleMapsUrl` requires `^https?://`; server `sanitizeLocationUpdate` strips bad URIs on write. |
| **[M-5]** `express.json` 10MB global body limit | ✅ `e4d0b4f`. Global dropped to 1MB; path-mounted 10MB on `/api/locations/bulk` + `/api/transits/bulk`. |
| **[L-3]** `render.yaml` `npm install` not `npm ci` | ✅ `e4d0b4f`. Switched to `npm ci` (lockfile-strict). |
| **[L-4]** `render.yaml` missing `ALLOWED_EMAILS` + `ALLOWED_ORIGINS` | ✅ `e4d0b4f`. Both declared with `sync: false`. |
| **[H-2]** JWT bearer in `localStorage`, 90-day TTL, no revocation | ✅ Full path shipped. `53e2db7`: TTL 30d + `jti` revocation + `/api/auth/logout`. `ade84d8`: bearer migrated to `HttpOnly` + `SameSite=Strict` + `Secure`-in-prod cookie; JS can no longer read the token (XSS-exfiltration window closed). |

## Major shipped batches (chronological)

See memory roadmap for full commit-level detail. Headline batches:

- **2026-05-25 → 2026-05-26** — P0/P1 batch (bucket strength, list icons,
  geocode retry, fill-missing, trip dashboard, server-negative-path tests,
  perf Tiers 1+2, collection map view).
- **2026-05-26** — Audit + 5-phase fix sweep (Phases A–E, ~60 findings),
  marker sizing, planner-tab removal, perf Tier 3.
- **2026-05-27** — Transits CRUD + FR24 import + trip-transit sync + stats.
- **2026-05-29** — P0 broken-deletes fix (`53e2db7`), easy-wins security
  batch (`ed39f65`), Transits UX HIGHs (`1b10643`), airport stubs on FR24
  (`c27fbb5`), Playwright harness (4 specs).
- **2026-05-30** — Replay v2 (transit animation), P2 admin+Places tests,
  marker layer-diff perf, FR24 paired-IATA + column-drift + HH:MM:SS fix,
  decommissioned-airports patch, distance-bucket line coloring + per-mode
  dash, click-transit→open-trip, transit-tab structural fix, countries-
  with-flags stats section, M-3/M-5/L-3/L-4 audit batch, FR24 not-an-export
  guard + LOW polish bundle, CSP nonce on `script-src` (`aa479d5`),
  **H-2 HttpOnly cookies migration** (`ade84d8`), **full onclick refactor
  + `script-src-attr 'none'`** (`c9f7ec9` — 217 inline handlers → document-
  level capture-phase dispatcher; +3 e2e specs: view-switch, edit-modal,
  filter-category), **CSS-ify hover-bg bridge** (`342cf0d` — `.hover-bg-tertiary`
  rule replaces the last 4 inline data-mouseover/out sites), **Google data
  ingestion research brief** (`a537b43` — `docs/research/google-data-ingestion.md`),
  **Timeline phone-export parser fix** (`99d0ea2` — real names, `placeId`,
  address, casing preservation), **Import guide refresh for 2024 Google changes**
  (`ac88ce0` — on-device Timeline export path + Saved-folder CSV-list path).
  **Session totals: 560 jest + 8 e2e green.**
- **2026-05-31** — UX batch from user-reported regressions + design pass.
  - **Batch 1** (`3d4933e`): selectTrip invalidateSize-before-fitBounds fix
    (trip-zoom no longer broke on first open); country flags switched from
    regional-indicator emoji to flagcdn.com SVG/PNG (Windows can't render
    🇵🇹-style codepoints — users were seeing "PT" text); country-card click
    `maxZoom` 9→12 (was too zoomed out to tell which cities you'd visited);
    cluster radius 40→30 + `disableClusteringAtZoom: 15` (less aggressive
    grouping at street zoom); `getGoogleMapsUrl` prefers `name+address`
    search over raw coords (lands on the Google place card with reviews
    instead of a generic dropped pin); popup "📍 Open in Google Maps" text
    → 🗺️ icon next to the close ✕ at top-right.
  - **Batch 2** (`0927de7`): sidebar restructure — top of sidebar now has
    "Add place" + "Search place" inputs side-by-side, both at the top;
    the legacy bottom "+ Add New Location" button is gone. `quickAddPlace()`
    opens the add modal pre-filled with the typed name. Modal's redundant
    "🔍 Search Place" field removed (the sidebar already had one). Inline
    5-star rating widget in the popup — click a star to set, click the
    current value to clear, PUT with optimistic UI + rollback toast.
    Tiny `.marker-rating` label below each marker showing Google rating
    preferred / `myRating` fallback. Roadmap bootstrap additions:
    Playwright scraper + beliapp.co import.
  - **Batch 3** (`7c337e0`): edit modal declutter. 13 stacked form-groups
    reorganized into 3 visual sections separated by uppercase dividers:
    **Identity** (Name+Address, Category, Status+Price-in-one-row, Bucket
    strength), **Organize** (Tags, Collections, Trip), **Memory** (My+
    Google Rating, Visits, People, Notes). Lat/Lng inputs hidden via
    `display:none` (still in DOM so search-pick / map-click / edit-open
    paths still populate them; user just can't hand-edit). Visits list
    collapsed from a per-row editable list to a compact "Last visited X
    · N visits total" summary + a single "Add today's visit" button
    (`addTodayVisit()`). Existing visit data preserved in PUT payload.
    New `.modal-divider` CSS rule.
  - **Batch 4** (`5d93e62`): Places API legacy → Places API (New) migration.
    All 3 server helper paths (`fetchPlaceByPlaceId`, `fetchPlaceByText`,
    `/api/places/search` inline) cut over to `places.googleapis.com/v1/places...`
    Key moved from URL query string to `X-Goog-Api-Key` request header
    (security upgrade — never appears in URL/logs again). `X-Goog-FieldMask`
    on every outbound call to cap cost. `priceLevel` string enum
    (`PRICE_LEVEL_MODERATE` etc.) → 0-4 integer mapping at the helper
    boundary, so bulk-sync downstream + frontend consumers stay unchanged.
    Internal helper return shape preserved as a contract. `places.test.js`
    rewritten: 15 → 19 tests (+enum round-trip, +headers-present, +defensive
    unknown-enum, +key-not-in-URL).
  - **Batch 5** (this commit): Top-rated Discovery feature end-to-end.
    `POST /api/places/discover` — server proxy to `places:searchText` with
    `includedType` + `locationBias.circle` + server-side `userRatingCount`
    filter (default ≥1000), sort by userRatingCount desc, cap at 20. A
    `CATEGORY_TO_PLACE_TYPE` map covers the 10 queryable category keys.
    Frontend: ✨ "Discover top-rated" button in the sidebar search section
    → modal (category select + radius km + min-ratings) → result cards with
    rating, count, price level, address → "+ Bucket" button adds the place
    to the bucket list via `POST /api/locations`. All events through the
    `data-click` dispatcher (no `onclick=`). All user/API strings escaped
    via `esc()`. Font sizes ≥ 12px (a11y floor). 7 new tests in
    `places.test.js` (happy/filter/sort/cap/bad-coords/bad-category/
    api-error/radius-clamp); 1 skipped (501 no-key path: env key captured
    at module load, can't clear mid-run). Builds on Batch 4's Places API
    (New) infrastructure — same auth header, same FieldMask, same priceLevel
    enum mapping.
  - **Session totals: 579 jest + 8 e2e green (1 skip).**
  - **Batch 6** (this commit): Narrate-a-trip feature end-to-end. Haiku 4.5
    (`claude-haiku-4-5-20251001`) with cached system prompt + forced tool use
    (`parse_trip` schema). `POST /api/trips/narrate-status` (enabled check)
    + `POST /api/trips/narrate` — parses free-form description to structured
    name/dates/stops JSON. Per-user `user.anthropicKey` + `ANTHROPIC_API_KEY`
    env fallback (mirrors Google Places key pattern exactly). SDK loaded with
    dynamic `require` to avoid startup cost. Errors sanitized at boundary
    (401 → "API key rejected", 429 → "Rate limited" — never leaks upstream
    message body). Frontend: ✨ "Narrate" button in Trip Manager footer →
    textarea modal → Parse → preview (trip name + dates + stops list) →
    "Create trip" one-click (POST /api/trips, stops bundled into `notes` as
    markdown). Account modal grows a parallel Anthropic API key section
    (Connected/Not-connected, change-key details, Save/Remove, mirrors
    Places section structure). Auto-creating stops as bucket locations
    shipped in **Trips v2** (this session) — see entry below. Cost ~$0.001/parse
    after prompt-cache warmup. 14 new tests in
    `tests/narrate.test.js` + `tests/narrate-nokey.test.js` (12 pass,
    2 skip with documented reason — no-key path requires separate module
    instance, covered by narrate-nokey.test.js).
  - **Session totals: 594 jest + 8 e2e green (3 skip).**
  - **Batch 7** (this commit): Live autocomplete on sidebar Add/Search inputs.
    Both `#quick-add-input` and `#map-search-input` now fire debounced (250ms)
    typeahead via `/api/places/search` when Google is configured, with Nominatim
    (`nominatim.openstreetmap.org`) fallback. Results render inline below both
    inputs (reusing `#map-search-results`) with rating + price + address chips.
    Each result has "+ Add" (opens add modal pre-filled with name/address/coords/
    googleRating/priceLevel) and "📍" (pans map to result, keeps results open).
    Race protection: in-flight results discarded if the input query has moved on
    (`AbortController` + value-mismatch guard). `liveSearchInput` added to `ACTIONS`
    (receives `el, e` to read `data-livesearch-source`; avoids `data-arg0` collision
    with the existing `enterKey` handler on the same elements). `_liveSearchDebounce`
    + `_liveSearchAbort` module-level vars. Dispatcher bugfix note: `466c897` already
    fixed `_runAction` unconditionally calling `e.preventDefault()` for `data-prevent`
    (was blocking typing). 9 new regression tests in `import.test.js` (dispatcher
    wiring, livesearch-source attrs, escape, no-inline-onclick, race-check, modal
    pre-fill, map.setView).
  - **Session totals: 607 jest + 8 e2e green (3 skip).**
  - **Batch 8** (this commit): Cheaper typeahead — Autocomplete + session tokens + Photon free provider.
    New `POST /api/places/autocomplete` (Essentials tier, ~$0.0028/call vs Text Search Pro $0.032). Returns
    predictions (placeId + main/secondary text) only — full lat/lng/rating/price fetched on click via existing
    `/places/sync`. `sessionToken` bundles all autocomplete calls + the final Place Details lookup as ONE
    session billing event. Per-session cost drops from ~$0.16 to ~$0.017 (90% saving on heavy typers).
    `fetchPlaceByPlaceId` extended to accept + append `sessionToken` query param to Place Details URL.
    `/api/places/sync` threads `sessionToken` from request body through to `fetchPlaceByPlaceId`.
    Search provider switchable in Account settings dropdown: **Google Places** / **Photon** (free, no key,
    OSM-based, fast, hits `photon.komoot.io` directly from browser — CORS-friendly) / **OSM Nominatim**
    (free, no key, basic). `getSearchProvider()` allows `'google'|'nominatim'|'photon'` (was binary);
    `setSearchProvider()` validates against the allowlist + resets `_placesEnabled` cache. Provider select
    added as a static section in the Account modal HTML (`#account-search-provider`) with `data-change=
    "onSearchProviderChange"` — initialized from `localStorage` on modal open. `_runLiveSearch` fans out
    to the three providers; Google path uses the new autocomplete endpoint with `_getOrCreateSessionToken()`;
    Photon + Nominatim hit external APIs directly with `AbortController` signal for race-safety.
    `liveResultAdd` + `liveResultGo` are now `async` — Google results call `/places/sync` with the same
    session token to resolve lat/lng/rating/price; `_resetSessionToken()` marks the session consumed after
    the sync call. 8 new server tests (autocomplete happy/sad/session paths, sync sessionToken threading)
    + 9 updated/new frontend regression tests in import.test.js.
  - **Session totals: 619 jest + 8 e2e green (3 skip).**
  - **Batch 9** (this commit): Three-provider enrichment everywhere. Edit modal
    grows two sibling sync buttons next to the existing 🔄 Google: **🌍 Photon**
    (`syncPhotonFromEditModal` — forward search on `photon.komoot.io` with
    coord bias) and **🗺️ Nominatim** (`syncNominatimFromEditModal` — reverse-
    geocode when coords present, forward when not). Both are conservative
    fill-only (don't overwrite user-entered address/lat/lng), use
    `osmToCategory()` to fill missing categories, stamp `_photonSyncedAt` /
    `_nominatimSyncedAt`, PUT via `/api/locations/:id`. Bulk-edit toolbar
    grows a 🌍 Photon button alongside the existing 🗺️ OSM (renamed Nominatim
    in the title) and 📍 Google; `bulkEnrichPhoton` iterates selected,
    polite 100ms between Photon calls, fill-only. Account modal Search
    Provider section restructured into a dropdown + three explainer cards
    ("🌍 Photon · Free · no key" / "🗺️ Nominatim · Free · no key" / "🔄 Google
    · Paid · key required") so the role of each provider is clear at a
    glance. `syncFromEditModal` button label restoration trimmed `🔄 Sync Google`
    → `🔄 Google` for consistency. 9 new regression tests in import.test.js.
  - **Session totals: 628 jest + 8 e2e green (3 skip).**
  - **Late-afternoon batch** (chronological, batch numbers retired — per-commit detail in memory roadmap):
    - `ba10ed8` 📍 My-location button in sidebar (`navigator.geolocation`,
      pan+zoom + accuracy halo + "+ Add place here" popup CTA).
    - `c961b6b` **CRITICAL FIX** `data-arg-N="this"` regression. After the
      CSP refactor, 13 dispatcher callsites were passing the literal string
      `"this"` to receivers expecting an element ref (`.classList.add` of a
      string silently crashed). Fix in `_readPositionalArgs`: map
      `v === 'this' ? el : v`. Codified discovery: `data-argN="this"` is the
      canonical element-ref sentinel.
    - `6d3906f` Google Photos integration research brief
      (`docs/research/google-photos-integration.md`). Path 1 (Photos Library
      API) dead since 2025-03-31 scope removal. Path 3 (manual EXIF drop)
      recommended; Path 2 (photo-org bridge) queued.
    - `29ce8f1` **Trips v2 — narrated stops auto-geocoded** into bucket
      locations linked by `tripId` + `tripOrder`. Photon → Nominatim →
      placeholder fallback (no lat/lng) so nothing is lost. Trip POST
      decoupled from stop loop. Helper `geocodeNarratedStop(name)` factored
      out for unit testing. 15 new jest in `tests/trips-v2.test.js`.
      **Wishlist entry closed.**
    - `febb14d` + `8134bdb` **Time Out / website import v1.** Extensible
      `WEBSITE_IMPORT_ADAPTERS` registry, first adapter `timeout.js`.
      HTTPS + SSRF guard (localhost, RFC1918, IPv6 loopback). 10s timeout,
      5MB cap. JSON-LD ItemList primary + numbered-headings fallback. 🌐
      Web Import section in Import view + review modal. 53 new jest.
      **Wishlist entry closed.**
    - `c993276` Roadmap-only — mark Time Out shipped.
    - `c417584` **Google Photos Path 3 v1 — EXIF drop zone** in edit modal
      Memory section. `exifr@7.1.3` via jsdelivr CDN with SRI sha384.
      Parses `{filename, lat, lon, takenAt}`; distance check warns when
      photo GPS > 5 km from location. Server: `media` field allowlisted,
      per-entry schema sanitized, cap 100. 20 new tests (16 client + 4
      server). Path 3 of the research brief shipped.
    - `ef278cf` **UX batch (3 asks).** (a) Bucket-strength ↔ Rating swap —
      modal shows only hearts when `status=bucket`, only stars when `=been`;
      both fields persist regardless. Sidebar gains a "Want-to-Go Strength"
      min slider. (b) Popup delete moved from top-right (next to Leaflet's
      native ×) to bottom action row as 🗑️ icon. (c) Discovery routes by
      `getSearchProvider()` — Google: existing endpoint; Photon: new
      client-side `_photonDiscover` (OSM tag filter, post-haversine, sort by
      distance, cap 20); Nominatim: friendly steer toast. 7 new tests in
      `tests/discover-provider.test.js`.
  - **Session totals before compact: 733 jest + 8 e2e green (3 skip).**
  - **Post-compact session — afternoon batch:**
    - `3683adf` **Provider-respecting Google chrome + Visits expand/remove +
      Timeline import button (4 asks).** (a) `_refreshGoogleChromeVisibility()`
      single point of truth — toggles modal sync btn, bulk toolbar btn, and
      import auto-sync label based on `shouldUseGoogle()` (provider===google
      AND placesEnabled); hooked from `onSearchProviderChange` + boot;
      Photon/Nominatim users no longer see Google chrome even with a key
      set. (b) Visits modal collapsible — summary line stays visible, click
      expands to per-visit editable `<input type="date">` + × remove; new
      `+ Today` and `+ Add date` buttons. (c) All visits already persisted
      (verified). (d) Discoverable `📅 Import Timeline JSON` button in
      Import view's Google Data Guide → Timeline section reuses the existing
      `parseJSON` → `parseGoogleTimelineSegments` path. 17 new jest in
      `tests/visits-google-chrome.test.js` (visits flow + provider matrix +
      static markup pins). Cybersec audit clean.
    - `acd0332` Timeline import surfaced on Chronology view — small
      `📅 Import Timeline` button in chrono-header (sibling to year/cat/trip
      selects) + primary `📅 Import Timeline JSON` CTA in the "No Visits
      Yet" empty state. Single hidden file input, three CTAs (Import view +
      Chronology header + Chronology empty state) — call-to-action lands
      where the user feels the absence. +1 test (cross-location pin).
    - `73e6ca3` Trips-view Timeline button differentiated from the morning's
      individual-place buttons. Pre-existing `importTripFromTimeline`
      bundles visits into a NEW trip with stops — materially different
      from the new buttons that drop individual places. Label
      `📂 Import from Timeline` → `📂 Timeline → New Trip` + tooltip
      explaining the trip-bundling behavior; the three individual-place
      buttons each gained a tooltip cross-referencing the trip-view button.
      Both flows stay — both legitimate. +1 test.
    - **Beli adapter investigation** — see Open section above for verdict
      (architecturally blocked, user-confirmed skip).
  - **Session totals after post-compact afternoon: 752 jest + 8 e2e green (3 skip).**

- **2026-05-31 late evening — popup + cluster + dispatcher batch (5 commits, +32 jest).**
  - `fdc4ef8` Inline "Log visit today" button on marker popup. New
    `logTodayFromPopup(locId)` async fn: optimistic visit append + PUT,
    rollback on failure. TOCTOU race guard via module-level
    `_logTodayInFlight = new Set()`. Popup patched in-place via
    `marker.getPopup().setContent(...)` so it stays open on success;
    bucket→been status flip path closes the popup + re-renders markers
    (status change affects icon class). +7 jest in
    `tests/visits-google-chrome.test.js` (idempotent / popup-patch /
    flip path / rollback / race / missing-loc / static markup).
  - `4de764f` Cluster threshold `disableClusteringAtZoom: 15→12`. User
    wanted unclustered markers earlier; at z=12 viewport holds ~50-200
    markers — well within Leaflet's budget, and the incremental-diff
    render path viewport-culls already.
  - `18f92ef` Fix 3 split-onclick leftovers from the CSP dispatcher
    migration. The `c9f7ec9` migration mechanically split
    `onclick="fn(arg).then(...)..."` at the first `(`, capturing the
    tail as a literal string in `data-arg0`. Three hits: (a) `+ New
    Trip` button — removed `.then(()=>{populateTripSelector();}` from
    arg0, added explicit call at end of `promptNewTrip` try block; (b)
    Collection-card click — replaced inline-composed `switchView`+
    `setTimeout(openEditModal)` with new `switchToMapAndEdit(locId)`
    composer; (c) Attach checkbox — `data-arg1="this.checked"` →
    `data-arg1="this"` + `toggleAttachSelect(id, el)` reads
    `el.checked` (canonical sentinel pattern). +6 jest in
    `tests/dispatcher-arg-leftovers.test.js` (all three call sites
    pinned + receiver-signature pins).
  - `0b8c42f` Popup consolidation + enrichment confirmation flow (5
    user asks). (a) Popup actions: removed redundant Bucket/Been
    toggle — clicking "Been" now logs today's visit AND atomically
    flips bucket→been (`toggleStatusFromPopup` deleted; consolidated
    into `logTodayFromPopup`). (b) Edit button alignment fixed — all 3
    popup-row buttons (Been / Edit / Delete) now share
    `padding:8px 12px` for uniform appearance. (c) Edit modal: new
    "Enrich data" form-group at the TOP with 🌍 Photon / 🗺️ Nominatim /
    🔄 Google buttons (was buried under Google Maps Rating); old row
    removed. (d) **Photon "doesn't work" fix** — root cause was the
    fill-only conservative filter that silently skipped fields with
    any existing value. Refactor: fetch ALL fields, build diff list
    with `buildEnrichmentDiffs(loc, proposed)`, surface in new
    `showEnrichmentConfirm(sourceLabel, diffs)` modal — per-field
    checkbox, fills default-checked, overwrites default-unchecked.
    `applyEnrichmentUpdates(loc, updates, syncedAtField)` PUTs only
    user-approved subset + stamps source-specific syncedAt. All three
    sync functions (`syncFromEditModal`, `syncPhotonFromEditModal`,
    `syncNominatimFromEditModal`) now route through this flow. (e)
    Google Maps button moved out of enrich row — now inline next to
    Name label as "🗺️ View on Maps" link; the actual `🔄 Google` sync
    button lives in the new Enrich row with consistent styling.
    +14 jest in `tests/enrichment-confirm.test.js` (pure
    `buildEnrichmentDiffs` + interactive `showEnrichmentConfirm` with
    JSDOM + XSS regression + static markup pins).
  - `94bedd3` Trips view zero-trips empty state. New
    `_renderTripDetailEmpty()` helper picks "No Trips Yet" copy + 3
    CTAs (manual / Timeline → New Trip / AI Narrate) when
    `state.trips.length === 0`; falls through to "Select a Trip" copy
    otherwise. Wired into `selectTrip(null)`, delete-trip flow, and
    `switchView('trips-view')` hook so zero-trip users see actionable
    CTAs instead of "Choose a trip from the dropdown" (which is empty).
    +5 jest in `tests/trips-empty-state.test.js`.
  - **Session totals after late-evening batch: 784 jest + 8 e2e green
    (3 skip).**

- **2026-06-01 marker batch — bucket fill + gold/silver stars + popup
  labels + drag-drop + bucketlist bootstrap (4 commits, +26 jest).**
  - UX consult (ux-designer subagent) for bucket marker visibility +
    star badge composition + rating-source pick. Memo recommendations:
    violet wishlist fill `rgba(139,92,246,0.18) !important` + ring
    shadow (replaces opacity:0.8 penalty); 14px gold/silver `★` badge
    top-right `-6px`; prefer first-person score (myRating) over
    Google aggregate.
  - `37860c6` Popup button differentiation + bucket fill + gold/silver
    star badge (5 edits). (a) Popup button text differentiates by
    status — bucket → `✅ Mark as Been`, been → `📍 Visit today` (was
    always "✅ Been" — confusing). (b) `.marker-icon.bucket` violet
    fill + ring shadow per UX memo, opacity penalty removed. (c) New
    `.marker-rating-badge` CSS (`.gold` #f59e0b + `.silver` #94a3b8),
    top-right corner. (d) `createMarkerIcon` renders star badge for
    rating ≥ 4.0 (gold ≥ 4.5, silver 4.0-4.5), numeric tag for <4.0,
    nothing for unrated. (e) `logTodayFromPopup` gains falsy-locId
    guard. +10 jest in `tests/marker-style.test.js` (6 vm-sandbox
    `createMarkerIcon` + 4 static markup pins) + adjusted
    `tests/visits-google-chrome.test.js` button label pin +
    `tests/import.test.js` rating-source pin. Cybersec audit clean.
  - `16e69b9` Status-conditional rating source for marker badge. User
    feedback: "i meant google maps rating" — fix the source pick so
    bucket items use `bucketStrength` (the user's want-to-go score)
    rather than `myRating` (which is 0 for bucket — they haven't been
    yet). Bucket → `bucketStrength || googleRating`; been →
    `myRating || googleRating`. Same gold/silver thresholds applied
    to whichever number wins. +7 jest covering bucket-source paths
    (strength 5/4/3, fallback to google, source-wins-over-google,
    no-rating, been regression).
  - `5839558` Show numeric rating tag alongside the gold/silver star
    badge. User: "i still want the rating below". Prior behavior:
    badge REPLACED numeric. New: badge complements — at-a-glance star
    PLUS precise value (`5.0`, `4.7`, etc). Negligible perf — one
    extra `<span>` per qualifying marker. Sub-4.0 ratings keep
    numeric-only; no-rating still renders nothing.
  - `795256f` Drag markers to relocate (drag-drop on the main map).
    All 4 main-render L.marker calls pick up `draggable: true`;
    `bindMarkerBehavior` wires `dragend` → new
    `handleMarkerDrop(marker, loc, newLatLng)` async fn. Optimistic
    update of loc.lat/lng + PUT `{lat,lng}`. Per-loc in-flight Set
    guard (`_dragDropInFlight`) prevents racing PUTs. Client bounds
    guard mirrors server `validateLocation` (NaN/|lat|>90/|lng|>180 →
    snap marker back + error toast, no PUT). Failure path:
    rollback loc + `marker.setLatLng(prev)` + error toast. Trip-view
    and Collection-focus markers stay non-draggable (sequence
    semantics + they don't call `bindMarkerBehavior`). +7 jest in
    `tests/marker-drag.test.js` (happy + rollback + 3 bounds guards
    + concurrent in-flight + 3 static markup pins). Cybersec audit
    clean (server PUT already filters by `userId`, no IDOR; toast
    uses `textContent` not `innerHTML`).
  - **Data-side bootstrap (no commits — JSON staged on Desktop +
    Google Tasks #bucketlist cleanup):**
    - 17 items from Google Tasks `#bucketlist` (list id
      `VzM0QTAyMnpIbVcySG5kYQ`) geocoded via Photon (1.1s polite
      gap + Nominatim fallback) into Oikumene-export-shape JSON
      ready to drop into Import view. Two coords manually patched:
      "1 year around the world" (Photon matched "Equator" to a
      Washington State street) → Lisbon home anchor;
      "Trans-Siberian Railway" → Moscow western terminus (Photon
      picked Vladivostok end). Three Berlin-start routes will
      stack at 52.517,13.395 — drag-drop ships in the same batch
      so user can spread them post-import.
    - All 17 imported titles deleted from Google Tasks
      `#bucketlist` via `gws tasks tasks delete`. 32
      non-geographic items remain (Yoga, Skydive, Build PC,
      Cricket, programming reddit links, etc. — separate
      disposition path).
    - **9 family places ("Fazer com miúdas")** geocoded same way:
      Planetário Gulbenkian, Galeria do Loreto, MUDE, Museu do
      Ar, Aldeia da Mata Pequena, Palácio de Monserrate, Museu
      dos Coches, Casa-Museu Amália Rodrigues, Casa Fernando
      Pessoa. MUDE coord patched manually (Photon matched a
      different museum at Largo Júlio de Castilho in Restelo —
      real MUDE is Rua Augusta 24, Baixa). Tagged
      `fazer-com-miudas` + `family`, `bucketStrength: 4`. JSON
      staged at `~/Desktop/bucketlist-import-2026-06-01/`.
  - **Session totals after marker batch: 810 jest + 8 e2e green
    (3 skip).**

- **2026-06-02 — Wishlist + 4 marker style variants + RainViewer
  weather overlay + full multi-domain audit (4 commits, +60 jest).**
  - `087df07` **Wishlist view** — new ⭐ nav tab between Chronology and
    Trips. Cards for every `status:'bucket'` location with star badge
    (gold ≥4.5 / silver ≥4.0), ♥ strength hearts, tag chips, and a
    4-action row (📍 Map / ✅ Been / ✏️ Edit / 🗑️). Sort by Strength
    (default) / Rating / Name / Recently-added. Filter by tag, category,
    or full-text search. Pagination 100/page. Closes the visibility gap
    from the 26 imported bucket items. Reuses `logTodayFromPopup` for
    Been action, `openEditModal` for Edit, `showConfirm` for delete.
    Cybersec audit found 2 issues (native `confirm()` → `showConfirm`;
    missing numeric guard on badge `toFixed`) — both fixed pre-commit.
    +13 jest in `tests/wishlist-view.test.js`.
  - `1a71d0f` **4 marker style variants + sidebar toggle.** New "Marker
    Style" dropdown next to "Marker Size" with 5 options: Circle
    (default, preserved), **Squircle** (iOS app-icon superellipse via
    `border-radius: 22%`), **Teardrop** (Apple Maps pin, anchor at
    bottom-point), **Glyph** (Mapbox/Raycast minimal: emoji + dot, no
    bg), **Pill** (Linear-style chip with `★X.X` rating inline).
    Architecture mirrors `markerSizeMode`: `VALID_MARKER_STYLES` +
    `setMarkerStyle` + localStorage + `createMarkerIcon` branches per
    shape (`iconSize`/`iconAnchor`/`popupAnchor` differ). Status colors
    + corner badge preserved for all styles except pill (inline rating)
    and glyph (suppresses bottom numeric tag for cleaner minimalism).
    Live-tested with 4 seeded locations (2 been, 2 bucket, mixed
    ratings). +21 jest. Cybersec audit clean (8 focus areas, zero
    issues + 1 LOW cosmetic note on glyph mobile visibility).
    **⚠️ Live audit 2026-06-02 later surfaced that the sidebar
    dropdown is silently broken via `data-arg0="this.value"` — see
    Audit 2026-06-02 P0 above.**
  - `20e00d7` **RainViewer weather radar overlay** — first dynamic
    overlay shipped via the `DYNAMIC_OVERLAYS` registry. 🌧️ button in
    map top-right next to 📍 and ✨. Browser-side fetch of
    `api.rainviewer.com/public/weather-maps.json` → `L.tileLayer` at
    `zIndex:400` with opacity 0.6. Frame metadata cached 10 min.
    localStorage persistence. CSP `connectSrc` gets `api.rainviewer.com`;
    tile loads covered by existing `imgSrc: https:`. **Registry pattern
    is the extensible deliverable** — future overlays (USGS, FlightRadar,
    ISS) slot in as new entries without touching toggle handler.
    Cybersec found 2 MEDIUM + 1 LOW, all fixed pre-commit with
    regression pins: `RAINVIEWER_HOST_RE` + `RAINVIEWER_PATH_RE`
    allowlists block `javascript:` host injection; `_overlayAttachInFlight`
    Set guards double-click race; `hasOwnProperty.call` blocks inherited
    prototype keys in `DYNAMIC_OVERLAYS[key]` access. Live-verified in
    Playwright: poisoned host blocked + fell back to safe default,
    double-click attached exactly 1 layer, ~60 tiles loaded from
    `tilecache.rainviewer.com` on toggle-on, clean detach.
    +26 jest in `tests/overlays.test.js`.
  - `c5d229d` **Full multi-domain audit** logged (this batch — security
    + UX + code + perf + live functionality, 4 parallel specialist
    agents). See [Audit 2026-06-02](#audit-2026-06-02-full-multi-domain)
    section above for the full table.
  - **Session totals after 2026-06-02 batch: ~870 jest + 8 e2e green
    (3 skip).**

- **2026-06-03 — Regions Country/Region/City switcher + web-import bug fix +
  status-tagged HTTP errors (905 jest + 8 e2e green).**
  - **Regions tab — 3-view switcher.** New segmented control in Regions
    header: 🏳️ Country | 🗺️ Region (default) | 🏙️ City. Switcher uses
    existing `.filter-group-btn` pattern; color-scheme select migrated
    `data-click` → `data-change` (the prior wiring was silently broken
    since `change` is the only event fired for `<select>`).
    - **Country view**: aggregates admin1 features by `properties.country`
      via new `aggregateRegionsByCountry(geo, regionCounts)`. Paints whole
      countries at `weight: 0` so adjacent same-country regions blend into
      a single shape; basemap (`dark_nolabels`) provides faint outlines.
      Click country → popup lists all visited places in that country.
    - **City view**: bundled new asset `public/cities.json` (4.2 MB,
      107,200 cities pop ≥ 1000 from GeoNames `cities1000` via the
      `all-the-cities` npm package, filtered to real city feature-codes —
      excluded PPLX/PPLL/PPLH/PPLW/PPLQ/PPLCH/PPLR/STLMT to avoid snapping
      to neighborhoods like Tiergarten / The Rocks / Financial District).
      Build script at `scripts/build-cities-json.js` is reproducible.
      Compact tuple format `[lat, lng, name, iso2, pop]` sorted by pop
      desc. Snap algorithm: 1°×1° grid index for O(~20) candidates per
      visit; **tiered selection** — most populous within 25 km wins
      (megacity beats neighborhood), else nearest within 50 km, else drop.
      This means Statue of Liberty snaps to "New York City" (pop 8.1 M)
      not "Financial District" (60 k); Eiffel + Louvre both → "Paris"
      (2.1 M), Sydney Opera → "Sydney" (4.6 M), Brandenburg Gate →
      "Berlin" (3.4 M), Golden Gate → "San Francisco" (864 k). Markers
      are `L.circleMarker` sized `sqrt(pop)` clamped to [4, 40] px, color
      intensity by visit count via the existing color-scheme dropdown.
      Click city → popup lists visits snapped to that city.
    - +17 jest in `tests/regions-views.test.js` (markup pins, country
      aggregation correctness, haversine sanity, tiered-snap with both
      tier-1 and tier-2 paths, grid boundary scan, radius scale).
      Live-verified in Playwright with 24-location seed across 6
      countries; screenshots of all 3 modes captured.
  - **Web import bug fix.** User reported "web import is not working e.g.
    timeout". Root cause: Time Out updated list-item markup from
    `<h3>1. Name</h3>` to `<h3><span>1.</span>&nbsp;Name</h3>`. The
    regex `/^\d+\.\s+/` ran *before* entity decoding, so `&nbsp;`
    (literally `&nbsp;` at that point) didn't match `\s` → 0 venues
    extracted. Fix in `server/import-adapters/timeout.js` — decode
    entities BEFORE the regex check. Live re-test against
    `timeout.com/london/restaurants/best-restaurants-in-london` now
    extracts 10 venues (the page has 50 total but the rest lazy-load
    via JS — addressed by the LLM-adapter HIGH-FEAT item above).
  - **Status-tagged HTTP errors for /api/import/website.** Encoded
    upstream HTTP status into the `error` string (`fetch_failed_404`,
    `fetch_failed_503`, `fetch_failed_403`) so the existing single-string
    error contract carries the cause through to the client toast. Added
    3 client-side toast variants: "page moved (404)" vs "site blocking
    us (403/401)" vs "temporarily down (5xx)" vs the generic catch-all.
    Time Out reshuffles URLs frequently and the prior "Could not fetch"
    was unhelpful when the real issue was just a 404.
  - **Roadmap entry added** for "Bootstrap preset collections" (user
    idea — UNESCO sites, National Parks, Airports, Stadiums, Wonders,
    etc. as ready-made opt-in collections — see Wishlist section).
  - **Decision recorded:** server-side Haiku adapter (option a) over
    browser-side WebLLM (option b). Reason: 100-500 MB model download
    tax on every user is the wrong shape for a tier-3 occasional
    feature. Haiku at ~$0.002/parse + BYOK reuses existing Anthropic
    wiring from Narrate. HIGH-FEAT row above now specifies the engine
    attribution UX (pre-fetch hint + post-parse chip) so users know
    upfront which engine will run and after which engine did run.
  - **Session totals after 2026-06-03 batch: 905 jest + 8 e2e green
    (3 skip).**
  - **gzip compression middleware (P0 audit ship).** `compression@^1.8.1`
    added and mounted right after the CSP-nonce middleware in
    `server/index.js`. Render doesn't auto-gzip Node responses, so
    `index.html` was shipping at ~580 KB raw on every cold load; with the
    default zlib level + `threshold: 1024` it compresses to ~140 KB
    (~4× reduction) and `/api/locations` JSON gets a similar win on
    accounts with hundreds of locations. `Vary: Accept-Encoding` is
    auto-set so shared caches keep gzip and identity copies separate.
    No app code touched beyond the middleware mount; CSP nonce continues
    to template correctly because compression wraps `res.end`/`res.write`
    AFTER `serveIndex` already substituted the placeholder. +6 jest in
    `tests/compression.test.js` (dep pin, gzip on `/`, identity on `/`,
    `Vary` header, sub-threshold skip stays uncompressed, large-JSON
    `/api/locations` round-trip).
  - **Session totals after gzip ship: 911 jest + 8 e2e green (3 skip).**
  - **LLM-powered web-import adapter (P0 audit ship, HIGH-FEAT).** Brittle
    Time Out regex → any-URL Haiku-powered parser. New
    `server/import-adapters/llm.js` exports `parseVenuesLLM(html, url, apiKey)`:
    HTML stripped of `<script>/<style>/<noscript>/<iframe>/<svg>/<!-- -->`,
    entities decoded, capped at 30k chars (~10k tokens, ~$0.002/parse) → sent
    to Haiku 4.5 with cached system prompt + forced `parse_venues` tool use →
    returns `{city, articleTitle, venues:[{name,address,snippet}]}` with
    defensive cleaning on the way out (drop empty-name rows, cap snippet at
    200 chars, cap venues at 100). Mirrors `parseTrip()` shape from narrate;
    BYOK per-user key + `ANTHROPIC_API_KEY` env fallback; errors sanitised at
    boundary (401 → `llm_error_401`, 429 → `llm_error_429`, no tool use →
    `llm_no_tool_use`).
    `POST /api/import/website` rewired: when `getAnthropicKey()` returns a key
    the LLM runs for ANY https host that passed the SSRF guard; without a
    key, the regex registry (Time Out only) is the fallback and other hosts
    return `host_not_supported`. Response carries `engine:'llm'|'regex'`.
    Route-level error mapping: `llm_error_401` → `llm_key_rejected` (HTTP 401),
    `llm_error_429` → `llm_rate_limited`, `llm_no_tool_use` → `llm_no_output`,
    `llm_sdk_missing` → `llm_unavailable`. **Engine attribution UX** —
    new `GET /api/anthropic/status` returns `{enabled, mode:'smart'|'basic'}`;
    new `#web-import-engine-hint` placeholder under the URL input refreshes
    via `refreshWebImportEngineHint()` on every Import view entry + clears the
    cache on Account-modal Save/Remove (`_resetWebImportEngineCache`). Result
    modal grows a chip (`data-engine="llm"` violet pill: 🤖 Parsed by Claude
    Haiku; `data-engine="regex"` neutral pill: 📋 Parsed by Time Out adapter
    (regex)). Friendly client toasts added for the 5 new error shapes
    (`mapWebImportError`). +24 jest in `tests/import-website-llm.test.js`
    (4 stripHtml unit, 7 parseVenuesLLM unit, 2 status endpoint, 6 route
    wiring incl. SSRF-before-engine, sanitisation, engine field shape,
    4 static markup pins, 1 host_not_supported semantics). Cybersec
    considerations: HTML body is attacker-controlled but forced-tool-use
    constrains output to schema (worst case: fabricated venue rows reviewed
    in modal before commit); SSRF guard unchanged + runs before adapter
    selection so LLM cannot bypass it; per-user BYOK so a malicious user
    can only burn their own quota; all upstream Anthropic errors sanitised
    to single-string codes.
  - **Session totals after LLM-import ship: 935 jest + 8 e2e green (3 skip).**
  - **Cybersec review fixes (same ship, fold-in).** Sonnet cybersec review of
    the LLM adapter surfaced 0 CRIT / 0 HIGH / 4 MED / 2 LOW / 2 INFO.
    Fixed in the same commit: **MED-1 SSRF redirect bypass** —
    `fetch(url, {…, redirect:'error'})` so a 301/302 from an attacker-
    controlled host can't be used to bounce the server-side fetch into a
    private/metadata IP after the SSRF_BLOCK hostname check passed.
    **MED-2 SSRF_BLOCK gaps** — added `169.254.0.0/16`,
    `metadata.google.internal`, IPv6 link-local `fe80::/10`, IPv6 ULA
    `fc00::/7`. New `normalizeHostForSSRF(host)` strips `[ ]` from IPv6
    hostnames AND decodes IPv4-mapped IPv6 (`::ffff:7f00:1` → `127.0.0.1`)
    so existing IPv4 regexes still fire — Node's WHATWG URL parser was
    silently defeating both forms. **MED-4 toast leak** —
    `mapWebImportError` fallthrough no longer echoes raw upstream `msg`
    into the toast (`return 'Import failed. Please try again.'`).
    **LOW-1 per-endpoint rate limit** — `app.use('/api/import/website',
    rateLimit({ windowMs: 60_000, max: 10 }))` caps LLM cost to ~$0.02/min
    in pathological cases (was unlimited under the global 200/min). MED-3
    (snippet → notes path is pre-existing, broader scope) deferred to P1.
    +7 SSRF regression jest + 1 redirect-pin jest in
    `tests/import-website.test.js`; updated `import-website-client.test.js`
    fallthrough test to pin the static-message behaviour. Closes the
    HIGH-SEC SSRF row in the 2026-06-02 audit table.
  - **Session totals after cybersec fold-in: 941 jest + 8 e2e green
    (3 skip).**
  - **err.message-leak sanitisation (P0 audit ship, HIGH-SEC — closes the
    second HIGH-SEC row).** All 7 catch blocks that previously responded
    `res.status(500).json({error: err.message})` now mirror the narrate
    pattern: `log('error', '<endpoint>_failed', { userId, error: err.message })`
    server-side + `res.status(500).json({error: 'Internal error'})` to the
    client. Covers: `GET /api/my-backups`, `GET /api/my-backup`,
    `POST /api/places/search`, `POST /api/places/autocomplete`,
    `POST /api/places/sync`, `POST /api/places/bulk-sync`,
    `POST /api/places/discover`. Upstream Google API bodies (incl. key
    hints / URL fragments / quota messages) and filesystem paths
    (`ENOENT` traces, `BACKUP_DIR` absolute paths) no longer reach the
    wire. +8 jest in `tests/error-sanitization.test.js` — 1 per route
    × 7 (forced upstream throw via `jest.spyOn(global, 'fetch')` for
    Places + `jest.spyOn(fs, 'readdirSync')` for backups; asserts
    `{error: 'Internal error'}` body + secret string absent) + 1
    static pin against the file regex `res.status(500).json({error:
    err.message` so a future regression is caught at suite-time.
  - **Session totals after err.message sanitisation: 949 jest + 8 e2e
    green (3 skip).**
  - **Marker-icon in-place update (P0 HIGH-PERF — closes the marker-style
    rebuild stall).** New `updateAllMarkerIcons()` (`public/index.html`)
    iterates `_renderState.markerById` and calls
    `marker.setIcon(createMarkerIcon(loc))` in place per marker. L.marker
    instances are reused, no cluster layer add/remove churn, no
    `bindMarkerBehavior` re-attachment. 1000-marker style toggle ~300-600ms
    main-thread stall → <50ms icon-DOM swap. Both `setMarkerStyle` and
    `setMarkerSizeMode` now: cluster mode + populated registry → in-place
    path (returns true, sets `_renderState.markerStyle/Size` to current
    state); heat mode or empty registry → renderMarkers() fallback. Old
    `_renderState.markerStyle = null` cache-bust removed (the in-place
    path keeps the diff cache consistent by writing the new value
    directly). +7 jest in `tests/marker-icon-inplace.test.js` (in-place
    in cluster, heat fallback, empty-registry fallback, invalid-style
    coerce, missing-loc skip, static pins on both handler bodies
    delegating to updateAllMarkerIcons + cache-bust gone) + 4 updated
    tests in `tests/marker-style.test.js` (the original suite still pins
    state mutation, ls persistence, invalid-style coercion, and
    description-element text; the "busts cache to null" test was
    replaced by the new contract).
  - **Session totals after marker in-place ship: 956 jest + 8 e2e green
    (3 skip).**
  - **Mobile-UX batch (last P0 — closes both HIGH-LIVE rows from the
    2026-06-02 audit).** Two independent fixes that ship together because
    they're both first-time-on-mobile dead-ends.
    - **Save-modal lat/lng unhide + Photon auto-geocode.** The lat/lng
      `form-row` has been `display:none` since the 2026-05-31 declutter
      but `saveLocation` still rejects empty coords with a toast — leaving
      a stuck user with no path forward. Two-pronged fix: (a)
      `quickAddPlace` now fires `_autoGeocodeAddModalIfNeeded()`
      fire-and-forget after setting the name → Photon forward-geocode →
      fills lat/lng (and address, if absent) in place. Guards skip the
      call when editing, when coords already set, or when name empty;
      values the user typed during the in-flight fetch are never
      clobbered. (b) `saveLocation` now calls `_unhideLocCoordsRow()` on
      the coords-missing path → flips `#loc-coords-row` to visible +
      `scrollIntoView({behavior:'smooth', block:'center'})` + `.focus()`
      on the lat input. Toast copy split: name-missing vs
      coords-missing. The lat/lng `<div>` got `id="loc-coords-row"` for
      the unhide target.
    - **Mobile sidebar auto-collapse on ≤480px first load.** Existing
      `@media (max-width:480px)` rules already make the sidebar
      `width: 100vw` and slide the toggle to `calc(100vw - 44px)` when
      open — what was missing was the **default collapsed state** so
      the map is visible on first load. `init()` now reads
      `matchMedia('(max-width:480px)').matches` and collapses when the
      user has no saved `hm_sidebar` preference; explicit user toggle
      (`hm_sidebar='0'|'1'`) still wins thereafter, so once a mobile
      user opens the sidebar manually it stays open across reloads.
      Desktop default stays "open".
    - **+14 jest in `tests/mobile-ux-batch.test.js`** (8 autoGeocode
      behavioural — happy / skip-when-editing / skip-when-coords-set /
      skip-when-name-empty / network-fail / no-features / no-address-
      clobber + unhide flips display & focuses + 3 static pins for the
      save-modal half; 3 static pins for the mobile-sidebar half — CSS
      rule preserved, init reads matchMedia, explicit-pref precedence).
      **+1 updated** `tests/import.test.js` pin for the new
      `id="loc-coords-row"` markup.
  - **Session totals after mobile-UX batch: 970 jest + 8 e2e green
    (3 skip).**
  - **🏁 Audit P0 close-out complete — 10 of 10 shipped 2026-06-03.**
    Next session: drain P1 (narrate+discover per-endpoint rate limits,
    DNS-rebinding SSRF defence, CSP photon.komoot.io, ETag on
    /api/locations, render-blocking CDN defers, surgical
    rebuildIndexes, marker-hash field-by-field compare).
