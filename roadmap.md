# Oikumene Roadmap

Project-specific backlog for the Oikumene history map app.

Convention (defined in `~/projects/ai/companion/docs/architecture.md`):
- **Top-level** (this file) — Oikumene-specific concerns
- **Personal life** — `~/.claude/personal/roadmap.md` (gitignored, never in repo)

Session-log detail (commit chronology, test counts) lives in the memory roadmap
at `~/.claude/projects/C--Users-pedro-projects-software-history-map/memory/project_roadmap.md`.

## Open

### Security (audit 2026-05-30, reconciled against shipped work)

The 2026-05-30 audit produced 12 findings. **All 12 are now resolved**
(H-2 cookie migration shipped 2026-05-30 in `ade84d8`). See Resolved
table below for the per-finding reconciliation.

### Other open items

- **Import Pedro's `#bucketlist` Google Tasks list (49 items) → Oikumene bucket locations.** Source: Google Tasks list id `VzM0QTAyMnpIbVcySG5kYQ`, dumped to backup `~/.claude/backups/google-tasks/2026-06-01-010047-archive-2023.json` is for #archive-2023; re-pull #bucketlist when picked up. Split needed: ~14 items are geographic (Bombonera, North Korea, Bora Bora, Trans-siberian, 1yr around the world, Australia, Walk Berlin→Lisbon, Antarctica, Wimbledon, Cross Africa, Mecca, Bike Berlin→Athens, Carnaval Brasil event, GP F1 Monaco) → import as `status: bucket` locations via `POST /api/locations` using the same geocode-or-placeholder pattern as Trips v2 (Photon → Nominatim → placeholder). Non-geographic items (Yoga, Skydive, Learn to meditate, Build PC, Cricket, etc.) — leave in source list for separate disposition (probably into Google Tasks `#sprint` → 🤖 Hobbies / wants or 🎓 Personal development). Added 2026-06-01 per Pedro: "#bucketlist should likely go into oikumene bucket list - it's just another data source among a myriad others".

- **Marker layer-diff** — ✅ shipped 2026-05-30 (commit `d1b37ba`).
- **FR24 "not an export" guard** — ✅ shipped 2026-05-30 (commit `9f34cd4`).
- **LOW polish bundle** — ✅ shipped 2026-05-30 (commit `9f34cd4`).
- **CSP nonce on `script-src`** — ✅ shipped 2026-05-30 (commit `aa479d5`).
  Per-request nonce on every inline `<script>` block.
- **H-2: HttpOnly cookie for bearer** — ✅ shipped 2026-05-30 (commit `ade84d8`).
  Cookie is `HttpOnly` + `SameSite=Strict` + `Secure` in prod, 30d TTL. JS
  can no longer read the bearer (closes the XSS-exfiltration window).
  `auth()` reads cookie first, Authorization header as back-compat fallback.
- **CSP `script-src-attr 'none'`** — ✅ shipped 2026-05-30 (commit `c9f7ec9`).
  All 217 inline event handlers (`onclick=` / `onchange=` / `onmouseover=` /
  `oninput=` / `onkeydown=` / `onfocus=`) migrated to a document-level
  capture-phase dispatcher reading `data-<event>=` + `data-argN=` attributes.
  No `'unsafe-inline'` remains on any JS-execution directive. A stored XSS
  that lands `<button onclick="alert(1)">` is silently ignored.
- **`style-src` stays permissive** (deferred). Leaflet injects nonceless
  inline styles at runtime for cursors/panes/tiles; per CSP-3, mixing
  `'unsafe-inline'` with a nonce in `style-src` causes browsers to ignore
  `'unsafe-inline'` and enforce nonces strictly. Until we have a strict-
  dynamic-for-CSS story (or migrate off Leaflet inline styles), this
  residual remains as accepted defense-in-depth gap. Lower severity than
  script injection — style injection cannot execute code.
- **CSS-ify legacy hover-bg ACTIONS** — ✅ shipped 2026-05-30 (commit `342cf0d`).
  Single `.hover-bg-tertiary:hover` rule replaces the 4 bridged sites; `hoverIn`
  / `hoverOut` removed from the dispatcher. Pure presentational refactor.
- **Bootstrap map/collections/trips DBs** — waiting on user inputs. Existing
  bootstrap surfaces: bulk JSON/CSV/KML, Google Timeline, OSM enrich, Google
  Places sync, FR24 (transits + auto-airport stops). Additional candidate
  paths queued for the bootstrapping push:
  - **Playwright/headless-browser scraper** for sources without an export
    API. Spin up Chromium server-side, log in as the user (cookies
    forwarded), scrape the place list + metadata, normalize into the
    location-import shape. Targets: anywhere the user has a curated list
    that won't export cleanly. ToS-grey per source; gate per-target.
  - **beliapp.co import** — ⛔ **architecturally blocked (investigated 2026-05-31).**
    `https://beliapp.co/app/<username>` does NOT host a web profile. With
    any UA it redirects: WebFetch (default UA) → Branch.io `app.link` deep-link
    page ("install mobile app"); desktop Chrome UA via curl → 200 ending at
    `apps.apple.com/us/app/beli/id1478375386` (App Store). The public URL is
    pure install-marketing — zero list data, zero JSON, no SPA bootstrap to
    parse. The browser web app exists but is auth-gated; the user reported
    "I have the export on Gmail" but Gmail search across 9 angles (sender,
    subject, attachments, snoozed, `in:anywhere beli`, self-sent, etc.)
    found nothing — Beli does not appear to email exports. Practical paths
    if revisited: (1) export feature in the Beli mobile app that produces a
    CSV/JSON file (status unknown — needs in-app check); (2) ~2-3 day
    Playwright + stored-credentials scraper (ToS-grey, brittle, adds
    Chromium dependency); (3) skip Beli. **Current verdict: skipped per
    user 2026-05-31.** Pattern still useful for other apps with similar
    architecture — adapter slot in `WEBSITE_IMPORT_ADAPTERS` is open.

### Wishlist (P1+)

- **Dynamic map overlays — fun, live data layers.** Toggleable overlays on the main map for things that move/change in real time. Targets:
  - **FlightRadar live overlay** — `/api/flightradar/live` proxy to FR24 (or ADS-B Exchange as a free alt) bounded by current map viewport; render small ✈ markers with heading rotation + on-click panel showing flight number/route/altitude/speed; auto-refresh every 15-30s; rate-limit guard. Plays nicely with existing FR24 *import* (transits), but this one is "see what's flying NOW" not "import where I've been".
  - **Weather overlay** — clouds / precip / temperature tiles via OpenWeatherMap or RainViewer (RainViewer is free, no key). Tile layer slot in `mapStyle` toggle next to cluster/heat.
  - **Wind / jet-stream layer** — windy.com tile feed (paid) or Earth Nullschool style WebGL render (free, BYO). Lower priority — niche.
  - **Marine traffic (AIS)** — AISHub or MarineTraffic free tier for vessels in viewport. Niche but cool for coastal locations.
  - **ISS / satellite ground tracks** — pull from N2YO API or open-notify; tiny 🛰 dot moving across the map.
  - **Earthquake / volcano feed** — USGS GeoJSON (free, no key); circle-radius by magnitude. Educational, low-cost ship.
  - **Cruise ships / aircraft carriers** — for travel-curious users; spotter community data sources exist but ToS-grey.

  Architecture: each overlay = a registered entry in `DYNAMIC_OVERLAYS` map → `{label, icon, fetch(bounds), render(layer, data), refreshIntervalSec, attribution}`. Single overlay-control UI in the map (similar to `.map-tools-control`) opens a panel with toggle switches per source. Server side: thin proxies in `server/overlays/` (rate-limit + key shielding + caching). Per-overlay logging + provider-key gating like the Places provider pattern. **Ship order: RainViewer (free, no key, instant win) → FlightRadar (requires key or ADS-B Exchange free) → USGS quakes (free) → others.**

- **Google data — easier ingestion path.** Research spike completed 2026-05-30
  (`a537b43` — see `docs/research/google-data-ingestion.md`). **Three follow-ups
  shipped:** `99d0ea2` patched the phone-export parsers
  (`parseGoogleTimelineSegments` + `parseGoogleTimelineNew`) to read real place
  names, capture `placeId` + `address`, and stop mangling diacritic casing;
  `ac88ce0` updated the Google Data Guide with the 2024+ on-device export path
  and the Takeout `Saved/` CSV-list path; `5d93e62` migrated the server proxy
  off the legacy Places API onto Places API (New) — `X-Goog-Api-Key` header
  (key no longer in URL query string), `X-Goog-FieldMask` cost control,
  `priceLevel` enum→0-4 mapping at the helper boundary so downstream consumers
  stay unchanged. **KML/KMZ already shipped** (`parseKML` + JSZip unzip — the
  research brief's "~1 day, `togeojson`" note was stale). **Still open:** Data
  Portability API OAuth flow (blocked on Google's Restricted-scope verification
  for personal apps — monitor for relaxation). Do not build the sharable-list
  scraper (ToS risk + low value).
- **Time Out / website import** — ✅ shipped 2026-05-31 (commits `febb14d` +
  `8134bdb`). `POST /api/import/website` with extensible adapter registry
  (`WEBSITE_IMPORT_ADAPTERS` in server/index.js); Time Out is the first
  registered adapter (`server/import-adapters/timeout.js`). HTTPS-only +
  SSRF guard (rejects localhost, RFC1918, IPv6 loopback). 10s timeout, 5MB
  cap. Adapter uses JSON-LD ItemList as primary signal, falls back to
  numbered h2/h3 headings + nearby `<address>` blocks. Client UI lives in
  the Import view ("🌐 Web Import") + review modal with editable
  name/address per row and Select-all toggle; on confirm, each selected
  venue is geocoded via `geocodeNarratedStop` (shipped in Trips v2) and
  POSTed as a bucket-status location with `tags: ['timeout']` + notes that
  carry the article title and snippet. 53 new jest tests (31 server,
  22 client). Next adapter slot ready for Beli, Bon Appétit, Eater, etc.
- **Trips — natural-language entry v2** — ✅ shipped 2026-05-31. Each parsed stop
  is now geocoded via Photon (fallback Nominatim) and POSTed as a bucket-status
  location linked to the trip via `tripId` + `tripOrder`. Unmatched stops still
  create placeholder bucket locations (no lat/lng) so nothing is lost. Helper
  `geocodeNarratedStop(name)` factored out for testability; 15 new jest tests in
  `tests/trips-v2.test.js`.
- **Google Photos integration** — per-location photo fetch via GPS+date.
- **Sync to Google Maps saved lists** — **blocker**: no public write API;
  research spike needed.
- **Bifrost ↔ Oikumene bridge** — bidirectional location/trip exchange.

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

## Audit 2026-06-02 (full multi-domain)

Pedrow-commissioned full audit mirroring the Fortuna run. 4 parallel specialist agents (cybersec / code+perf / UX/UI / live functionality). All 4 returned full reports. **Headline:** security baseline holds (zero CRITICAL — the 12-finding May 30 fix bundle kept its value) but the live agent surfaced a CRITICAL the static audits missed, and the UX agent found a real keyboard-accessibility bug.

### 🔴 P0 — Ship this week (1-2 days)

| Sev | Finding | File:Line | Fix |
|---|---|---|---|
| CRIT-LIVE | **3 select dropdowns silently broken** via `data-arg0="this.value"` — passes literal string instead of `el.value`. **Marker Style / Marker Size Mode / Trip Selector visually change but have ZERO effect.** Trip detail panel is unreachable via UI; can only be opened via `selectTrip(id)` console call. | `public/index.html` — 3 selects | Either extend `_readPositionalArgs` to resolve `"this.value"` → `el.value` (also `"this.checked"`, `"this.dataset.X"` etc.), OR migrate the 3 selects to `data-change="setMarkerStyle"` reading `el.value` inside the handler. Pin in `tests/marker-style.test.js` + `tests/trips-v2.test.js`. |
| CRIT-UX-BUG | **Hearts not keyboard-settable** — `data-click="handleHeartKey"` duplicate attribute on each heart span silently overrides `setBucketStrength` (HTML spec: last attribute wins). Bucket strength can only be set via mouse click. | `public/index.html:2174-2178` | Rename one attribute (`data-keydown="handleHeartKey"`) so they don't collide. |
| HIGH-SEC | **SSRF blocklist missing link-local + IPv6 private ranges** in `POST /api/import/website`. `169.254.169.254` (GCP/Render metadata), `fd00::/8` IPv6 ULA, `::ffff:127.0.0.1` IPv4-mapped loopback all pass the current regex. Authenticated user → server-side fetch to cloud metadata endpoint. | `server/index.js:719-727` | Add: `/^169\.254\./`, `/^fd[0-9a-f]{2}:/i`, `/^::ffff:(127\.|10\.|172\.(1[6-9]\|2\d\|3[01])\.|192\.168\.)/i`. Also: `dns.lookup(host)` then re-apply IP blocklist (defends DNS-rebinding / CNAME chains). |
| HIGH-SEC | **`err.message` leaked to clients on 500** in 7 catch blocks across Places (`/api/places/discover` etc), backup, narrate. Exposes Google API error bodies (incl. key hints / URLs / quota info) and filesystem paths. | `server/index.js:719/727 → 1057, 1071, 1252, 1312, 1342, 1394, 1471` | Replace with `res.status(500).json({ error: 'Internal error' })`; log detail via `log('error', …)`. Narrate endpoint already does this at line 705-710 — apply that pattern everywhere. |
| CRIT-PERF | **No HTTP compression middleware.** `index.html` ships at 576 KB raw. `compression` not in `package.json`/`server/index.js`. Render doesn't auto-gzip Node responses. Gzip → ~140 KB (4× cheaper) for free. | `server/index.js` (absent), `package.json` | `npm install compression`; `app.use(require('compression')())` before static middleware. |
| HIGH-PERF | **Marker-style toggle does full rebuild** instead of `marker.setIcon()` in place. 1000 markers = 300-600ms main-thread stall. | `public/index.html:4107-4115` (`setMarkerStyle` cache bust) + `_renderState` | Add `updateMarkerIcon(marker, loc)` that calls `marker.setIcon(createMarkerIcon(loc))` per entry in `_renderState.markerById`. |
| HIGH-LIVE | **Save modal silently fails when lat/lng empty + fields are hidden** — toast "Please fill in lat and lng" appears but fields are hidden by default. User has no path forward. | `public/index.html` add-modal lat/lng row | Auto-run Photon geocode on modal open when name filled + coords empty; if still missing on Save, unhide the lat/lng row + scroll-to + focus. |
| HIGH-LIVE | **Mobile sidebar covers entire 375px viewport** — sidebar is 375px wide identical to viewport. Map fully obscured. No auto-collapse. | sidebar CSS | Add `@media (max-width: 480px)` → sidebar `width: 100vw` collapsed by default; show toggle FAB on map. |

### 🟠 P1 — Ship this month (~1 week)

**Security finishing touches**
- **Per-endpoint rate limits** on expensive routes (narrate / discover / web-import) — 10/min/user. Today protected only by global 200/min. (`server/index.js:134`)
- **`photon.komoot.io` missing from CSP `connectSrc`** despite 4 client-side fetches to it (`server/index.js:95-104` ← add host; verify against full client `fetch` site list).
- **`ANTHROPIC_API_KEY` missing from `render.yaml`** — add `- key: ANTHROPIC_API_KEY\n  sync: false`.
- **`@anthropic-ai/sdk: ^0.30.1`** caret on a 0.x → pin exact `0.30.1` + `npm ci`.
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
- **Regions view zero interaction** beyond color scheme; clicking a country does nothing.
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

### Sequenced ship plan

| Sprint | Theme | Items | ~Effort |
|---|---|---|---|
| **S1 (this week)** | Fix the 2 silent breakages + 2 HIGHs + cache the bundle | 8 P0 items above (data-arg0 dispatcher, hearts duplicate attr, SSRF link-local, err.message leak, compression, marker-style in-place setIcon, save-modal lat/lng, mobile sidebar) | 1-2 days |
| **S2** | Hardening + perf round 2 | Per-endpoint rate limits, CSP `photon.komoot.io`, ETag on /api/locations, initMap-first, lazy non-map CDNs, surgical rebuildIndexes, RainViewer persist fix, Photon-provider error label | 3-4 days |
| **S3** | UX redesign batch | Collapse nav to 5+overflow, mono font on stats, FAB add-place, Stadia tiles + theme swap, KPI ribbon for Stats, sidebar command-panel collapse | 1 week |
| **S4+** | Power features | Pick 2-3: Year-in-Review, Neighborhoods cluster, Plan-a-Day, Stadia tiles + theme map, Share-trip link | 1-2 weeks each |

### Cross-audit notes

- **What was already in good shape** (per cybersec agent): server hygiene (Helmet CSP+nonce, HttpOnly+Strict+Secure cookies, ALLOWED_EMAILS fail-closed, ALLOWED_ORIGINS CORS, JWT revocation, rate limiting, sanitizeDoc, path-traversal guard, RainViewer URL allowlist, recent enrichment confirm + Wishlist all clean from XSS).
- **What the static audits missed but live caught:** the `data-arg0="this.value"` dispatcher gap. Recommend adding a Playwright sweep test that exercises every dropdown in the app + asserts state mutation per `change`.
- **What live missed but static caught:** the `data-click="handleHeartKey"` duplicate-attribute keyboard accessibility bug — silently broken keyboard heart-setting was not exercised in live testing because the agent used mouse clicks.

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
