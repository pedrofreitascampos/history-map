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
