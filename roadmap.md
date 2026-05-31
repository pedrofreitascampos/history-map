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
  - **beliapp.co import** — Beli is an app for restaurant/bar lists. The
    user's profile is at <https://beliapp.co/app/guavajellyreturns> with
    visited places + a linked wishlist. Need to (a) check whether Beli has
    a JSON export (profile API / settings → export), (b) if not, scrape
    via Playwright (the page is SPA-rendered). Restaurants + bars import
    into the locations DB with category set; the wishlist becomes
    `status: 'bucket'`. Also pull through ratings if present.

### Wishlist (P1+)

- **Google data — easier ingestion path.** Research spike completed 2026-05-30
  (`a537b43` — see `docs/research/google-data-ingestion.md`). **Two follow-ups
  shipped:** `99d0ea2` patched the phone-export parsers
  (`parseGoogleTimelineSegments` + `parseGoogleTimelineNew`) to read real place
  names, capture `placeId` + `address`, and stop mangling diacritic casing;
  `ac88ce0` updated the Google Data Guide with the 2024+ on-device export path
  and the Takeout `Saved/` CSV-list path. **Still open:** KML/KMZ import for
  My Maps (~1 day, `togeojson`), legacy Places API → Places API (New)
  migration (not urgent), Data Portability API OAuth flow (blocked on Google's
  Restricted-scope verification for personal apps — monitor for relaxation).
  Do not build the sharable-list scraper (ToS risk + low value).
- **Top-rated Google Places by category** — discovery: places near a region
  with >1000 ratings, filtered by category, one-click bucket-list add.
- **Time Out / website import** — generic web-scrape importer with per-site
  adapters; Time Out as first adapter.
- **Trips — natural-language entry** — "Narrate a trip" mode parsing "Aug 3–10
  in Lisbon, then 4 nights Porto" into date range + stops + linked transits.
  Recommended v1: Haiku API (~$0.001/parse). Browser-side WebLLM is the truly-
  offline future option.
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
  - **Session totals: 570 jest + 8 e2e green.**
