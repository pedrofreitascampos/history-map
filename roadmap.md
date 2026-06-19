# Oikumene Roadmap

Per-batch session log + full commit detail → `~/.claude/projects/C--Users-pedro-projects-software-history-map/memory/project_roadmap.md`.

## Status

**2026-06-17:** 1683 jest (3 skip) · Audit batches · async-route safety · `onclick=` eliminated · `sanitizeNotes` · ARIA tabs + dialogs · Touch targets 44px · Offsite S3/R2 backup · Nominatim proxy + throttle · Per-theme category colors · API key encryption.

## 🔍 Audit 2026-06-16 (security · code · system · UI/UX · perf)

Five parallel auditors; findings validated against source. Sequencing:

### This week (security + durability) — ✅ DONE 2026-06-16 (commit b380182)
- [x] **Data durability confirmed safe** — user confirmed a persistent disk IS mounted at `/data`; data survives deploys/restarts. The "existential data loss" framing was a wrong inference from a stale `render.yaml`. render.yaml synced (plan→starter, disk block added, dashboard noted as source of truth).
- [x] **Durable JWT revocation** — `revokedJtis` now NeDB-backed (`db.revokedTokens`), loaded on startup, persisted on logout, pruned.
- [x] **`/api/places/bulk-sync` cost cap** — dedicated `rateLimit({max:5/min})` added.
- [x] **Username case-bypass** — lowercase normalization at register/login/SSO/admin-reset.
- [x] **`share.html` Leaflet SRI** — integrity hash added.

### Quick wins (perf + hygiene) — ✅ MOSTLY DONE 2026-06-16 (commit 691e7ed)
- [x] `<link rel=preconnect>` for unpkg/jsdelivr/fonts. *(fonts already had display=swap; Chart/JSZip/exifr already deferred — auditor over-reported.)*
- [x] `Cache-Control: max-age=7d` for `admin1.json` (3.4 MB) + `cities.json` (4.4 MB).
- [x] `runBackup` `fs.writeFileSync` → `await fs.promises.writeFile`.
- [x] `/healthz` route added.
- [x] `defer` Leaflet trio — verified safe (`L` only touched at runtime; initMap runs on DOMContentLoaded). Inverted the stale "stays blocking" guard.
- [x] Drop SW `/api/*` caching (cross-user leak); bumped CACHE_VER v1→v2.
- [x] Delete dead `scripts/convert-inline-handlers.js`.
- [x] **Memoize `computeStats()`** — `_statsCache`/`_statsCacheGen` guard; O(1) on repeat Stats tab switches (same pattern as `getFilteredLocations`).

### Next sprint (system + a11y + code)
- [x] **Offsite backups** — `_uploadBackupToS3` fires after every local write; env-gated (`BACKUP_S3_BUCKET/ACCESS_KEY/SECRET_KEY`); soft-failure (`.catch` → log, never blocks); R2-compatible (`forcePathStyle`, `region=auto`); `.env.example` updated.
- [x] **Proxy + throttle geocoding** — `GET /api/geocode` + `/api/geocode/reverse` server proxy; serial chain with 1050 ms floor; 24 h cache (1000-entry LRU); proper `User-Agent`; all 11 frontend direct-Nominatim calls replaced.
- [x] **async-route wrapper** — one-time method patch before first route; all 28 previously-unprotected handlers now call `next(err)` on rejection.
- [x] **ARIA tabs + dialogs** — `role="tablist"/"tab"` + `aria-selected` on nav + stats tabs; `switchView`/`switchStatsTab` keep them in sync; `_trapFocus` helper + `role="dialog"` + `aria-modal` + focus restore + Escape on all 3 overlays.
- [x] **Per-theme category colors** — Parchment gets 14 WCAG AA–compliant dark `--cat-*` overrides; Volcano gets `--cat-restaurant:#f97316` (orange) to avoid accent `#f87171` collision; `applyTheme` resets all `--cat-*` on switch and syncs `COLOR_HEX` for Leaflet markers.
- [x] **Touch targets** — leaflet zoom + map-tools 36→44px; `.people-tag .remove-tag` 24→44px; `.marker-rating` 9→12px (meets 12px a11y floor).
- [x] **Encrypt per-user API keys at rest** — AES-256-GCM (`enc:iv:enc:tag` format); wrapping key derived via SHA-256 from `JWT_SECRET`; lazy plaintext migration (legacy values pass through until next save); shared env key restricted to admin in multi-user mode, open in single-user mode (`!ADMIN_EMAIL`).
- [x] **`onclick=` → `data-click`** — all 5 removed (clearRegionFilter chip, 3× Leaflet popups, share-link-url); `ACTIONS.selectInput` added.
- [x] **`sanitizeNotes` extraction** — shared helper; `sanitizeTripUpdate` and `sanitizeTransitUpdate` now strip `<script>`/`javascript:` from notes (was location-only).
- [x] `_idxAddLoc`/`_idxRemoveLoc` — already in sync with `rebuildIndexes`; roadmap item was stale.

### Design discussion (don't ship unilaterally)
- Nav 10→~6 tabs + overflow (NOTE: prior nav-collapse was user-rejected 2026-06-12).
- Merge Regions into Map as a choropleth layer; rename "Plan" (its HTML comment still says WISHLIST VIEW); Map=Plan=🗺️ collision.
- More emoji/color collisions: festival≡event color, museum(🏺)≡show(🎭) color.

### Cool ideas (delight ÷ effort)
- "On This Day" → one-tap Replay · Year-in-Review shareable card (reuse WebM export path) · ~~collection completion rings~~ ✅ · isochrone wishlist scoring (Valhalla already in CSP) · ~~`?` keyboard-shortcut overlay + ⌘K quick-add~~ ✅ · ~~LLM trip-journal from visits~~ ✅ · per-category marker style.

| Batch | Date | Jest | Highlights |
|---|---|---|---|
| **LLM trip-journal** | **2026-06-19** | **+30 (1777)** | **POST /api/trips/:id/journal · Haiku prose from stop list (name/category/visitDate/rating/notes) · 10 req/min rate limit · ✍️ button in trip detail · generateTripJournal (loading state) · #journal-modal + 📋 copy · openJournalModal/closeJournalModal · Escape integration** |
| **Collection completion rings** | **2026-06-19** | **+22 (1747)** | **SVG donut ring wrapping collection emoji · CIRC=113.1 · dashOffset=(CIRC×(1-pct/100)) · green at 100% (--success) · accent in-progress · transparent at 0% · aria-label with count · bar removed · Stats-tab cards unaffected (.coll-ring-wrap scoped)** |
| **⌘K quick-add** | **2026-06-19** | **+24 (1725)** | **`openQuickAddModal` · `#quick-add-modal` with debounced geocode search (400ms, /api/geocode) · `quickAddSearch` → `_quickAddHits[]` → `quickAddPick` → `openAddModal(lat,lng)` pre-fills name+address · Ctrl+K/⌘K global key handler · `.quick-add-result` CSS · shortcuts overlay updated** |
| **Keyboard shortcut overlay** | **2026-06-19** | **+18 (1701)** | **⌨️ topbar button · `?` key opens overlay · `/` key focuses map search · `<kbd>` CSS · closeShortcutsModal + Escape integration · 7-row shortcut table (general + rating)** |
| **Google Maps share-target** | **2026-06-16** | **+25 (1573)** | **manifest share_target (GET /share-target) · sw.js offline fallback · _parseGoogleMapsCoords · _handleGoogleMapsShare + geocode fallback · _initGoogleMapsShareTarget (URLSearchParams) · _setBookmarkletHref · import guide: Android PWA + drag-to-bookmark link** |
| **Regions filter** | **2026-06-16** | **+24 (1548)** | **🗺️ View on Atlas button in all 3 region popups · sidebar filter chip (📍 label + × dismiss) · filterAtlasByLocs / clearRegionFilter · drill-down fitBounds zoom on region/country click · state.filters.regionLocs fast-exit** |
| **P2 polish batch** | **2026-06-15** | **+27 (1524)** | **Stale search fix · npm audit fix (0 vulns) · .env.example · prefers-color-scheme auto-detect · Stats KPI ribbon + 4 tabs (Overview/Countries/Categories/Timing) · switchStatsTab + Chart.js resize** |
| **Dynamic overlays Tier 2+** | **2026-06-15** | **+19 (1497)** | **🌍 USGS earthquakes M2.5+ (circles by magnitude) · 🛸 ISS live position (10s auto-update) · 2 new toolbar buttons · CSP whitelisted** |
| **Replay export** | **2026-06-15** | **+22 (1478)** | **🎥 Export clip button · canvas captureStream + MediaRecorder → .webm · dark lat/lng grid visualization · no external libs** |
| **Graph view** | **2026-06-15** | **+28 (1456)** | **🕸️ Graph toggle · dark basemap switch · _buildGraphSequence · SVG marker-end arrowheads · node dedup · toggleGraphMode/drawGraph/clearGraph** |
| **Currency overlay** | **2026-06-15** | **+27 (1428)** | **💱 Rates toggle · COUNTRY_CURRENCY table (~100 countries) · _getFxRates (1hr cache) · _renderCountryFlags extracted · open.er-api.com CSP whitelisted** |
| **People lens** | **2026-06-15** | **+18 (1401)** | **👥 People toggle · colored left-lane per person · legend chips · #chrono-person filter · _buildPeopleColorMap · 8-color palette** |
| **Import diff preview** | **2026-06-15** | **+17 (1383)** | **_classifyImportItems: adds/updates/skips · diff view with collapsible sections · per-section checkboxes · pre-classified confirmImport path** |
| **Isochrones** | **2026-06-15** | **+18 (1366)** | **Travel-time rings · Valhalla API · toggleIsoPanel · drawIsochrones · clearIsochrones · Walk/Bike/Drive · 15/30/45 min chips** |
| **Trip cost + Plan view** | **2026-06-14** | **+24 (1348)** | **Cost fields on stops + transits · per-trip cost tile · Plan tab replacing Wishlist · _greedyRoute · 3 itinerary proposals** |
| **Context-aware Discover** | **2026-06-14** | **+16 (1342)** | **Trip centroid seeding · auto-radius · missing-category chips · _tripCentroid + setDiscoverCategory** |
| **Already-been detection** | **2026-06-14** | **+3 (1326)** | **Per-item dedup choices: Skip/Add visit date/Import as new · visit PATCH on existing · #dedup-apply-btn** |
| **Visit timing charts** | **2026-06-13** | **+20 (1323)** | **Day-of-week (Mon-first, weekend orange) + month-of-year bars · category filter · renderTimingCharts** |
| **Google Saved Places import** | **2026-06-13** | **+23 (1303)** | **Takeout JSON parser (old+new format) · Geo Coordinates strings · Want-to-go→bucket · import guide UI** |
| **Smart import dedup** | **2026-06-13** | **+31 (1280)** | **Levenshtein sim + 500 m gate · confirmImport hook · saveLocation toast · #dedup-modal review UI** |
| **PWA / Offline** | **2026-06-13** | **+19 (1249)** | **sw.js tile cache (200 cap) · cache-first CDN · network-first API · manifest.json · no-store SW route** |
| **Share Trip** | **2026-06-12** | **+15 (1230)** | **POST/DELETE /trips/:id/share · GET /api/share/:token (public) · /s/:token page · CSP-nonce** |
| **Plan-a-Day** | **2026-06-12** | **+53 (1215)** | **wishlist select toggles · OSRM nearest-neighbour · plan-day-modal · trip creation + nav** |
| **S3 + S4 start** | **2026-06-12** | **+21 (1162)** | **Sidebar FAB · Stadia tiles · jargon cleanup · On This Day · Year in Review · Neighborhoods · Photo Timeline** |
| **S2.5 hardening** | **2026-06-11/12** | **+192 (1141)** | **a11y · security · perf · audit-fix · live-fixes** |
| **S2 perf + replay** | **2026-06-04** | **+26 (949)** | **cluster zoom · transits · fullscreen · cold-load perf** |
| **S1 P0 close-out** | **2026-06-03** | **+210 (923)** | **10/10 audit items** |

## 🟠 Open — pick from here

### Power features (ranked by impact-vs-effort)

~~7. **💰 Trip cost tracker** — cost field per stop/transit → per-trip + per-year roll-up.~~ ✅
~~8. **🎯 Isochrones / travel-time rings** — X min by car/walk/transit from a pinned location.~~ ✅
~~9. **🔀 Conflict-free import preview diff** — adds/updates/dupes as reviewable list before committing.~~ ✅
~~10. **👥 People lens in Chronology** — toggle showing each person as a colored lane.~~ ✅
~~11. **💱 Currency overlay for Regions** — local symbol + FX rate per country.~~ ✅
~~12. **🕸️ Graph view on Atlas** — node-link over dark basemap, directed edges between consecutive visits.~~ ✅
~~13. **🎥 Replay export to GIF/MP4** — "Record" button → shareable clip.~~ ✅
~~14. **🌉 Bifrost ↔ Oikumene bridge** — superseded by built-in Plan view.~~ ⛔ dropped
~~15. **🌐 Dynamic overlays Tier 2+** — USGS earthquakes, FlightRadar live, ISS, wind/jet-stream, marine AIS.~~ ✅

### Longer-term / blocked

- ~~**Direct share-from-Google-Maps** — Mobile PWA share-target + Desktop bookmarklet.~~ ✅
- **Bootstrap preset collections** — UNESCO (~1200), National Parks, Airports, Stadiums, Wonders. Open design Q: in `state.locations` vs overlay layer.
- **Google Data Portability API OAuth** — blocked on Google restricted-scope verification.
- **Strict `style-src` CSP** — Leaflet injects nonceless inline styles; gap accepted until replacement.

## 🟡 P2 — Polish backlog

**Security** — ~~`npm update express` (path-to-regexp HIGH + qs MODERATE); missing `.env.example`.~~ ✅ | `revokedJtis` in-memory only; dev JWT secret hardcoded.

**Infra** — `render.yaml` free tier wipes data on deploy (upgrade Starter + persistent disk).

**UX**
- ~~Theme switch cycles blind — no preview, no `prefers-color-scheme`.~~ ✅
- Category colors not part of theme swap (Volcano: red accent + red marker collide).
- ~~Stats view = 800 px scroll dump — needs KPI ribbon + tab-within-stats.~~ ✅
- Trips view: 50/50 split hardcoded; no drag-to-reorder stops; no full-screen planning map.
- ~~Regions view: filter map by region click + drill-down zoom (popups ✅, filtering ✗).~~ ✅
- ~~`#map-search-results` persists stale text after sidebar blur.~~ ✅
- ~~Wishlist: actions row always visible (hover/focus only); no `+ Add` in header when list has items.~~ ⛔ stale — Wishlist tab removed (Plan view replaced it 2026-06-14)
- ~~Two 🏛️ categories (Monument + Museum) — emoji collision.~~ ✅ Museum → 🏺

## ⛔ Blocked / Dropped

- **beliapp.co import** — install-marketing only, no data endpoint. Skipped 2026-05-31.
- **Sync to Google Maps Saved Lists** — no public write API.
- **Google Photos Library API Path 1** — dead since 2025-03-31.
- **Nav collapse to 5+overflow** — user rejected 2026-06-12.
