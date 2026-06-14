# Oikumene Roadmap

Per-batch session log + full commit detail → `~/.claude/projects/C--Users-pedro-projects-software-history-map/memory/project_roadmap.md`.

## Status

**2026-06-15:** 1383 jest (3 skip) · Import diff preview shipped.

| Batch | Date | Jest | Highlights |
|---|---|---|---|
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
10. **👥 People lens in Chronology** — toggle showing each person as a colored lane.
11. **💱 Currency overlay for Regions** — local symbol + FX rate per country.
12. **🕸️ Graph view on Atlas** — node-link over dark basemap, directed edges between consecutive visits.
13. **🎥 Replay export to GIF/MP4** — "Record" button → shareable clip.
14. **🌉 Bifrost ↔ Oikumene bridge** — bidirectional location/trip exchange with the Bifrost planner.
15. **🌐 Dynamic overlays Tier 2+** — USGS earthquakes, FlightRadar live, ISS, wind/jet-stream, marine AIS.

### Longer-term / blocked

- **Direct share-from-Google-Maps** — Mobile PWA share-target (SW ✅ now unblocked — add `share_target` to manifest + `POST /api/import/google-maps-link`) + Desktop bookmarklet (`javascript:` on `google.com/maps/...` → `#add?url=<encoded>`).
- **Bootstrap preset collections** — UNESCO (~1200), National Parks, Airports, Stadiums, Wonders. Open design Q: in `state.locations` vs overlay layer.
- **Google Data Portability API OAuth** — blocked on Google restricted-scope verification.
- **Strict `style-src` CSP** — Leaflet injects nonceless inline styles; gap accepted until replacement.

## 🟡 P2 — Polish backlog

**Security** — `revokedJtis` in-memory only; dev JWT secret hardcoded; `npm update express` (path-to-regexp HIGH + qs MODERATE); missing `.env.example`.

**Infra** — `render.yaml` free tier wipes data on deploy (upgrade Starter + persistent disk).

**UX**
- Theme switch cycles blind — no preview, no `prefers-color-scheme`.
- Category colors not part of theme swap (Volcano: red accent + red marker collide).
- Stats view = 800 px scroll dump — needs KPI ribbon + tab-within-stats.
- Trips view: 50/50 split hardcoded; no drag-to-reorder stops; no full-screen planning map.
- Regions view: filter map by region click + drill-down zoom (popups ✅, filtering ✗).
- `#map-search-results` persists stale text after sidebar blur.
- Wishlist: actions row always visible (hover/focus only); no `+ Add` in header when list has items.
- Two 🏛️ categories (Monument + Museum) — emoji collision.

## ⛔ Blocked / Dropped

- **beliapp.co import** — install-marketing only, no data endpoint. Skipped 2026-05-31.
- **Sync to Google Maps Saved Lists** — no public write API.
- **Google Photos Library API Path 1** — dead since 2025-03-31.
- **Nav collapse to 5+overflow** — user rejected 2026-06-12.
