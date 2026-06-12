# Oikumene Roadmap

Per-batch session log + full commit detail → `~/.claude/projects/C--Users-pedro-projects-software-history-map/memory/project_roadmap.md`.

## Status

**2026-06-12:** 1162 jest (3 skip) · **S2.5 audit batch complete** — security hardening, a11y sweep, glyph/terminology unification, bulk-edit restructure, sub-12px text floor.

| Batch | Date | Jest | Highlights |
|---|---|---|---|
| **A11y + UX polish** | **2026-06-12** | **+12 (1162)** | **keyboard coords toggle · account/filter font floor · 🔖 wishlist glyph · bulk enrich row** |
| **Security batch** | **2026-06-12** | **+9 (1150)** | **backup authz userId · DNS-rebinding dns.lookup · mono stats font · Wishlist terminology** |
| **Perf round 2 + security** | **2026-06-11** | **+29 (1112)** | topojson CDN · markerHash · getFilteredLocations memo · prefetchReplayRoutes · Cache-Control · SSRF |
| **Audit-fix (S2.5)** | **2026-06-11** | **+27 (1083)** | flex-shrink replay · data-click sweep · replay transit date · photon default · toast CSS |
| Live fixes | 2026-06-11 | +21 (1056) | Photon stale results · Narrate UX · form autofill · overlay persist |
| Replay redesign | 2026-06-04 eve | +12 | cluster zoom · transits · fullscreen |
| Perf cold-load | 2026-06-04 pm | +14 (1000) | Cache-Control · initMap defer · CDN async |
| P0 close-out | 2026-06-03 | +210 (970) | 10/10 from 2026-06-02 audit |

## 🟠 Open — pick from here

### UX P1

### Longer-term (P1+, scoped)

- **Direct share-from-Google-Maps → Oikumene** (2026-06-03 user ask). Two surfaces, shared server endpoint + URL parser:
  - **Mobile PWA share-target** — `manifest.json` `share_target` → `POST /api/import/google-maps-link`. Parses single place / saved list / `maps.app.goo.gl` short-link. Blocked on Service Worker (Power #7).
  - **Desktop bookmarklet** — one-line `javascript:` bookmarklet on `google.com/maps/...` → `#add?url=<encoded>` hash handler. No extension needed.
  - Implementation: (1) URL parser, (2) shortlink SSRF-guarded expander, (3) `#add?url=` hash handler, (4) PWA manifest + SW, (5) bookmarklet install card.
- **Bootstrap preset collections** (2026-06-03 user ask) — UNESCO World Heritage (~1200), National Parks, Airports (OurAirports CSV), Stadiums (Wikidata), Wonders, Blue Flag beaches. Sketch: `/api/collections/presets` catalog + per-preset adapter in `server/preset-collections/`. **Open design Q:** preset locations in `state.locations` (clutters views) or as overlay layer (cleaner)?
- **Bootstrap from sources without export API** — Playwright/headless scraper. Adapter slot in `WEBSITE_IMPORT_ADAPTERS`. Case-by-case targets.
- **Google Photos Path 2** — requires photo-org repair (DB columns + NAS path pivot). Queued behind photo-org.
- **Google Data Portability API OAuth** — blocked on Google Restricted-scope verification for personal apps.
- **Strict `style-src` CSP** — Leaflet injects nonceless inline styles; accepted gap until strict-dynamic-for-CSS or Leaflet replacement.

## 🟡 P2 — Polish backlog

**Security INFO/LOW** — `revokedJtis` in-memory only; dev JWT secret hardcoded; KMZ zip-slip belt-and-suspenders; `express ^4.18.2` transitive `path-to-regexp` HIGH + `qs` MODERATE (`npm update express`); missing `.env.example`.

**Code-quality** — `render.yaml` free tier wipes data on deploy (upgrade Starter + persistent disk); no ESLint with `no-undef`; `logout` swallows errors silently.

**UX MEDIUM/LOW**
- Theme switch needs preview — single 🌙 cycles blind; no `prefers-color-scheme` integration.
- Category colors not part of theme swap — `--cat-restaurant: #ff6b6b` constant; in Volcano theme red accent + red marker collide.
- Playfair at 13px uppercase in `.filter-section h4` — switch UI chrome to DM Sans.
- Stats view = 800 px vertical scroll dump — KPI ribbon + tab-within-stats (Strava pattern).
- Wishlist actions row always visible — show on hover/focus only.
- Wishlist no `+ Add` in header when list has items.
- Trips view 50/50 split hardcoded; no drag-to-reorder stops; no full-screen map for planning.
- Regions view: filter map by region click + drill-down zoom still open (popups ✅, filtering ✗).
- Transit legend inline hex colors not linked to `--success`/`--warning`/`--danger` semantic vars.
- Two 🏛️ categories (Monument + Museum) — emoji collision.
- `#map-search-results` persists stale text after sidebar blur.
- Ad-hoc spacing (8/10/12/14/16/20/24 px) — no 4px-base grid.

**Live functionality LOW** — drag-drop no undo; wishlist sort on keyboard nav; autocomplete persistence after blur.

## ✨ Power features

Ranked by impact-vs-effort. Pick 2-3 per sprint.

1. **🛣️ Plan-a-Day trip builder from Wishlist** — select 3-5 wishlist → auto walking-order route (OSRM) → named Day Trip.
4. **🔗 Share trip via public read-only link** — no account needed to view a shared itinerary.
5. **📡 Offline / PWA mode** — Service Worker + tile cache. Unblocks Google-Maps share-target above.
6. **🔍 Smart import deduplication** — fuzzy-match incoming names vs existing (Levenshtein < 0.2 + within 500 m) before commit.
7. **⏱️ Time-of-day heatmap** — "you visit restaurants mostly Fri-Sat 8-10 pm". Uses existing `visits[].date`.
8. **🧭 Context-aware Discover** — when viewing a trip, seed Discover at trip centroid + suggest missing categories.
9. **💱 Currency overlay** for Regions — local symbol + FX rate per country.
10. **👥 "People lens" in Chronology** — toggle showing each person as a colored lane.
11. **📥 Direct Google Maps Saved Places import** (Takeout CSV) — primary first-run seeding source.
12. **🎯 Isochrones / travel-time rings** — X min by car/walk/transit from a pinned location.
13. **🚫 "Already been" detection on Timeline import** — fuzzy-match vs existing `been` items; flag as "update date?" instead of duplicating.
14. **🕸️ Graph view on Atlas tab** — node-link over dark basemap, directed edges between consecutive visits, colored by transit mode.
15. **🌉 Bifrost ↔ Oikumene bridge** — bidirectional location/trip exchange with the Bifrost travel planner.
16. **🌐 Dynamic overlays Tier 2+** — USGS earthquakes (lowest-cost next), FlightRadar live, ISS track, wind/jet-stream, marine AIS. Registry in place — ~30 lines per overlay.
17. **🎥 Replay export to GIF/MP4** — "Record" button → shareable clip.
18. **💰 Trip cost tracker** — cost field per stop/transit → per-trip + per-year spend roll-up.
19. **🔀 Conflict-free import preview diff** — adds/updates/dupes as reviewable list before any import commits.

## Sequenced ship plan

| Sprint | Theme | Status |
|---|---|---|
| S1 | Audit 2026-06-02 P0 close-out | ✅ All 10 shipped 2026-06-03 |
| S2 | Hardening + perf round 2 | ✅ All batches shipped 2026-06-04 → 2026-06-12 |
| S2.5 | Audit-fix batch (2026-06-11) | ✅ All items shipped 2026-06-12 |
| **S3** | **UX + Power features** | ✅ **DONE.** Sidebar FAB · Stadia tiles · provider jargon cleanup. |
| **S4** | **Power features** | 🔴 **NEXT.** Pick 2-3 from Power features list. |

## ⛔ Blocked / Dropped

- **beliapp.co import** — `beliapp.co/app/<username>` is install-marketing only. No web profile/JSON/SPA bootstrap. 2026-05-31 user-confirmed skip.
- **Sync to Google Maps Saved Lists** — no public write API.
- **Google Photos Library API (Path 1)** — dead since 2025-03-31 (scope removed).
- **Nav collapse to 5+overflow** — user explicitly rejected 2026-06-12.
