# Oikumene Roadmap

Project-specific backlog for the Oikumene history map app.

Convention (defined in `~/projects/ai/companion/docs/architecture.md`):
- **Top-level** (this file) — Oikumene-specific concerns
- **Personal life** — `~/.claude/personal/roadmap.md` (gitignored, never in repo)

Session-log detail (commit chronology, test counts) lives in the memory roadmap
at `~/.claude/projects/C--Users-pedro-projects-software-history-map/memory/project_roadmap.md`.

## Open

### Security (audit 2026-05-30, reconciled against shipped work)

The 2026-05-30 audit produced 12 findings. All 11 actionable findings are
now resolved; H-2 has a partial fix shipped with a deferred long-term piece.
See Resolved table below for the full reconciliation.

### H-2 deferred decision

JWT TTL was shortened 90d → 30d and per-token `jti` revocation + `/api/auth/logout`
shipped (`53e2db7` era). Long-term migration to **HttpOnly cookies** remains
deferred — captured here so it doesn't get lost. Tradeoff: cookie migration
touches every `api()` call site + needs CSRF on state-changing routes.

### Other open items

- **Marker layer-diff** — ✅ shipped 2026-05-30 (commit `d1b37ba`).
- **FR24 "not an export" guard** — ✅ shipped 2026-05-30 (commit `9f34cd4`).
- **LOW polish bundle** — ✅ shipped 2026-05-30 (commit `9f34cd4`).
- **CSP nonce refactor** — ✅ partial shipped 2026-05-30 (commit `aa479d5`).
  `script-src` now requires a per-request nonce; `'unsafe-inline'` removed.
  Residuals (intentionally deferred): `script-src-attr` still permissive
  (hundreds of `onclick=` handlers — needs an event-delegation refactor);
  `style-src` stays permissive because Leaflet injects nonceless inline
  styles at runtime (per CSP-3, mixing `'unsafe-inline'` with a nonce in
  style-src causes browsers to ignore `'unsafe-inline'` — no strict-dynamic
  story for third-party CSS).
- **Bootstrap map/collections/trips DBs** — waiting on user inputs. Existing
  bootstrap surfaces: bulk JSON/CSV/KML, Google Timeline, OSM enrich, Google
  Places sync, FR24 (transits + auto-airport stops).

### Wishlist (P1+)

- **Google data — easier ingestion path.** Today's import surfaces touch Google
  data only at the edges: Google Timeline JSON import (locations + trips),
  Google Saved Places JSON import (parseGoogleSavedPlaces — Place IDs from
  starred list URLs), and per-location Google Places sync (rating + price +
  user count). What's missing is a smooth "give me everything I've put into
  Google Maps" path. Research spike needed: (a) Google Takeout still the
  authoritative dump path — what schemas does it ship today vs. when the
  Timeline parser was written; (b) is there a partner-program/Saved-Places
  API that would let us pull stars + want-to-go + custom lists directly with
  OAuth scope upgrade; (c) sharable-list URL scraping as a stopgap. Tracked
  alongside the existing Maps-saved-lists writeback blocker.
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
  with-flags stats section. **Session totals: 517 jest + 5 e2e green.**
