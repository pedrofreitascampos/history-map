# Research Brief: Google Data Ingestion Paths for Oikumene

**Date:** 2026-05-30  
**Scope:** Getting "everything I've put into Google Maps" into Oikumene

---

## 1. Today's Surface

Oikumene currently ingests two Google data sources via client-side file drop: (a) Timeline exports — handling five distinct JSON schemas (old `timelineObjects`/`placeVisit`, a mid-era plain array of `placeVisit`, the new `visit`/`topCandidate` array, the `semanticSegments` wrapper from phone export, and `timelineEdits`) plus raw `Records.json` GPS pings — and (b) "Maps (your places)" Saved Places as a GeoJSON `FeatureCollection` with a `google_maps_url` property per feature. The server-side Places Details API proxy enriches imported locations with ratings, price level, and coordinates. The gap is everything else: the separate Saved folder CSV exports (one per list — Starred, Want to Go, custom lists), Maps reviews, labeled places, and any forward path for the new encrypted on-device timeline format. There is also no write-back — Oikumene cannot push data back to Google Maps in any direction.

---

## 2. Takeout Schema Status (2026)

### Timeline — the big 2024 break

In late 2024 Google moved Timeline to **on-device storage** and reduced the cloud auto-delete window to 3 months. The knock-on effects for Takeout are severe:

- A Takeout request today for "Location History" returns **three useless files**: `Settings.json` (contains `timelineDeletionTime`), `Encrypted Backups.txt` ("You have encrypted Timeline backups stored on Google servers" — no data), and `Tombstones.csv`. **No placeVisit JSON, no Records.json.**
- The actual timeline data now lives on the user's Android phone. To export it: **Settings > Location > Location Services > Timeline > Export Timeline data**. This produces a single large JSON (typically 30–70 MB) with three top-level keys:
  - `semanticSegments` — interpreted stays and travel segments. Each `visit` entry has `topCandidate.placeLocation` (lat/lng as a degree string `"48.1234°, 16.5678°"`), `placeId`, and `semanticType`.
  - `rawSignals` — low-level GPS pings, Wi-Fi scans, activity records. ~1 month retention.
  - `userLocationProfile` — frequently visited places with `placeId` and `HOME`/`WORK` labels.

**Assessment of existing parsers:**

| Parser | Status |
|--------|--------|
| `parseGoogleTimelineOld` — `timelineObjects`/`placeVisit`, E7 coords | Still valid for pre-2024 archive files users already saved. Not produced by Takeout 2024+. |
| `parseGoogleTimelineNew` — array with `visit.topCandidate.placeLocation` | **Partially matches phone export** but coordinate parsing is wrong: phone export uses `"48.1234°, 16.5678°"` strings with degree symbols; current parser splits on `,` and uses `parseFloat` which drops the `°` character — this works accidentally (parseFloat stops at `°`). The name falls back to `semanticType` instead of place name because `placeLocation.name` is not read. `_placeId` is captured but `topCandidate.placeId` vs `topCandidate.placeLocation` nesting needs verification against a real file. |
| `parseGoogleTimelineSegments` — `semanticSegments` wrapper | **Closest match for new phone export.** Handles the top-level `semanticSegments` key correctly. Same coordinate concern as above — works by accident via `parseFloat`. Does not read `placeId`. |
| `parseGoogleRawLocations` — `locations[]` with `latitudeE7` | Valid for old `Records.json`. Not produced by Takeout 2024+. |
| `parseGoogleTimelineEdits` — `timelineEdits` wrapper | Niche / legacy; status unclear. |

**Bottom line for parsers:** Users with pre-2024 archive files are well served. Users exporting from their phone today will likely land in `parseGoogleTimelineSegments` (correct branch) but get degraded data: place names from `semanticType` labels rather than actual place names (no `placeLocation.name` read), and `placeId` is not harvested (missed enrichment opportunity). This is a fixable ~1-hour patch, not a rewrite.

### Saved Places

Takeout offers **two separate export paths** that produce different formats:

**Path A — "Maps (your places)"** (what `parseGoogleSavedPlaces` already handles):
- Exports `Saved Places.json` as GeoJSON `FeatureCollection`.
- Properties: `Title`, `google_maps_url`, `location.address`, `location.name`, `Comment`.
- **Includes coordinates** in `geometry.coordinates`.
- Covers starred/hearted places and reviews, not custom lists.
- Known bugs: some entries export as `[0, 0]` (no coords); custom-list places sometimes export without a name.

**Path B — "Saved"** (not yet handled):
- Exports **one CSV per list** (Starred Places, Want to go, and every custom list the user created).
- Columns: `Title`, `Note`, `URL`, `Tags`, `Comment` (no `Lat`/`Lng`).
- Oikumene's `parseCSV` already detects `isGoogleSaved` (has `title` + `url`, no coord columns) and routes to Nominatim geocoding. **This path already works** but is undiscoverable — there's no UI hint that dropping a CSV from the "Saved" folder is supported.
- The `URL` column contains a Google Maps link with `@lat,lng` embedded; the parser already extracts this with a regex. For most places this gives exact coordinates without a geocode call.

**Maps Reviews** — available via `dataportability.maps.reviews` scope (see Section 3); not currently ingested.

---

## 3. API Options

### Places API (already in use)
- `place/details`, `place/findplacefromtext`, `place/textsearch` — all already proxied.
- **No "list my places" endpoint exists.** The Places API is a lookup service, not a personal data API. The New Places API (v1, 2023+) adds `places/` and `places/:id` but still has no user-personalization endpoints.
- The legacy Places API used here is deprecated as of Q1 2025; Google asks developers to migrate to Places API (New). For Oikumene's use (details + text search) the migration is straightforward field renames — not urgent but worth scheduling.

### Google Data Portability API
- Launched 2023, GA for Maps in 2024. Allows third-party apps to initiate a one-time or periodic data export with user OAuth consent.
- Relevant scopes:
  - `dataportability.maps.starred_places` (Restricted) — exports GeoJSON of starred places.
  - `dataportability.maps.aliased_places` (Restricted) — labeled places (Home, Work, custom labels).
  - `dataportability.maps.reviews` (Sensitive) — user's reviews.
  - `dataportability.mymaps.maps` — KML/KMZ of user-created My Maps.
- **"Restricted" scopes require Google's OAuth verification** (security assessment, privacy policy, brand review). This is a multi-week process and not trivially available to a personal/hobby app. Sensitive scopes are lighter but still need policy alignment.
- The export is async (initiates a Takeout-style archive job, not a real-time read). The API is designed for "port my data to a competing service" not "sync my data continuously."
- **Verdict:** Promising but blocked by OAuth scope verification. Not feasible for a personal-use app without Google Cloud verification. Monitor for relaxation of restrictions.

### Google My Maps API
- The Embed API and standalone Maps API for My Maps have never had a public programmatic read/write endpoint. The Data Portability scope `dataportability.mymaps.maps` exports as KML — this is the only programmatic path, and it has the same OAuth verification barrier. My Maps data can be **manually exported as KML** from the My Maps UI (mymaps.google.com → three-dot menu → Export to KML). Oikumene's generic GeoJSON parser would not handle KML directly, but a KML parser is a reasonable 1-day addition if users have My Maps data.

### Google Drive / People API
- No Maps saved places in Drive or People API. Not applicable.

### Shareable list URLs (`maps.app.goo.gl/...`, `google.com/maps/placelists/...`)
- Google Maps "lists" (formerly "place lists") generate shareable short URLs.
- The underlying structure: short URL → 302 redirect → long `google.com/maps/@.../data=...` URL encoding place IDs and coordinates in a protobuf-encoded `data=` parameter.
- Server-side fetching of these URLs works (confirmed by third-party scrapers like the Apify actor), but:
  1. **Requires JavaScript rendering** — the list content loads via XHR after page render; a plain `fetch` returns an empty shell. A headless browser (Puppeteer/Playwright) is needed.
  2. **Only public lists** — private lists (not shared with "anyone with the link") are inaccessible.
  3. **Google ToS §5.3** prohibits scraping Maps properties without authorization. While hobbyist use is unlikely to be enforced, it introduces legal risk and fragility (URL structure changes regularly).
- **Verdict:** Interesting for ingesting publicly shared itineraries from others, but wrong tool for ingesting the user's own private saved lists.

---

## 4. Stopgap Options Ranked by Effort / Value

### (a) Phone Timeline export support — patch `parseGoogleTimelineSegments` ★★★★☆
**Effort:** ~2–4 hours. **Value:** High — this is now the only way users get their recent place visits out of Google.
- Read `placeLocation.name` (or `placeLocation.address`) in addition to `semanticType` so real place names appear instead of generic type labels.
- Harvest `topCandidate.placeId` and store as `_googlePlaceId` so the existing Places API sync can enrich the entry immediately after import.
- Add a UI hint: "Export from Google Maps app: Settings → Location → Timeline → Export" (users have no idea this exists).

### (b) Saved folder CSV drop zone with URL-coord extraction ★★★☆☆
**Effort:** ~1 day. **Value:** Medium — covers Want to Go and custom lists which are not in the GeoJSON path.
- The code already handles this silently; the gap is discoverability.
- Add an explicit "Saved list CSV" drop target or detect the filename pattern (`Starred places.csv`, `Want to go.csv`, `*.csv` from a `Saved/` folder).
- The URL column `@lat,lng` regex already works — confirm it avoids the geocode path for entries that have coords in the URL (most named places do).
- Show a summary after import: "Imported 47 from Starred, 23 from Want to go" so users know which list they dropped.

### (c) KML import for My Maps and manual KML export ★★☆☆☆
**Effort:** ~1 day (add a KML parser). **Value:** Low-medium — serves users who have manually created My Maps layers.
- Add client-side KML/KMZ parsing (e.g. `togeojson` npm package, or ~200 lines of custom XML parsing).
- Accept `.kml` and `.kmz` in the existing file drop zone.
- My Maps KML includes `<name>`, `<Point>` coordinates, and `<description>` HTML — enough for a useful import.

### (d) Sharable-list URL paste (server-side scrape) ★☆☆☆☆
**Effort:** 2–3 days (headless browser integration). **Value:** Low for own data; only useful for public shared lists from others. Legal risk. Do not ship.

### (e) Google Data Portability API OAuth flow ★★☆☆☆
**Effort:** 1–2 weeks (OAuth app, Google verification process, async job polling). **Value:** High potential — covers starred, labeled, reviews in one authenticated flow. Blocked by Google's "Restricted" scope verification for a personal app. Revisit when/if Google relaxes verification requirements for personal-use applications (track `dataportability.maps.starred_places` scope tier changes).

### (f) Manual export guide + multi-format drop zone ★★★★☆
**Effort:** ~0.5 days. **Value:** High — the existing parsers cover 80% of what users need; the gap is user confusion about which files to export and where to drop them.
- Add a "How to export from Google Maps" modal or tooltip with step-by-step screenshots for: (1) Takeout → Maps (your places) → `Saved Places.json`; (2) Takeout → Saved → CSV files; (3) Google Maps app → Timeline → Export.
- The parsers already handle all three. Discoverability is the actual bottleneck.

---

## 5. Recommendation

**Ship in order:**

1. **Patch `parseGoogleTimelineSegments`** (option a, ~4 hours): read real place names and harvest `placeId` from the phone export. This is the highest-signal fix — it unblocks users who recently exported from their phone and got degraded "restaurant" / "food" labels instead of real names. The Places API sync will immediately enrich those entries if a key is configured.

2. **Add a "How to export" guide** (option f, ~0.5 days): a small modal accessible from the import button explaining the three paths with exact menu navigation for each. Most users don't know the phone export exists, and many don't know that Takeout now only returns encrypted blobs via the web. This has disproportionate impact for zero code change to the parsers.

3. **Add KML/KMZ support** (option c, ~1 day): rounds out coverage for My Maps power users and makes the import surface feel complete. Use a well-tested library (`togeojson`) rather than rolling a parser.

4. **Explicitly surface the CSV path** (option b, ~1 day): the code works; make it visible by adding a drag-target hint for `*.csv` files and post-import list breakdown.

**Do not build** the sharable-list scraper. The value (public lists from others) doesn't justify the fragility and ToS exposure.

**Watch:** Google Data Portability API scope verification requirements. If a personal-use / single-developer exemption path appears, the starred places + reviews export is a clean 1-OAuth-flow solution that would supersede the Takeout dance entirely.

---

## References

- [locationhistoryformat.com — Records.json reference](https://locationhistoryformat.com/reference/records/)
- [locationhistoryformat.com — Semantic Location History](https://locationhistoryformat.com/reference/semantic/)
- [Dawarich — What's inside your Google Timeline export](https://dawarich.app/blog/whats-inside-your-google-timeline-export/)
- [addshore.com — The day Google (almost) lost my Timeline data](https://addshore.com/2025/03/the-day-google-almost-lost-my-data/)
- [Google Data Portability API — Available OAuth Scopes](https://developers.google.com/data-portability/user-guide/scopes)
- [Google Data Portability API — Maps schema reference](https://developers.google.com/data-portability/schema-reference/local_actions)
- [Google Data Portability API — My Maps schema reference](https://developers.google.com/data-portability/schema-reference/mymaps)
- [Nick Gracilla — Export Google Maps Saved Places Lists](https://www.nickgracilla.com/posts/export-google-maps-saved-places/)
- [Takeout Tools — Export Guide](https://www.takeout-tools.com/blog/export-google-maps-saved-places-guide)
- [Google Issue Tracker — API for bookmarks/saved places (open since 2017)](https://issuetracker.google.com/issues/68749469)
- [Apify — Google Maps Shared List Scraper](https://apify.com/parseforge/google-maps-shared-list-scraper)
- [Timelinize — Google Location History data source](https://timelinize.com/docs/data-sources/google-location-history)
- [The Register — Google Timeline location purge, Dec 2024](https://www.theregister.com/2024/12/13/google_timeline_purge/)
