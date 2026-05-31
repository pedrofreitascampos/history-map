# Research Brief: Google Photos Integration Paths for Oikumene

**Date:** 2026-05-31  
**Scope:** Fetching the user's photos by GPS + date range so Oikumene can surface them when a location is opened

---

## 1. TL;DR / Recommendation

The direct Google Photos API path is **dead on arrival** as of March 2025: the broad read scope (`photoslibrary.readonly`) was permanently removed, the Picker API that replaced it is interactive-only (no server-side search by location or date), and GPS metadata has never been exposed through the API. The only viable programmatic paths are the **photo-org bridge** (Path 2) or **manual upload with client-side EXIF parse** (Path 3). The bridge is the higher-value option but requires answers about the NAS's network exposure before it can be scoped. Ship Path 3 first as an immediate-value stopgap.

| Path | Effort | User value | Risk | Verdict |
|------|--------|-----------|------|---------|
| 1 — Direct Google Photos API | N/A | High (if it worked) | Blocked: scope removed Mar 2025, GPS never exposed | **Not viable** |
| 2 — photo-org bridge (NAS SQLite) | M (3–5 days) | High — surfaces all historical library photos automatically | Medium: requires NAS port exposure or static export mechanism | **Best long-term path** |
| 3 — Manual upload + client EXIF | S (1–2 days) | Medium — user drops photos, app auto-associates | Low | **Ship first** |

---

## 2. Path 1 — Direct Google Photos API

### Current state (March 2025 onwards)

On **March 31, 2025**, Google made a breaking change to the Photos Library API ([Google Developers Blog, Sep 2024](https://developers.googleblog.com/en/google-photos-picker-api-launch-and-library-api-updates/)). Three scopes were permanently removed:

- `https://www.googleapis.com/auth/photoslibrary.readonly` — **removed**
- `https://www.googleapis.com/auth/photoslibrary.sharing` — **removed**
- `https://www.googleapis.com/auth/photoslibrary` — **removed**

Apps that previously held tokens for these scopes now receive **HTTP 403 PERMISSION_DENIED** on all Library API calls. There is no grace period or migration path for the old scopes.

After the change the Library API still exists, but it is locked down to **app-created content only**: an app can only list, search, and retrieve media items that it itself uploaded via `mediaItems.batchCreate`. It cannot read the user's existing library in any way.

**This is a complete blocker for the "show me photos from my library near this location" use case. There is no workaround.**

### GPS metadata blocker — confirmed still true

GPS coordinates have never been exposed via `mediaItem.mediaMetadata` or any sub-field. The `photo` sub-object of `mediaMetadata` exposes only: `cameraMake`, `cameraModel`, `focalLength`, `apertureFNumber`, `isoEquivalent`, `exposureTime`. There is no `geoData`, `latitude`, `longitude`, or equivalent field in the API response schema. This was confirmed by the Google Issue Tracker thread ([#111228390](https://issuetracker.google.com/issues/111228390), open since 2018 and still unresolved).

The rationale Google has consistently cited is user privacy: exposing GPS to third-party apps would allow precise location history extraction without the user being explicitly aware.

**Separately verified:** the photo-org codebase (`google_photos_client.py`, `_parse_media_item`) confirms this — `lat, lon = None, None` is hardcoded; the GPS values on the `MediaItem` model are always null even after a full API fetch. GPS is extracted only by downloading the full image bytes and parsing EXIF client-side (see `trip_detector.py:extract_gps_from_image`). This means photo-org had to work around the same API limitation.

### Library API vs Picker API

The **Google Photos Picker API** is the intended replacement for user-initiated photo selection ([Google Developers: Get started with the Picker API](https://developers.google.com/photos/picker/guides/get-started-picker)). Key constraints:

- **Session-based, interactive only.** The user must open a Picker UI, manually select photos, and the app receives those specific items for that session. There is no server-side call to search the library programmatically.
- **No filtering by date or location.** The Picker does not expose `dateFilter`, `contentFilter`, or any geographic filter. The user can browse and search within the Picker's own UI, but the app cannot pre-filter to "photos from this trip".
- **No GPS in results.** Returned `mediaItem` objects have the same metadata schema as the Library API — no GPS coordinates.
- **Rate limit:** 100,000 requests/minute per project (effectively unlimited for personal use).

The Picker is useful for "let the user attach a specific photo to this location" (Path 3 variant), but cannot auto-discover photos matching a location.

### OAuth scope verification for personal-use

`photoslibrary.readonly` was classified as a **Restricted** scope (most stringent tier). Restricted scope verification requires:

- Google brand review (2–3 business days)
- Security assessment by a Google-approved third-party lab
- Annual re-verification

This process is designed for production apps with many users. There is no official "personal use / single developer / internal" exemption for restricted scopes on public OAuth clients. The unverified-app flow (the purple warning screen) is tolerated for **Testing** status apps capped at 100 test users, but `photoslibrary.readonly` was removed regardless of verification status on March 31, 2025 — the scope no longer exists, making verification moot.

**Note:** photo-org (`google_photos_client.py`) was using `photoslibrary` and `photoslibrary.sharing` — both removed. The photo-org pipeline is likely broken as of April 2025 unless a new scope was added.

### Search filters available

Before the March 2025 removal, `mediaItems.search` supported:
- `dateFilter` — `ranges[]` with `startDate`/`endDate` (calendar dates, not timestamps)
- `mediaTypeFilter` — `PHOTO`, `VIDEO`, or `ALL_MEDIA`
- `featureFilter` — `FAVORITES` only
- `contentFilter` — content categories like `LANDSCAPES`, `CITYSCAPES`, `PEOPLE`, etc. (not GPS-based)

**There was never a geographic filter.** No `geoFilter`, no bounding-box search, no proximity search. The only GPS-based feature was trip albums, which Google builds internally but does not expose as a filter in the Library API.

### Quotas and rate limits

Library API (for app-created content only, post-March 2025):
- 10,000 requests/project/day
- 75,000 media-bytes access requests/project/day

Picker API:
- 100,000 requests/project/minute (effectively unlimited)

No paid tier exists for the Photos API; quota increases can be requested via Google Cloud Console but are not guaranteed.

### Verdict: Not viable

The Google Photos Library API cannot be used to fetch the user's own photos by location or date range. The relevant scope was removed in March 2025, GPS was never exposed, and the replacement Picker API is interactive-only. Path 1 is closed.

---

## 3. Path 2 — Bridge through photo-org

### What photo-org does today

photo-org is a Python pipeline (Docker on Synology NAS) that:

1. **Fetches** all media items from Google Photos via the Library API (`iter_all_media_items`)
2. **Downloads images** and extracts GPS from EXIF using PIL (`trip_detector.py:extract_gps_from_image`) — this is precisely the workaround needed because the API doesn't return GPS
3. **Clusters GPS+date** data using DBSCAN (sklearn) with a 50 km radius and 2-day gap threshold to detect trips (`detect_trips`)
4. **Reverse-geocodes** trip centroids via Nominatim and creates Google Photos albums (`create_trip_albums`)
5. **Scans faces** using InsightFace to build per-daughter and family albums
6. **Fans out** to Synology NAS, OneDrive, and AWS Glacier Deep Archive via rclone

### Data structures it produces

The SQLite database (`photo_org.db`) has five tables:

| Table | Key columns | Relevance to Oikumene |
|-------|-------------|----------------------|
| `processed_media` | `media_id`, `filename`, `has_gps` | Index of all processed photos — `has_gps=1` rows have GPS that was extracted |
| `album_membership` | `media_id`, `album_title` | Trip and season album groupings |
| `face_embeddings` | `media_id`, `person_name`, `confidence` | Face recognition results |
| `backup_ledger` | `media_id`, `destination` | Backup sync status |
| `managed_albums` | `album_title`, `google_album_id` | Album ↔ Google Photos ID map |

**Critical gap:** `processed_media` tracks `has_gps` as a boolean but does **not store the actual GPS coordinates**. The GPS is extracted only to perform the DBSCAN clustering and is discarded afterwards — the `MediaItem.latitude/longitude` fields are populated in memory during `fetch_gps_for_items` but are not written to the DB. Similarly, `creation_time` is not stored in `processed_media`.

This means the current DB **cannot answer** "give me photo IDs within 500m of (38.7, -9.14) between 2024-06-01 and 2024-06-05". To enable this query, photo-org would need to store lat, lon, and creation_time per media item.

### Integration options

**Option A — Extend photo-org DB + expose a query API (recommended)**

Effort: ~2 days in photo-org + ~0.5 days in Oikumene.

Steps:
1. Add `latitude REAL, longitude REAL, creation_time TEXT` columns to `processed_media` in `db.py`
2. Persist these fields in `mark_processed` (called from `fetch_gps_for_items` when GPS is extracted)
3. Add a query method: `get_photos_near(lat, lon, radius_km, date_from, date_to) → list[media_id, filename, base_url_or_product_url]`
4. Expose as a minimal FastAPI/Flask endpoint (e.g. `GET /api/photos?lat=&lng=&radius=&from=&to=`) on a port accessible from Oikumene's Render deployment
5. Oikumene fetches this endpoint when a location popup opens and renders thumbnails

**Option B — Nightly static JSON export**

photo-org runs a scheduled `export-index` command that writes a JSON file (gzipped, ~1 MB for a typical 50k-photo library) containing `[{media_id, filename, lat, lon, creation_time, product_url}]`. Oikumene loads this once on startup or on a refresh trigger and queries it in-memory. Syncthing or a shared NAS mount could deliver the file.

Eliminates the need for a live HTTP endpoint but requires a file-delivery mechanism and ~1 MB client-side index load.

**Option C — Sync GPS-tagged media IDs into Oikumene's NeDB**

photo-org exports a per-location index (keyed by `placeId` or `(lat, lon)` bucket) that Oikumene imports during place enrichment. Most aligned with how Oikumene already structures place data, but tightest coupling — changes in photo-org schema break Oikumene imports.

### Important caveat: photo-org's Library API scopes are broken post-March 2025

`google_photos_client.py` uses `photoslibrary` and `photoslibrary.sharing` — both removed on March 31, 2025. **photo-org as currently written cannot fetch new photos from Google Photos.** The entire pipeline depends on a scope that no longer exists.

Fixing this requires migrating to `photoslibrary.appendonly` (only for uploads, not reads) or, more practically, switching to a **Google Takeout** batch import or local-file-based approach for ingestion. This is a significant prerequisite for the bridge path — photo-org must first be repaired before Oikumene can leverage it.

An alternative that avoids the API scope problem entirely: photo-org processes **local NAS photos** (already backed up via rclone) rather than pulling from the API. The EXIF-extraction logic already works on raw image bytes, so pointing it at `/volume1/photos/backup/` instead of the Google API would bypass the scope issue while preserving all GPS indexing capability.

### Effort estimate

| Task | Effort |
|------|--------|
| Fix photo-org API scopes or pivot to local-file ingestion | 1–2 days |
| Extend DB schema to store lat/lon/creation_time | 2 hours |
| Backfill GPS data for existing processed_media items | 1–4 hours (depends on library size; downloads required) |
| Add query method + minimal HTTP endpoint in photo-org | 4 hours |
| NAS network exposure (depends on Pedro's Synology setup) | Unknown |
| Oikumene: popup photo fetch + thumbnail strip | 4 hours |
| **Total** | **3–5 days** |

### Verdict: Best long-term path, with blockers to resolve first

photo-org is structurally the right bridge: it already downloads photos, extracts EXIF GPS, and clusters by trip. The data needed to serve Oikumene is produced mid-pipeline but not persisted. The additions are surgical. The hard unknowns are (a) whether the Synology is reachable from Render (public IP, DDNS, reverse proxy, or Cloudflare tunnel), and (b) the API scope fix. Viable once those are resolved.

---

## 4. Path 3 — Manual Upload + Client-Side EXIF Parse

### Mechanism

User drags photos onto an Oikumene location card or the edit modal. The browser parses EXIF using a library, extracts GPS + DateTimeOriginal, auto-populates the visit date and confirms the location match, then stores a thumbnail reference or media entry against the location.

### Library options

**`exifr`** ([npm](https://www.npmjs.com/package/exifr), [GitHub](https://github.com/MikeKovarik/exifr))
- Actively maintained (~7.1.x), 65 KB minified, tree-shakeable
- Browser-native (no Node.js required)
- Reads JPEG, HEIC, TIFF, PNG
- Outputs `{ latitude, longitude, DateTimeOriginal, Make, Model, ... }` directly — GPS DMS-to-decimal conversion is built in
- Supports `File`, `Blob`, `<img>` element, URL, ArrayBuffer
- Best choice

**`exifreader`** ([npm](https://www.npmjs.com/package/exifreader))
- Lighter (20 KB), good GPS support, TypeScript definitions
- Good alternative if tree-shaking is a concern

**`piexifjs`** — write-only, not useful here.

### Storage options

| Option | Effort | Max photos | Notes |
|--------|--------|-----------|-------|
| Store `product_url` / link only (user pastes Google Photos share URL) | Minimal | Unlimited | No blob storage; links expire if unshared |
| Store EXIF-derived metadata only (lat/lon, date, filename) — no image | Trivial | Unlimited | Oikumene shows a text list, not thumbnails |
| Store `data:image/jpeg;base64,...` in NeDB | 0.5 days | ~5–10 photos/location (NeDB doc size limit ~16 MB) | Functional but NeDB is a bad blob store |
| Upload to `/api/uploads/` endpoint → serve static file | 1 day | Unlimited | Needs disk quota mgmt on Render (ephemeral!) |
| Upload to external storage (Cloudinary free tier, or NAS-mounted path) | 1.5 days | Unlimited | Cleanest; Cloudinary free = 25 GB/25k transforms |

**Recommended storage for Path 3:** EXIF metadata only (no blob), plus the photo's filename, GPS, and date stored in the location's `media` array. Show a "N photos attached" badge — user can open them from their device. Defer actual image hosting to the photo-org bridge when that's ready.

### Effort estimate

- Add a drop zone to the location edit modal: 2 hours
- Client-side exifr parse + GPS/date extraction: 2 hours
- Store parsed metadata in location NeDB doc: 1 hour
- UI: show attached photo count + date in popup: 1 hour
- **Total: ~1–2 days** (metadata-only variant)

Adding actual image hosting (+blob store) doubles the effort.

### Verdict: Ship first

No external dependencies, no OAuth, no API changes. Gives immediate value for photos the user adds manually going forward. GPS auto-match (did you take this photo within 500m of the stored lat/lng?) makes onboarding feel smart. The metadata store is also the ground-truth index that photo-org's bridge can later back-fill automatically.

---

## 5. Recommendation

**Ship in this order:**

1. **Path 3 — EXIF drop zone (metadata only), ~2 days.** Attach photos to visits in the edit modal, parse GPS + date with `exifr`, store metadata in the NeDB location doc. No blob storage. Gives Pedro a way to manually document visits with photo context immediately.

2. **Resolve photo-org prerequisites (parallel track, ~2 days).** Fix the API scope breakage or pivot to local-file ingestion from the NAS backup path. Extend the DB schema to persist lat/lon/creation_time. This unblocks the bridge.

3. **Path 2 — photo-org bridge HTTP endpoint, ~3 days.** Once photo-org can index GPS, add the query API and wire Oikumene's popup to fetch thumbnails automatically. This is the "open a place and see all your photos from that visit" feature at full automation.

**If NAS is not internet-reachable** (see Open Questions), Path 2 falls back to Option B (nightly static JSON export via file sync), or to a Cloudflare Tunnel / Tailscale VPN approach for the Synology.

---

## 6. Open Questions for Pedro

1. **Is the Synology NAS reachable from the internet?** (Does it have a public IP, DDNS hostname, or port forwarding?) Oikumene runs on Render — it can only call photo-org if there's an externally accessible endpoint. Alternatives: Cloudflare Tunnel (`cloudflared`) or Tailscale are low-config options.

2. **Is photo-org currently running?** Given the March 2025 scope removal, the Google Photos fetch step is broken. Has it been patched, or has the pipeline been idle?

3. **Does photo-org already process local-file photos?** The EXIF extraction in `trip_detector.py` works on raw bytes — it could be pointed at `/volume1/photos/backup/` (rclone destination) without any API call. This would be the fastest fix to the scope problem.

4. **Library size?** The backfill scan (downloading images to extract GPS for already-processed items) scales linearly. At 10,000 photos with HTTP download latency, even parallelized it takes hours. Is the NAS backup copy local enough to read EXIF without downloading from Google?

5. **Where should photos appear in Oikumene?** Three UX options:
   - **Inline popup:** a horizontal thumbnail strip below the visit notes — best for quick glance
   - **Edit modal gallery tab:** a dedicated Photos tab in the edit modal — best for managing photos
   - **Separate gallery view:** a full-page photo grid for a location — most ambitious
   Start with the edit modal tab (lower layout risk) and promote to inline later.

6. **Should manual-upload and bridge-sourced photos share the same `media[]` schema?** Yes — design the metadata schema once for Path 3 and let the bridge back-fill it. `{ source: "manual" | "photo-org", mediaId, filename, lat, lon, takenAt, productUrl }` is sufficient.

---

## References

- [Google Developers Blog — Picker API launch and Library API changes (Sep 2024)](https://developers.googleblog.com/en/google-photos-picker-api-launch-and-library-api-updates/)
- [Google Photos APIs: Updates page](https://developers.google.com/photos/support/updates)
- [Google Photos APIs: Release notes](https://developers.google.com/photos/support/release-notes)
- [Picker API: Get started guide](https://developers.google.com/photos/picker/guides/get-started-picker)
- [Google Photos API: Limits and quotas](https://developers.google.com/photos/overview/api-limits-quotas)
- [Google Photos API: Authorization scopes](https://developers.google.com/photos/overview/authorization)
- [Google Photos Library API (legacy): Authorization scopes](https://developers.google.com/photos/library/legacy/guides/authorization)
- [Restricted scope verification](https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification)
- [mediaItems REST resource reference](https://developers.google.com/photos/library/reference/rest/v1/mediaItems)
- [Issue Tracker #111228390 — EXIF metadata missing when downloading photos](https://issuetracker.google.com/issues/111228390)
- [memoryKPR — Google Photos API Deprecation: What It Means for Third-Party Apps (2025)](https://memorykpr.com/blog/google-photos-api-deprecation-what-it-means-for-third-party-apps-and-how-to-prepare/)
- [Hacker News — Google Photos API Read-Only Scopes Deprecated](https://news.ycombinator.com/item?id=41604241)
- [exifr npm package](https://www.npmjs.com/package/exifr)
- [exifr GitHub](https://github.com/MikeKovarik/exifr)
- [exifreader npm package](https://www.npmjs.com/package/exifreader)
