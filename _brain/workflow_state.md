# OSINT Dashboard — Root Planner workflow

**Working directory for commands:** `osint-dashboard/backend/` (see `../README.md`).  
**Stack:** FastAPI + Jinja2 + Tailwind (CDN) + SQLite (`data/osint.db`).  
**Decision log:** `_brain/intelligence_features_decisions.md` (append-only for workers).

---

## Deployment — Railway (SQLite path)

- [x] **2026-05-05 — `DATA_PATH` for persistent DB** — `backend/app/db.py` resolves `osint.db` with `os.environ["DATA_PATH"]` when set (directory path; file is `<DATA_PATH>/osint.db`). If unset, defaults to `backend/data/osint.db`. The parent directory is created with `mkdir(parents=True, exist_ok=True)` in `_connect()` before `sqlite3.connect`. Legacy JSON seed path remains `backend/data/zero_day_headlines.json` (bundled with the app, not on the volume).
- [x] **2026-05-05 — GitHub `origin` + `main`** — Local monorepo at `KM-IT-OPS` sets `remote.origin.url` → `https://github.com/KM-it-ops/osint-dashboard`. The full `osint-dashboard/` tree is committed locally, then published to GitHub with `git subtree split --prefix=osint-dashboard` → branch `export-osint-main` pushed to **`origin/main`** (repo root = dashboard app; `_brain/` stays local-only). The remote had GitHub’s default **Initial commit**; push used **`--force`** once so **`main`** matches the subtree (replace template history).
- [x] **2026-05-05 — Railway Gunicorn (ASGI)** — Stack is **FastAPI** (not Flask): ASGI application object **`app`** in `osint-dashboard/backend/app/main.py`. `osint-dashboard/requirements.txt` includes **gunicorn** plus existing runtime deps. **`osint-dashboard/railway.json`** sets `deploy.startCommand` to run from `backend/` with **`gunicorn app.main:app -k uvicorn.workers.UvicornWorker`** binding **`0.0.0.0:${PORT}`** (default 8000 locally). Nixpacks build left as default.

---

## Completed bootstrap (reference)

- [x] Phases 1–4: skeleton, headlines, SQLite, Live Target Analyzer (see git history / prior checklist).

---

## Phase 5 — Feature 1: Public advisory & leak-intel scraper (“Dark Web Scraper”)

**Objective:** Safely collect **public** threat intelligence (security advisories, official breach notifications, CVE/NVD context) using the **Firecrawl HTTP API** (same queries the Firecrawl MCP would run in the IDE—backend cannot host MCP; use `app/firecrawl_client.py`).

**Ethics / scope:** No access to illicit marketplaces or exfiltrated personal data. Queries must be curated: `site:`, vendor advisories, CISA, NIST, public postmortems.

| Step | Work |
|------|------|
| 5.1 | **Schema:** `public_intel_snapshots` — `id`, `query_label`, `query_used`, `results_json`, `source_family` (e.g. `advisory`), `created_at`. |
| 5.2 | **Backend:** `POST /api/intel/scrape-advisories` (optional body: `focus` tag); calls Firecrawl search with whitelisted query set; persists snapshot; `GET /api/intel/snapshots?limit=`. |
| 5.3 | **UI:** Tailwind card “Advisory intelligence” — list latest snapshots, button “Refresh from public sources”, loading/error states. |
| 5.4 | **Verify:** `uvicorn app.main:app --reload` + hit APIs; append decision log. |

- [x] Phase 5 complete

---

## Phase 6 — Feature 2: Live threat map widget

**Objective:** Geographic visualization of **recent cyber-event records** derived from stored data (and optional seeded demo rows for empty DB).

| Step | Work |
|------|------|
| 6.1 | **Schema:** `geo_threat_events` — `id`, `label`, `country_code` (ISO-3166-1 alpha-2), `lat`, `lon`, `severity` (`low`/`medium`/`high`), `source_ref`, `created_at`. Index on `created_at`. |
| 6.2 | **Backend:** `GET /api/threat-map/events?limit=`; optional `POST` (internal/dev) to insert test events. Optionally enrich future: parse country from `target_intelligence_reports.report_json` on new analyzer runs (document in decision log if implemented). |
| 6.3 | **UI:** Tailwind widget + **SVG world map** (simple projection) or dot plot on a responsive canvas; plot lat/lon (fallback: country centroid lookup table inline in Python or small JSON static asset). |
| 6.4 | **Verify:** API returns GeoJSON-friendly list; dashboard renders markers; append decision log. |

- [x] Phase 6 complete

---

## Phase 7 — Feature 3: Automated CVE matcher

**Objective:** Cross-reference scanned targets against a **live CVE source** (prefer **NVD API 2.0** `services.nvd.nist.gov`, respect rate limits; cache responses in SQLite).

| Step | Work |
|------|------|
| 7.1 | **Schema:** `cve_cache` — `cve_id` PRIMARY KEY, `payload_json`, `fetched_at`; optional `cve_match_runs` — `id`, `target_raw`, `matched_cve_ids_json`, `created_at`. |
| 7.2 | **Backend:** `GET /api/cve/match?target=` extracts keywords/CVE IDs from target string; queries NVD (with httpx), merges with local reports; returns ranked matches. Shared client module `app/cve_client.py` with rate-limit handling. Env: optional `NVD_API_KEY` for higher quota. |
| 7.3 | **UI:** Section on dashboard or under analyzer results — “CVE matches” table (id, severity, summary snippet). |
| 7.4 | **Verify:** Match a known CVE id string; cache row appears in DB; decision log. |

- [x] Phase 7 complete

---

## Phase 8 — Feature 4: Social threat monitor (zero-day chatter feed)

**Objective:** Near–real-time **surface-web** intel (not private social APIs): Firecrawl search for discussions of zero-days / exploits; store and poll via API.

| Step | Work |
|------|------|
| 8.1 | **Schema:** `social_intel_items` — `id`, `title`, `url`, `source_query`, `snippet`, `published_hint`, `created_at` (ingestion time). Unique index on `url`. |
| 8.2 | **Backend:** `POST /api/intel/refresh-social-feed` (Firecrawl multi-query); `GET /api/intel/social-feed?limit=`. |
| 8.3 | **UI:** Live-feed card with auto-refresh (e.g. `setInterval` 120s) + manual refresh; accessible list markup. |
| 8.4 | **Verify:** Refresh populates rows; GET returns JSON; decision log. |

- [x] Phase 8 complete

---

## Phase 9 — Feature 5: Interactive relationship graph

**Objective:** Node–edge graph linking **IPs, domains, vulnerabilities** from SQLite (`target_intelligence_reports`, CVE cache, optional `graph_edges`).

| Step | Work |
|------|------|
| 9.1 | **Schema:** `graph_nodes` — `id`, `kind` (`ip`/`domain`/`cve`/…), `label`, `ref_id` nullable; `graph_edges` — `src_id`, `dst_id`, `relation` (text). Population job: derive from existing rows + regex extract IPv4/domain from `report_json`. |
| 9.2 | **Backend:** `GET /api/graph` returns `{ nodes: [...], edges: [...] }` in vis.js-compatible shape; `POST /api/graph/rebuild` to recompute from DB. |
| 9.3 | **UI:** Add **vis-network** (or similar) via CDN in `index.html`; dark theme to match dashboard; physics on, zoom/pan. |
| 9.4 | **Verify:** Graph renders with ≥1 edge when data exists; decision log. |

- [x] Phase 9 complete

---

## Phase 10 — Feature 6: PDF report generator

**Objective:** One-click PDF for a **specific target** report from `target_intelligence_reports`.

| Step | Work |
|------|------|
| 10.1 | **Deps:** Add `reportlab` (or pypdf + reportlab) to `requirements.txt`. |
| 10.2 | **Backend:** `GET /api/report/pdf/{report_id}` returns `application/pdf` (filename `intel-report-{id}.pdf`); sections: target, timestamp, summary text from `report_json`, key fields. |
| 10.3 | **UI:** “Download PDF” button next to each report in the recent reports list (or report detail). |
| 10.4 | **Verify:** PDF opens; decision log. |

- [x] Phase 10 complete

---

## Phase 11 — Feature 7: Critical CVE alert system + notification center

**Objective:** Background monitoring for **new Critical** CVE notices (from NVD pull or diff vs `cve_cache`), persist alerts; UI bell + unread list.

| Step | Work |
|------|------|
| 11.1 | **Schema:** `cve_alerts` — `id`, `cve_id`, `severity`, `title`, `summary`, `detected_at`, `acknowledged_at` nullable; partial index or filter on severity = CRITICAL. |
| 11.2 | **Background:** `asyncio` periodic task in lifespan (e.g. every 6h) or `BackgroundScheduler`—fetch recent Critical CVEs since last run watermark (store `app_metadata` key `last_nvd_poll`). |
| 11.3 | **Backend:** `GET /api/alerts`, `POST /api/alerts/{id}/ack`. |
| 11.4 | **UI:** Notification center panel; unread count badge; mark read. |
| 11.5 | **Verify:** Simulated or real NVD response creates row; ack works; decision log. |

- [x] Phase 11 complete

---

## Phase 12 — Feature 8: Executive summary dashboard widget

**Objective:** Auto-generated **text summary** of current landscape from local aggregates (no mandatory external LLM): counts from headlines, geo events, critical alerts, latest analyzer targets; optional template paragraphs.

| Step | Work |
|------|------|
| 12.1 | **Backend:** `GET /api/intel/executive-summary` returns `{ generated_at, text, stats: { ... } }`. |
| 12.2 | **UI:** Prominent card with summary paragraph + bullet metrics (Tailwind). |
| 12.3 | **Verify:** Endpoint stable with empty/partial DB; decision log. |

- [x] Phase 12 complete

---

## Execution order for workers

1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 (dependencies: 7 benefits from 3’s cache; 9 benefits from targets/CVE; 11 benefits from 7; 12 aggregates all). Workers may **merge phases** only when safe; prefer one PR-sized chunk per phase.

**Verification default:** From `osint-dashboard/backend/`: `python -m uvicorn app.main:app --reload` and manual/API checks.
