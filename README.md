# KM-IT-Ops OSINT Dashboard

Beginner-friendly scaffold: **FastAPI** serves HTML pages built with **Jinja2** templates and **Tailwind CSS** (CDN). Headlines are stored in **SQLite** (`backend/data/osint.db`) and loaded on every request.

## Prerequisites

- Python 3.10+ installed and available as `python`.

## Setup

From this folder (`osint-dashboard/`):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

On macOS/Linux, activate with `source .venv/bin/activate` instead.

## Run the dev server

The app expects your **current working directory** to be `backend/` so imports resolve (`app.main`).

```powershell
Set-Location backend
uvicorn app.main:app --reload
```

Open **http://127.0.0.1:8000/** — you should see the Hello World page.

API docs (automatic): **http://127.0.0.1:8000/docs**

### SQLite (`osint.db`)

On startup, the app creates **`backend/data/osint.db`** if needed. If the headline table is **empty**, it **imports once** from **`backend/data/zero_day_headlines.json`** (legacy Firecrawl export shape). After that, **`/`** and **`/api/headlines`** read **only SQLite**.

To **reload** after you edit the JSON (e.g. new Firecrawl results): delete `backend/data/osint.db`, restart the server, and the JSON will be imported again.

**Cursor MCP:** Global MCP config includes **`mcp-sqlite-osint`** (`npx mcp-sqlite` → path to `osint.db`) so you can inspect tables after the DB file exists. Reload MCP in Cursor if the server does not appear.

### Refresh zero-day headlines (Firecrawl → JSON → DB)

1. Update **`backend/data/zero_day_headlines.json`** (topic, `updated_at`, `source_note`, `headlines` with `title` + `url`). You can produce candidates with Firecrawl CLI, then paste into that shape:

```powershell
npx firecrawl-cli search "recent cybersecurity zero-day vulnerabilities" -o .firecrawl/zero-day-search.json
```

2. Delete **`backend/data/osint.db`** and restart uvicorn so the app re-imports the JSON into SQLite.

## Live Target Analyzer (Firecrawl API)

The dashboard can run **ad-hoc OSINT** on a domain or CVE: it calls **Firecrawl’s HTTP search API** (not Cursor MCP), normalizes results, saves them to SQLite, and shows a report on the home page.

1. Get an API key from [Firecrawl](https://firecrawl.dev) (or use your self-hosted instance URL).
2. In the `osint-dashboard/` folder, create a **`.env`** file (optional but recommended):

   ```env
   FIRECRAWL_API_KEY=your_firecrawl_api_key_here
   # Optional: self-hosted
   # FIRECRAWL_API_URL=https://your-instance.example
   ```

   Keep real keys in `.env` (gitignored) or your host’s secret env vars—never in tracked files.

3. Restart uvicorn. Use the **Live Target Analyzer** search box on **http://127.0.0.1:8000/** .

**API (for scripts):**

- `POST /api/analyze-target` — JSON body `{"target": "example.com"}` or `{"target": "CVE-2024-1234"}`
- `GET /api/target-reports?limit=10` — recent saved reports

Reports are stored in the **`target_intelligence_reports`** table in `backend/data/osint.db`.

**Note:** one-off research inside Cursor can still use the **Firecrawl MCP**; the running app always uses the **REST API** and `FIRECRAWL_API_KEY`.

## Project layout

| Path | Purpose |
|------|---------|
| `backend/app/main.py` | FastAPI app and routes |
| `backend/app/db.py` | SQLite: headlines feed + `target_intelligence_reports` |
| `backend/app/firecrawl_client.py` | Firecrawl `/v1/search` HTTP client |
| `backend/app/target_analyzer.py` | Classify target, normalize intelligence report |
| `backend/templates/` | HTML templates (Jinja2) |
| `backend/static/` | Static files (CSS, images) — use later |
| `backend/data/osint.db` | SQLite database (gitignored; created on run) |
| `backend/data/zero_day_headlines.json` | Optional one-time seed file (same shape as Firecrawl export) |
