"""

KM-IT-Ops OSINT Dashboard — web entrypoint.



Run from the `backend` folder:

    uvicorn app.main:app --reload



Then open http://127.0.0.1:8000/ in your browser.



Headline data is stored in SQLite (`data/osint.db`), seeded once from `data/zero_day_headlines.json`

if the database is empty (legacy Firecrawl export).



Live Target Analyzer uses the Firecrawl HTTP API (`FIRECRAWL_API_KEY`); see README.

"""



from __future__ import annotations



import asyncio

import logging

import os

import re

from contextlib import asynccontextmanager

from datetime import timezone, datetime

from typing import Any, Literal

from pathlib import Path



from dotenv import load_dotenv

from fastapi import FastAPI, HTTPException, Request

from fastapi.responses import JSONResponse, StreamingResponse

from fastapi.templating import Jinja2Templates

from pydantic import BaseModel, Field



from app.db import (

    acknowledge_cve_alert,

    aggregate_intel_dashboard_stats,

    count_unread_cve_alerts,

    get_app_metadata,

    get_target_report,

    init_db,

    insert_geo_threat_event,

    insert_public_intel_snapshot,

    insert_target_report,

    list_cve_alerts,

    list_geo_threat_events,

    list_public_intel_snapshots,

    list_social_intel_items,

    list_target_reports,

    load_intel_graph_vis,

    load_zero_day_feed,

    rebuild_intel_graph,

    upsert_social_intel_item,

)

from app.cve_client import NvdError, match_cves_for_target, run_critical_cve_poll

from app.firecrawl_client import FirecrawlError, search_web

from app.pdf_report import build_intel_report_pdf

from app.target_analyzer import _extract_items, count_search_items, run_target_analysis




# Ethical advisory scope only: curated site:-restricted searches (CISA, NVD, vendors).

_ADVISORY_BASE_QUERIES: tuple[tuple[str, str], ...] = (
    ("CISA news & advisories", "site:cisa.gov news cybersecurity advisory OR alert"),
    ("CISA Known Exploited catalog", 'site:cisa.gov "known exploited vulnerabilities" catalog'),
    ("NVD CVE database", "site:nvd.nist.gov CVE vulnerability"),
    ("CERT/CC vul notes", "site:kb.cert.org vulnerability note"),
    ("Microsoft Security Response", "site:msrc.microsoft.com security advisory update"),
)



def _dev_threat_map_post_enabled() -> bool:

    flag = os.environ.get("OSINT_DEV_THREAT_MAP_POST", "")

    return flag.strip().lower() in ("1", "true", "yes")





def _sanitize_intel_focus(raw: str | None) -> str | None:

    if not raw:

        return None

    s = " ".join(raw.strip().split())

    if len(s) > 128:

        s = s[:128]

    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._\-\/\(\)]*", s):

        return None

    lowered = s.lower()

    banned = ("http://", "https://", "ftp://", "site:", ".onion", "tor:", "dark web marketplace")

    if any(b in lowered for b in banned):

        return None

    return s





def _advisory_queries_to_run(focus: str | None) -> tuple[tuple[str, str], ...]:

    extras: list[tuple[str, str]] = []

    clean = _sanitize_intel_focus(focus)

    if clean:

        escaped = clean.replace('"', "")

        extras.append((f"CISA contextual ({escaped})", f'site:cisa.gov "{escaped}" advisory OR alert'))

        if re.fullmatch(r"CVE-\d{4}-\d{4,12}", escaped, re.I):

            extras.append(("NVD specific CVE context", f"site:nvd.nist.gov {escaped.upper()}"))

    return tuple(list(_ADVISORY_BASE_QUERIES) + extras)




# Surface-web only: curated searches for zero-day / exploit discussion (no dark-web scope).



_SOCIAL_INTEL_QUERIES: tuple[tuple[str, str], ...] = (
    (
        "Zero-day & exploit news",
        "\"zero-day\" OR zeroday cybersecurity exploit vulnerability news OR blog",
    ),
    (
        "In-the-wild exploitation",
        "\"actively exploited\" OR \"in the wild\" vulnerability CVE security",
    ),
    (
        "Exploit chains & PoC discussion",
        "proof-of-concept exploit vulnerability disclosure security research",
    ),
)





def _social_published_hint(item: dict[str, Any]) -> str:
    """Best-effort date string from Firecrawl search hit metadata."""
    for key in ("publishedTime", "publishedDate", "date"):
        v = item.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()[:256]
    meta = item.get("metadata")
    if isinstance(meta, dict):
        for key in ("publishedTime", "publishedDate", "date"):
            v = meta.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()[:256]
    return ""





def _social_row_from_hit(item: dict[str, Any], source_query: str) -> tuple[str, str, str, str] | None:
    url = str(item.get("url") or item.get("link") or "").strip()
    if not url.startswith(("http://", "https://")):
        return None
    title_raw = str(item.get("title") or "Untitled").strip() or "Untitled"
    sn = item.get("description") or item.get("snippet") or item.get("markdown") or ""
    snippet = sn.strip() if isinstance(sn, str) else str(sn or "").strip()
    hint = _social_published_hint(item)
    return title_raw, url, snippet[:2000], hint





# Folder layout: backend/app/main.py and backend/templates/ sit side by side.

_BACKEND_ROOT = Path(__file__).resolve().parent.parent

_TEMPLATES_DIR = _BACKEND_ROOT / "templates"



# Load .env from osint-dashboard/ (parent of backend/)

load_dotenv(_BACKEND_ROOT.parent / ".env")



templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))





_log = logging.getLogger("uvicorn.error")

NVD_POLL_INTERVAL_SEC = 6 * 3600

_METADATA_LAST_NVD_POLL = "last_nvd_poll"





def _intel_executive_summary_text(stats: dict[str, Any]) -> str:
    """Template narrative from aggregates (deterministic prose, no LLM)."""
    h = stats["zero_day_headlines"]
    tr = stats["target_reports"]
    adv = stats["advisory_snapshots"]
    soc = stats["social_intel_items"]
    geo = stats["geo_threat_events"]
    cache = stats["cve_cached"]
    runs = stats["cve_match_runs"]
    gn = stats["graph_nodes"]
    ge = stats["graph_edges"]
    alerts = stats["cve_alerts"]
    unread = stats["cve_alerts_unread"]
    crit_unread = stats["cve_alerts_critical_unread"]
    topic = (stats.get("feed_topic") or "").strip()

    corpus = (
        "The onboard SQLite corpus currently holds "
        f"{h} curated zero-day headline entr{'ies' if h != 1 else 'y'}, "
        f"{tr} saved target intelligence report{'s' if tr != 1 else ''}, "
        f"{adv} advisory scrape snapshot batch{'es' if adv != 1 else ''}, "
        f"and {soc} surface-web social intel item{'s' if soc != 1 else ''}"
    )

    corpus += (
        "; the threat map inventory lists "
        f"{geo} geo-tagged marker{'s' if geo != 1 else ''}."
    )

    cve_side = (
        f" CVE reference data includes {cache} cached NVD record{'s' if cache != 1 else ''}"
        f" and {runs} matcher run log entr{'ies' if runs != 1 else 'y'}."
    )

    if gn or ge:
        cve_side += f" The relationship graph materialization has {gn} node{'s' if gn != 1 else ''} and {ge} edge{'s' if ge != 1 else ''}."
    else:
        cve_side += " The relationship graph is empty until you run POST /api/graph/rebuild."

    alerts_part = ""
    if alerts:
        alerts_part = (
            f" The alert queue tracks {alerts} CVE notification{'s' if alerts != 1 else ''}"
            f" ({unread} unread"
        )
        if crit_unread:
            alerts_part += f", including {crit_unread} unread Critical"
        alerts_part += ")."
    else:
        alerts_part = " No critical CVE alerts have been recorded from the poll loop yet."

    feed_part = ""
    if topic:
        feed_part = f' The headline feed is scoped as “{topic[:180]}{"…" if len(topic) > 180 else ""}”.'

    latest = ""
    lt = stats.get("latest_report_target")
    lc = stats.get("latest_report_created_at")
    if lt and lc:
        tshort = lt[:96] + ("…" if len(lt) > 96 else "")
        latest = f" Latest saved analyzer target is “{tshort}” ({lc})."
    elif not tr:
        latest = " Live Target Analyzer has not persisted any rows yet."

    return (corpus + cve_side + alerts_part + feed_part + latest).strip()





def _nvd_poll_disabled() -> bool:

    return os.environ.get("OSINT_DISABLE_NVD_POLL", "").strip().lower() in (

        "1",

        "true",

        "yes",

    )





async def _nvd_critical_poll_loop() -> None:

    while True:

        try:

            await run_critical_cve_poll()

        except Exception:  # noqa: BLE001 — log and continue background monitoring

            _log.exception("NVD critical CVE poll failed")

        await asyncio.sleep(NVD_POLL_INTERVAL_SEC)





@asynccontextmanager

async def lifespan(_app: FastAPI):

    """Initialize SQLite schema (and optional JSON seed) before handling requests."""

    init_db()

    poll_task: asyncio.Task[None] | None = None

    if not _nvd_poll_disabled():

        poll_task = asyncio.create_task(_nvd_critical_poll_loop())

    yield

    if poll_task is not None:

        poll_task.cancel()

        try:

            await poll_task

        except asyncio.CancelledError:

            pass





app = FastAPI(

    title="KM-IT-Ops OSINT Dashboard",

    description="Beginner-friendly OSINT dashboard scaffold.",

    lifespan=lifespan,

)





class AnalyzeTargetBody(BaseModel):

    target: str = Field(..., min_length=1, max_length=256)





class ScrapeAdvisoriesBody(BaseModel):

    focus: str | None = Field(default=None, max_length=128)





class ThreatMapEventBody(BaseModel):

    label: str = Field(..., min_length=1, max_length=512)

    country_code: str = Field(..., min_length=2, max_length=2)

    lat: float = Field(..., ge=-90, le=90)

    lon: float = Field(..., ge=-180, le=180)

    severity: Literal["low", "medium", "high"]

    source_ref: str = Field(default="", max_length=2048)





@app.get("/api/headlines")

async def api_headlines():

    """Return headline feed as JSON for scripts or other tools."""

    return JSONResponse(load_zero_day_feed())





@app.get("/api/intel/executive-summary")

async def api_intel_executive_summary():

    """Aggregate local intel counts plus template prose (no external LLM)."""

    stats = aggregate_intel_dashboard_stats()

    generated_at = datetime.now(timezone.utc).isoformat()

    body = {

        "generated_at": generated_at,

        "text": _intel_executive_summary_text(stats),

        "stats": stats,

    }

    return JSONResponse(body)





@app.get("/api/target-reports")

async def api_target_reports(limit: int = 10):

    """Recent Live Target Analyzer runs (newest first)."""

    limit = max(1, min(limit, 50))

    return JSONResponse({"reports": list_target_reports(limit)})





@app.get("/api/report/pdf/{report_id}")

async def api_report_pdf(report_id: int):

    """Download a PDF snapshot of a saved ``target_intelligence_reports`` row."""

    if report_id < 1:

        raise HTTPException(status_code=400, detail="Invalid report id")

    row = get_target_report(report_id)

    if row is None:

        raise HTTPException(status_code=404, detail="Report not found")

    pdf_bytes = build_intel_report_pdf(row)

    filename = f"intel-report-{report_id}.pdf"

    return StreamingResponse(

        iter([pdf_bytes]),

        media_type="application/pdf",

        headers={"Content-Disposition": f'attachment; filename="{filename}"'},

    )





@app.post("/api/intel/scrape-advisories")

async def api_intel_scrape_advisories(body: ScrapeAdvisoriesBody = ScrapeAdvisoriesBody()):

    """

    Search public advisory sources via Firecrawl (whitelisted queries only).

    Optional JSON body: `focus` narrows contextual queries safely.

    """

    plan = _advisory_queries_to_run(body.focus)

    saved: list[dict[str, object]] = []

    try:

        for label, query_used in plan:

            api_body = await search_web(query_used, limit=8)

            row_id = insert_public_intel_snapshot(

                label,

                query_used,

                api_body,

                source_family="advisory",

            )

            saved.append(

                {

                    "id": row_id,

                    "query_label": label,

                    "query_used": query_used,

                    "source_family": "advisory",

                    "result_count": count_search_items(api_body),

                }

            )

    except FirecrawlError as e:

        raise HTTPException(status_code=e.status_code or 502, detail=str(e)) from e

    return JSONResponse({"snapshots": saved, "count": len(saved)})





@app.get("/api/intel/snapshots")

async def api_intel_snapshots(limit: int = 10):

    """Recent persisted advisory scrape batches."""

    lim = max(1, min(limit, 50))

    return JSONResponse({"snapshots": list_public_intel_snapshots(lim)})





@app.post("/api/intel/refresh-social-feed")

async def api_intel_refresh_social_feed():

    """

    Firecrawl multi-query surface-web search for zero-day/exploit chatter; upsert rows by ``url``.

    """

    queries_run = 0

    items_upserted = 0

    try:

        for _, query_used in _SOCIAL_INTEL_QUERIES:

            api_body = await search_web(query_used, limit=10)

            queries_run += 1

            for hit in _extract_items(api_body):

                row = _social_row_from_hit(hit, query_used)

                if row is None:

                    continue

                title, url, snippet, hint = row

                upsert_social_intel_item(

                    title,

                    url,

                    query_used,

                    snippet=snippet,

                    published_hint=hint,

                )

                items_upserted += 1

    except FirecrawlError as e:

        raise HTTPException(status_code=e.status_code or 502, detail=str(e)) from e

    except ValueError as e:

        raise HTTPException(status_code=400, detail=str(e)) from e

    return JSONResponse(

        {"ok": True, "queries_run": queries_run, "items_upserted": items_upserted}

    )





@app.get("/api/intel/social-feed")

async def api_intel_social_feed(limit: int = 25):

    """Latest ingested surface-web intel items (newest ``created_at`` first)."""

    lim = max(1, min(limit, 100))

    return JSONResponse({"items": list_social_intel_items(lim)})





@app.get("/api/threat-map/events")

async def api_threat_map_events(limit: int = 25):

    """Geo-tagged threat markers as a GeoJSON FeatureCollection (newest first)."""

    lim = max(1, min(limit, 100))

    return JSONResponse(list_geo_threat_events(lim))





@app.post("/api/threat-map/events")

async def api_threat_map_events_create(body: ThreatMapEventBody):

    """

    Dev-only: insert a test map event. Disabled unless env `OSINT_DEV_THREAT_MAP_POST`

    is set to 1/true/yes.

    """

    if not _dev_threat_map_post_enabled():

        raise HTTPException(

            status_code=403,

            detail="POST disabled. Set OSINT_DEV_THREAT_MAP_POST=1 for local test inserts.",

        )

    try:

        new_id = insert_geo_threat_event(

            body.label,

            body.country_code,

            body.lat,

            body.lon,

            body.severity,

            body.source_ref,

        )

    except ValueError as e:

        raise HTTPException(status_code=400, detail=str(e)) from e

    return JSONResponse({"ok": True, "id": new_id})





@app.post("/api/analyze-target")

async def api_analyze_target(body: AnalyzeTargetBody):

    """Search the web via Firecrawl, normalize a report, save to SQLite."""

    try:

        _canonical, kind, query_used, report = await run_target_analysis(body.target)

        rid = insert_target_report(

            body.target.strip()[:256],

            kind,

            query_used,

            report,

        )

        row = get_target_report(rid)

        if row is None:

            raise HTTPException(status_code=500, detail="Failed to read saved report")

        return JSONResponse(row)

    except FirecrawlError as e:

        raise HTTPException(status_code=e.status_code or 502, detail=str(e)) from e





@app.get("/api/cve/match")

async def api_cve_match(target: str = ""):

    """

    Match ``target`` against NVD: extract ``CVE-YYYY-NNNN`` ids or keyword-search.

    Caches CVE JSON in SQLite; records a row in ``cve_match_runs``.

    """

    try:

        payload = await match_cves_for_target(target)

        return JSONResponse(payload)

    except NvdError as e:

        raise HTTPException(status_code=e.status_code or 502, detail=str(e)) from e





@app.get("/api/alerts")

async def api_alerts(limit: int = 50):

    """

    Critical CVE notification queue: rows from background NVD polling, newest first.

    ``unread_count`` counts rows with no ``acknowledged_at``.

    """

    lim = max(1, min(limit, 200))

    return JSONResponse(

        {

            "alerts": list_cve_alerts(lim),

            "unread_count": count_unread_cve_alerts(),

            "last_nvd_poll": get_app_metadata(_METADATA_LAST_NVD_POLL),

        }

    )





@app.post("/api/alerts/{alert_id}/ack")

async def api_alerts_ack(alert_id: int):

    """Mark one alert as read (sets ``acknowledged_at``)."""

    if alert_id < 1:

        raise HTTPException(status_code=400, detail="Invalid alert id")

    if not acknowledge_cve_alert(alert_id):

        raise HTTPException(status_code=404, detail="Alert not found or already acknowledged")

    return JSONResponse(

        {

            "ok": True,

            "id": alert_id,

            "unread_count": count_unread_cve_alerts(),

        }

    )





@app.get("/api/graph")

async def api_graph():

    """Relationship graph derived from analyzer reports — vis-network JSON shape."""

    return JSONResponse(load_intel_graph_vis())





@app.post("/api/graph/rebuild")

async def api_graph_rebuild():

    """Truncate ``graph_*`` and repopulate from ``target_intelligence_reports`` (+ CVE labels from cache)."""

    stats = rebuild_intel_graph()

    return JSONResponse(stats)





@app.get("/")

async def home(request: Request):

    """Serve the dashboard homepage with the zero-day headlines widget."""

    feed = load_zero_day_feed()

    return templates.TemplateResponse(

        request=request,

        name="index.html",

        context={

            "feed_topic": feed.get("topic", "Headlines"),

            "feed_updated": feed.get("updated_at", ""),

            "feed_note": feed.get("source_note", ""),

            "headlines": feed.get("headlines", []),

            "recent_reports": list_target_reports(8),

            "intel_snapshots": list_public_intel_snapshots(8),

            "social_intel_items": list_social_intel_items(15),

        },

    )


