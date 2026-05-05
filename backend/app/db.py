"""
SQLite persistence: zero-day headline feed, target reports, advisory snapshots, social intel feed,
geo threat map, CVE cache, intel relationship graph (`graph_*`), app metadata (NVD poll watermark),
and critical CVE alerts.

Database file: ``osint.db`` inside ``DATA_PATH`` (Railway / persistent volume) when set, otherwise
``backend/data/osint.db`` (created on first run; parent directory is created if missing).

Headlines: legacy JSON seed via `replace_feed` when the DB is empty.
Geo markers: demo rows inserted only when `geo_threat_events` is empty after migration.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from pathlib import Path
from typing import Any, Literal

from app.target_analyzer import count_search_items

SeverityLevel = Literal["low", "medium", "high"]

_BACKEND_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_DATA_DIR = _BACKEND_ROOT / "data"


def _database_file_path() -> Path:
    """Resolve path to ``osint.db`` using ``DATA_PATH`` when set (e.g. Railway volume), else local ``data/``."""
    raw = os.environ.get("DATA_PATH", "").strip()
    if raw:
        return Path(raw).expanduser().resolve() / "osint.db"
    return _DEFAULT_DATA_DIR / "osint.db"


DB_PATH = _database_file_path()
_LEGACY_JSON = _DEFAULT_DATA_DIR / "zero_day_headlines.json"

# Demo geo events seeded only when `geo_threat_events` is empty after migration.
_DEMO_GEO_THREAT_SEED: tuple[tuple[str, str, float, float, str, str], ...] = (
    ("Ransomware activity cluster — North America", "US", 39.0, -98.35, "high", "demo_seed:regional_intel"),
    ("Phishing uplift — Western Europe", "GB", 51.5074, -0.1278, "medium", "demo_seed:regional_intel"),
    ("SOC notice — Baltic region probes", "DE", 52.52, 13.405, "low", "demo_seed:regional_intel"),
    ("APAC credential-stuffing wave", "JP", 35.6762, 139.6503, "medium", "demo_seed:regional_intel"),
    ("Southern hemisphere scan noise", "AU", -33.8688, 151.2093, "low", "demo_seed:regional_intel"),
)


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


# Graph rebuild: IPs, hostnames, CVE ids (aligned with CVE JSON 2.0 id length).
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_DOMAIN_TOKEN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b",
    re.IGNORECASE,
)
_CVE_GRAPH_RE = re.compile(r"CVE-\d{4}-\d{4,12}", re.IGNORECASE)


def init_db() -> None:
    """Create tables if missing; seed from legacy JSON once when the headline table is empty."""
    conn = _connect()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS feed_metadata (
              id INTEGER PRIMARY KEY CHECK (id = 1),
              topic TEXT NOT NULL,
              source_note TEXT NOT NULL DEFAULT '',
              updated_at TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS zero_day_headlines (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              title TEXT NOT NULL,
              url TEXT NOT NULL UNIQUE,
              sort_order INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_zero_day_headlines_sort
              ON zero_day_headlines(sort_order);

            CREATE TABLE IF NOT EXISTS target_intelligence_reports (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              target_raw TEXT NOT NULL,
              target_type TEXT NOT NULL CHECK (target_type IN ('domain', 'cve', 'other')),
              query_used TEXT NOT NULL DEFAULT '',
              report_json TEXT NOT NULL,
              created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_target_reports_created
              ON target_intelligence_reports(created_at DESC);

            CREATE INDEX IF NOT EXISTS idx_target_reports_target
              ON target_intelligence_reports(target_raw);

            CREATE TABLE IF NOT EXISTS public_intel_snapshots (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              query_label TEXT NOT NULL,
              query_used TEXT NOT NULL,
              results_json TEXT NOT NULL,
              source_family TEXT NOT NULL DEFAULT 'advisory',
              created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_public_intel_created
              ON public_intel_snapshots(created_at DESC);

            CREATE TABLE IF NOT EXISTS geo_threat_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              label TEXT NOT NULL,
              country_code TEXT NOT NULL,
              lat REAL NOT NULL,
              lon REAL NOT NULL,
              severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high')),
              source_ref TEXT NOT NULL DEFAULT '',
              created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_geo_threat_created
              ON geo_threat_events(created_at DESC);

            CREATE TABLE IF NOT EXISTS cve_cache (
              cve_id TEXT PRIMARY KEY,
              payload_json TEXT NOT NULL,
              fetched_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS cve_match_runs (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              target_raw TEXT NOT NULL,
              matched_cve_ids_json TEXT NOT NULL,
              created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_cve_match_runs_created
              ON cve_match_runs(created_at DESC);

            CREATE TABLE IF NOT EXISTS social_intel_items (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              title TEXT NOT NULL,
              url TEXT NOT NULL UNIQUE,
              source_query TEXT NOT NULL,
              snippet TEXT NOT NULL DEFAULT '',
              published_hint TEXT NOT NULL DEFAULT '',
              created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_social_intel_created
              ON social_intel_items(created_at DESC);

            CREATE TABLE IF NOT EXISTS graph_nodes (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              kind TEXT NOT NULL CHECK (kind IN ('ip', 'domain', 'cve', 'report')),
              label TEXT NOT NULL,
              ref_id INTEGER
            );

            CREATE INDEX IF NOT EXISTS idx_graph_nodes_kind ON graph_nodes(kind);

            CREATE TABLE IF NOT EXISTS graph_edges (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              src_id INTEGER NOT NULL,
              dst_id INTEGER NOT NULL,
              relation TEXT NOT NULL,
              FOREIGN KEY (src_id) REFERENCES graph_nodes(id) ON DELETE CASCADE,
              FOREIGN KEY (dst_id) REFERENCES graph_nodes(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_graph_edges_src ON graph_edges(src_id);
            CREATE INDEX IF NOT EXISTS idx_graph_edges_dst ON graph_edges(dst_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_graph_edges_unique
              ON graph_edges(src_id, dst_id, relation);

            CREATE TABLE IF NOT EXISTS app_metadata (
              key TEXT PRIMARY KEY,
              value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS cve_alerts (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              cve_id TEXT NOT NULL UNIQUE,
              severity TEXT NOT NULL,
              title TEXT NOT NULL DEFAULT '',
              summary TEXT NOT NULL DEFAULT '',
              detected_at TEXT NOT NULL DEFAULT (datetime('now')),
              acknowledged_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_cve_alerts_detected
              ON cve_alerts(detected_at DESC);

            CREATE INDEX IF NOT EXISTS idx_cve_alerts_critical_unread
              ON cve_alerts(severity)
              WHERE severity = 'CRITICAL' AND acknowledged_at IS NULL;
            """
        )
        conn.commit()

        geo_count = conn.execute("SELECT COUNT(*) AS c FROM geo_threat_events").fetchone()[0]
        if geo_count == 0:
            for label, cc, lat, lon, severity, src in _DEMO_GEO_THREAT_SEED:
                conn.execute(
                    """
                    INSERT INTO geo_threat_events (label, country_code, lat, lon, severity, source_ref)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (label, cc.upper(), lat, lon, severity, src),
                )
            conn.commit()

        count = conn.execute("SELECT COUNT(*) AS c FROM zero_day_headlines").fetchone()[0]
        if count == 0 and _LEGACY_JSON.is_file():
            with open(_LEGACY_JSON, encoding="utf-8") as f:
                data = json.load(f)
            replace_feed(conn, data)
    finally:
        conn.close()


def replace_feed(conn: sqlite3.Connection, data: dict[str, Any]) -> None:
    """Replace all headlines and metadata with the given payload (same shape as legacy JSON)."""
    topic = data.get("topic", "Recent cybersecurity zero-day vulnerabilities")
    source_note = data.get("source_note", "")
    updated_at = data.get("updated_at", "")
    headlines = data.get("headlines", [])

    conn.execute("DELETE FROM zero_day_headlines")
    conn.execute("DELETE FROM feed_metadata")
    conn.execute(
        """
        INSERT INTO feed_metadata (id, topic, source_note, updated_at)
        VALUES (1, ?, ?, ?)
        """,
        (topic, source_note, updated_at),
    )
    for index, item in enumerate(headlines):
        conn.execute(
            """
            INSERT INTO zero_day_headlines (title, url, sort_order)
            VALUES (?, ?, ?)
            """,
            (item["title"], item["url"], index),
        )
    conn.commit()


def load_zero_day_feed() -> dict[str, Any]:
    """Return headline feed for templates and /api/headlines."""
    conn = _connect()
    try:
        meta = conn.execute(
            "SELECT topic, source_note, updated_at FROM feed_metadata WHERE id = 1"
        ).fetchone()
        if meta is None:
            return {
                "topic": "Recent cybersecurity zero-day vulnerabilities",
                "updated_at": "",
                "headlines": [],
                "source_note": "No rows in feed_metadata. Run init_db() or import JSON.",
            }

        rows = conn.execute(
            """
            SELECT title, url
            FROM zero_day_headlines
            ORDER BY sort_order ASC, id ASC
            """
        ).fetchall()
        return {
            "topic": meta["topic"],
            "source_note": meta["source_note"],
            "updated_at": meta["updated_at"],
            "headlines": [{"title": r["title"], "url": r["url"]} for r in rows],
        }
    finally:
        conn.close()


def insert_target_report(
    target_raw: str,
    target_type: str,
    query_used: str,
    report: dict[str, Any],
) -> int:
    """Store a Live Target Analyzer result; returns new row id."""
    conn = _connect()
    try:
        cur = conn.execute(
            """
            INSERT INTO target_intelligence_reports (target_raw, target_type, query_used, report_json)
            VALUES (?, ?, ?, ?)
            """,
            (target_raw, target_type, query_used, json.dumps(report, ensure_ascii=False)),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def list_target_reports(limit: int = 10) -> list[dict[str, Any]]:
    """Recent intelligence reports, newest first."""
    limit = max(1, min(limit, 50))
    conn = _connect()
    try:
        rows = conn.execute(
            """
            SELECT id, target_raw, target_type, query_used, report_json, created_at
            FROM target_intelligence_reports
            ORDER BY datetime(created_at) DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [_row_to_report_dict(r) for r in rows]
    finally:
        conn.close()


def get_target_report(report_id: int) -> dict[str, Any] | None:
    """Single report by id, or None."""
    conn = _connect()
    try:
        row = conn.execute(
            """
            SELECT id, target_raw, target_type, query_used, report_json, created_at
            FROM target_intelligence_reports
            WHERE id = ?
            """,
            (report_id,),
        ).fetchone()
        if row is None:
            return None
        return _row_to_report_dict(row)
    finally:
        conn.close()


def insert_public_intel_snapshot(
    query_label: str,
    query_used: str,
    results: dict[str, Any],
    *,
    source_family: str = "advisory",
) -> int:
    """Persist one Firecrawl (or normalized) advisory search batch; returns new row id."""
    conn = _connect()
    try:
        cur = conn.execute(
            """
            INSERT INTO public_intel_snapshots (query_label, query_used, results_json, source_family)
            VALUES (?, ?, ?, ?)
            """,
            (
                query_label,
                query_used,
                json.dumps(results, ensure_ascii=False),
                source_family or "advisory",
            ),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def list_public_intel_snapshots(limit: int = 10, *, include_results: bool = False) -> list[dict[str, Any]]:
    """Recent advisory intel snapshots, newest first. Omits raw Firecrawl JSON unless include_results."""
    limit = max(1, min(limit, 50))
    conn = _connect()
    try:
        rows = conn.execute(
            """
            SELECT id, query_label, query_used, source_family, created_at, results_json
            FROM public_intel_snapshots
            ORDER BY datetime(created_at) DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            payload = json.loads(r["results_json"])
            d: dict[str, Any] = {
                "id": r["id"],
                "query_label": r["query_label"],
                "query_used": r["query_used"],
                "source_family": r["source_family"],
                "created_at": r["created_at"],
                "result_count": count_search_items(payload if isinstance(payload, dict) else {}),
            }
            if include_results:
                d["results"] = payload
            out.append(d)
        return out
    finally:
        conn.close()


def _row_to_report_dict(row: sqlite3.Row) -> dict[str, Any]:
    payload = json.loads(row["report_json"])
    return {
        "id": row["id"],
        "target_raw": row["target_raw"],
        "target_type": row["target_type"],
        "query_used": row["query_used"],
        "created_at": row["created_at"],
        "report": payload,
    }


def _geo_event_row_to_feature(row: sqlite3.Row) -> dict[str, Any]:
    lon, lat = float(row["lon"]), float(row["lat"])
    return {
        "type": "Feature",
        "geometry": {"type": "Point", "coordinates": [lon, lat]},
        "properties": {
            "id": row["id"],
            "label": row["label"],
            "country_code": row["country_code"],
            "severity": row["severity"],
            "source_ref": row["source_ref"] or "",
            "created_at": row["created_at"],
        },
    }


def list_geo_threat_events(limit: int = 25) -> dict[str, Any]:
    """Recent geo-tagged threat markers, newest first, as a GeoJSON FeatureCollection."""
    limit = max(1, min(limit, 100))
    conn = _connect()
    try:
        rows = conn.execute(
            """
            SELECT id, label, country_code, lat, lon, severity, source_ref, created_at
            FROM geo_threat_events
            ORDER BY datetime(created_at) DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return {
            "type": "FeatureCollection",
            "features": [_geo_event_row_to_feature(r) for r in rows],
        }
    finally:
        conn.close()


def get_cve_cached_payload(cve_id: str) -> dict[str, Any] | None:
    """Return parsed NVD-style JSON from ``cve_cache``, or None if missing."""
    cid = cve_id.strip().upper()
    if not cid:
        return None
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT payload_json FROM cve_cache WHERE cve_id = ?",
            (cid,),
        ).fetchone()
        if row is None:
            return None
        return json.loads(row["payload_json"])
    finally:
        conn.close()


def upsert_cve_cache(cve_id: str, payload: dict[str, Any]) -> None:
    """Store or replace a CVE JSON payload from NVD."""
    cid = cve_id.strip().upper()
    blob = json.dumps(payload, ensure_ascii=False)
    conn = _connect()
    try:
        conn.execute(
            """
            INSERT INTO cve_cache (cve_id, payload_json, fetched_at)
            VALUES (?, ?, datetime('now'))
            ON CONFLICT(cve_id) DO UPDATE SET
              payload_json = excluded.payload_json,
              fetched_at = excluded.fetched_at
            """,
            (cid, blob),
        )
        conn.commit()
    finally:
        conn.close()


def insert_cve_match_run(target_raw: str, matched_cve_ids: list[str]) -> int:
    """Record one matcher invocation; returns new row id."""
    conn = _connect()
    try:
        cur = conn.execute(
            """
            INSERT INTO cve_match_runs (target_raw, matched_cve_ids_json)
            VALUES (?, ?)
            """,
            (target_raw.strip()[:512], json.dumps(matched_cve_ids, ensure_ascii=False)),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def upsert_social_intel_item(
    title: str,
    url: str,
    source_query: str,
    *,
    snippet: str = "",
    published_hint: str = "",
) -> None:
    """Insert or update a surface-web intel row; unique ``url``. Preserves ``created_at`` on conflict."""
    u = url.strip()
    if not u or not u.startswith(("http://", "https://")):
        raise ValueError("url must be an http(s) URL.")
    t = (title or "").strip() or "Untitled"
    if len(t) > 2048:
        t = t[:2045] + "..."
    q = (source_query or "").strip()[:512]
    sn = snippet.strip()[:2000] if snippet else ""
    ph = published_hint.strip()[:256]

    conn = _connect()
    try:
        conn.execute(
            """
            INSERT INTO social_intel_items (title, url, source_query, snippet, published_hint)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(url) DO UPDATE SET
              title = excluded.title,
              source_query = excluded.source_query,
              snippet = excluded.snippet,
              published_hint = excluded.published_hint
            """,
            (t, u, q, sn, ph),
        )
        conn.commit()
    finally:
        conn.close()


def list_social_intel_items(limit: int = 20) -> list[dict[str, Any]]:
    """Recent social-intel links, newest first by ingestion ``created_at``."""
    limit = max(1, min(limit, 100))
    conn = _connect()
    try:
        rows = conn.execute(
            """
            SELECT id, title, url, source_query, snippet, published_hint, created_at
            FROM social_intel_items
            ORDER BY datetime(created_at) DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [
            {
                "id": r["id"],
                "title": r["title"],
                "url": r["url"],
                "source_query": r["source_query"],
                "snippet": r["snippet"] or "",
                "published_hint": r["published_hint"] or "",
                "created_at": r["created_at"],
            }
            for r in rows
        ]
    finally:
        conn.close()


def find_reports_with_cves(cve_ids: list[str], *, limit: int = 8) -> list[dict[str, Any]]:
    """Recent target reports whose stored JSON or target string mentions any of the CVE ids."""
    if not cve_ids:
        return []
    lim = max(1, min(limit, 50))
    conn = _connect()
    try:
        clauses: list[str] = []
        params: list[Any] = []
        for cid in cve_ids:
            c = cid.strip().upper()
            if not c:
                continue
            like = f"%{c}%"
            clauses.append("(report_json LIKE ? OR target_raw LIKE ?)")
            params.extend([like, like])
        if not clauses:
            return []
        where_sql = " OR ".join(clauses)
        rows = conn.execute(
            f"""
            SELECT id, target_raw, target_type, created_at
            FROM target_intelligence_reports
            WHERE {where_sql}
            ORDER BY datetime(created_at) DESC, id DESC
            LIMIT ?
            """,
            (*params, lim),
        ).fetchall()
        return [
            {
                "id": r["id"],
                "target_raw": r["target_raw"],
                "target_type": r["target_type"],
                "created_at": r["created_at"],
            }
            for r in rows
        ]
    finally:
        conn.close()


def insert_geo_threat_event(
    label: str,
    country_code: str,
    lat: float,
    lon: float,
    severity: SeverityLevel,
    source_ref: str = "",
) -> int:
    """Insert one map marker; validates ISO-3166-1 alpha-2 and coordinates. Returns new row id."""
    cc = country_code.strip().upper()
    if not re.fullmatch(r"[A-Z]{2}", cc):
        raise ValueError("country_code must be ISO-3166-1 alpha-2 (e.g. US, DE).")
    if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
        raise ValueError("lat/lon out of range.")
    if severity not in ("low", "medium", "high"):
        raise ValueError("severity must be low, medium, or high.")
    lab = label.strip()
    if not lab or len(lab) > 512:
        raise ValueError("label must be 1–512 characters.")
    ref = (source_ref or "").strip()[:2048]

    conn = _connect()
    try:
        cur = conn.execute(
            """
            INSERT INTO geo_threat_events (label, country_code, lat, lon, severity, source_ref)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (lab, cc, lat, lon, severity, ref),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def _cve_graph_label(conn: sqlite3.Connection, cve_id: str) -> str:
    """Short UI label using NVD cached description when present."""
    cid = (cve_id or "").strip().upper()
    if not cid:
        return cve_id
    row = conn.execute(
        "SELECT payload_json FROM cve_cache WHERE cve_id = ?",
        (cid,),
    ).fetchone()
    if row is None:
        return cid
    try:
        data = json.loads(row["payload_json"])
        vulns = data.get("vulnerabilities")
        if not isinstance(vulns, list) or not vulns:
            return cid
        first = vulns[0]
        if not isinstance(first, dict):
            return cid
        cve = first.get("cve")
        if not isinstance(cve, dict):
            return cid
        for d in cve.get("descriptions") or []:
            if isinstance(d, dict) and d.get("lang") == "en":
                txt = str(d.get("value") or "").strip()
                if txt:
                    tail = txt[:96] + ("…" if len(txt) > 96 else "")
                    return f"{cid} — {tail}"
    except (json.JSONDecodeError, TypeError, KeyError):
        pass
    return cid


def _report_search_blob(target_raw: str, report_json: str) -> str:
    """Flatten report fields + JSON for CVE / hostname / IPv4 extraction."""
    parts: list[str] = [target_raw or ""]
    try:
        rep = json.loads(report_json)
    except json.JSONDecodeError:
        return " ".join(parts)
    if not isinstance(rep, dict):
        return " ".join(parts) + " " + (report_json or "")
    parts.append(str(rep.get("summary") or ""))
    for kf in rep.get("key_findings") or []:
        parts.append(str(kf))
    for s in rep.get("sources") or []:
        if isinstance(s, dict):
            parts.append(str(s.get("url") or ""))
            parts.append(str(s.get("title") or ""))
            parts.append(str(s.get("snippet") or ""))
        else:
            parts.append(str(s))
    parts.append(report_json)
    return " ".join(parts)


def _extract_ipv4s(text: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for m in _IPV4_RE.finditer(text or ""):
        ip = m.group(0)
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def _extract_domains(text: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for m in _DOMAIN_TOKEN_RE.finditer(text or ""):
        raw = m.group(0).strip().lower().rstrip(".")
        lead = raw.split(".", 1)[0]
        if lead.isdigit():
            continue
        if raw in ("localhost",):
            continue
        if raw.startswith("cve-"):
            continue
        if len(raw) < 5:
            continue
        if raw in seen:
            continue
        seen.add(raw)
        out.append(raw)
    return out


def _extract_cves(text: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for m in _CVE_GRAPH_RE.finditer(text or ""):
        cid = m.group(0).upper()
        if cid not in seen:
            seen.add(cid)
            out.append(cid)
    return out


GraphKind = Literal["ip", "domain", "cve", "report"]


def rebuild_intel_graph() -> dict[str, Any]:
    """Derive ``graph_*`` from analyzer reports; enrich CVE labels from ``cve_cache``."""
    conn = _connect()
    nodes_map: dict[tuple[str, str], int] = {}

    def ensure_node(kind: GraphKind, label: str, *, dedup: str | None = None, ref_id: int | None = None) -> int:
        key = dedup if dedup is not None else label.strip().lower()
        tkey: tuple[str, str] = (kind, key)
        if tkey in nodes_map:
            return nodes_map[tkey]
        cur = conn.execute(
            """
            INSERT INTO graph_nodes (kind, label, ref_id)
            VALUES (?, ?, ?)
            """,
            (kind, (label or "")[:512], ref_id),
        )
        nid = int(cur.lastrowid)
        nodes_map[tkey] = nid
        return nid

    def add_edge(src: int, dst: int, relation: str) -> None:
        conn.execute(
            """
            INSERT OR IGNORE INTO graph_edges (src_id, dst_id, relation)
            VALUES (?, ?, ?)
            """,
            (src, dst, (relation or "related").strip()[:128]),
        )

    try:
        conn.execute("DELETE FROM graph_edges")
        conn.execute("DELETE FROM graph_nodes")

        rows = conn.execute(
            """
            SELECT id, target_raw, target_type, report_json
            FROM target_intelligence_reports
            ORDER BY id ASC
            """
        ).fetchall()

        for r in rows:
            rid = int(r["id"])
            target_raw = str(r["target_raw"] or "")
            target_type = str(r["target_type"] or "other")
            report_json = str(r["report_json"] or "{}")
            blob = _report_search_blob(target_raw, report_json)

            report_node = ensure_node(
                "report",
                f"Analysis #{rid}",
                dedup=f"report:{rid}",
                ref_id=rid,
            )

            if target_type == "domain":
                dom = target_raw.strip().lower().rstrip(".")
                if dom:
                    tn = ensure_node("domain", dom, dedup=f"domain:{dom}")
                    add_edge(report_node, tn, "analysis_target")
            elif target_type == "cve":
                mc = _CVE_GRAPH_RE.search(target_raw)
                if mc:
                    cid = mc.group(0).upper()
                    lab = _cve_graph_label(conn, cid)
                    cn = ensure_node("cve", lab, dedup=f"cve:{cid}")
                    add_edge(report_node, cn, "analysis_target")

            for cid in _extract_cves(blob):
                lab = _cve_graph_label(conn, cid)
                cn = ensure_node("cve", lab, dedup=f"cve:{cid}")
                add_edge(report_node, cn, "mentions")

            for ip in _extract_ipv4s(blob):
                inn = ensure_node("ip", ip, dedup=f"ip:{ip}")
                add_edge(report_node, inn, "observed_ip")

            for dom in _extract_domains(blob):
                dn = ensure_node("domain", dom, dedup=f"domain:{dom}")
                add_edge(report_node, dn, "observed_domain")

        conn.commit()
        nodes_n = int(conn.execute("SELECT COUNT(*) AS c FROM graph_nodes").fetchone()["c"])
        edges_n = int(conn.execute("SELECT COUNT(*) AS c FROM graph_edges").fetchone()["c"])
        return {"ok": True, "nodes_written": nodes_n, "edges_written": edges_n}
    finally:
        conn.close()


def get_app_metadata(key: str) -> str | None:
    """Return stored value for ``key``, or None."""
    k = (key or "").strip()
    if not k:
        return None
    conn = _connect()
    try:
        row = conn.execute("SELECT value FROM app_metadata WHERE key = ?", (k,)).fetchone()
        return str(row["value"]) if row else None
    finally:
        conn.close()


def set_app_metadata(key: str, value: str) -> None:
    """Upsert key/value in ``app_metadata``."""
    k = (key or "").strip()
    if not k:
        raise ValueError("key is required.")
    v = value if isinstance(value, str) else str(value)
    conn = _connect()
    try:
        conn.execute(
            """
            INSERT INTO app_metadata (key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (k, v),
        )
        conn.commit()
    finally:
        conn.close()


def insert_cve_alert_if_new(
    cve_id: str,
    severity: str,
    title: str,
    summary: str,
) -> bool:
    """Insert a CVE alert row if ``cve_id`` is not already present. Returns True when inserted."""
    cid = cve_id.strip().upper()
    if not cid:
        raise ValueError("cve_id is required.")
    sev = (severity or "").strip().upper() or "UNKNOWN"
    t = (title or cid)[:512]
    s = (summary or "")[:4000]
    conn = _connect()
    try:
        try:
            conn.execute(
                """
                INSERT INTO cve_alerts (cve_id, severity, title, summary)
                VALUES (?, ?, ?, ?)
                """,
                (cid, sev, t, s),
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            conn.rollback()
            return False
    finally:
        conn.close()


def list_cve_alerts(limit: int = 50) -> list[dict[str, Any]]:
    """Recent CVE alerts, newest ``detected_at`` first."""
    limit = max(1, min(limit, 200))
    conn = _connect()
    try:
        rows = conn.execute(
            """
            SELECT id, cve_id, severity, title, summary, detected_at, acknowledged_at
            FROM cve_alerts
            ORDER BY datetime(detected_at) DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [
            {
                "id": r["id"],
                "cve_id": r["cve_id"],
                "severity": r["severity"],
                "title": r["title"] or r["cve_id"],
                "summary": r["summary"] or "",
                "detected_at": r["detected_at"],
                "acknowledged_at": r["acknowledged_at"],
                "read": r["acknowledged_at"] is not None,
            }
            for r in rows
        ]
    finally:
        conn.close()


def count_unread_cve_alerts() -> int:
    """Alerts with no ``acknowledged_at``."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT COUNT(*) AS c FROM cve_alerts WHERE acknowledged_at IS NULL"
        ).fetchone()
        return int(row["c"]) if row else 0
    finally:
        conn.close()


def acknowledge_cve_alert(alert_id: int) -> bool:
    """Set ``acknowledged_at`` on one row. Returns False if id missing."""
    if alert_id < 1:
        return False
    conn = _connect()
    try:
        cur = conn.execute(
            """
            UPDATE cve_alerts
            SET acknowledged_at = datetime('now')
            WHERE id = ? AND acknowledged_at IS NULL
            """,
            (alert_id,),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def aggregate_intel_dashboard_stats() -> dict[str, Any]:
    """Single-connection snapshot counts for executive summary (safe on empty DB)."""
    conn = _connect()
    try:
        def count_one(sql: str) -> int:
            row = conn.execute(sql).fetchone()
            return int(row[0]) if row else 0

        meta = conn.execute("SELECT topic, updated_at FROM feed_metadata WHERE id = 1").fetchone()
        feed_topic = str(meta["topic"]) if meta else ""
        feed_updated_at = str(meta["updated_at"] or "") if meta else ""

        latest = conn.execute(
            """
            SELECT target_raw, created_at
            FROM target_intelligence_reports
            ORDER BY datetime(created_at) DESC, id DESC
            LIMIT 1
            """
        ).fetchone()

        return {
            "zero_day_headlines": count_one("SELECT COUNT(*) FROM zero_day_headlines"),
            "target_reports": count_one("SELECT COUNT(*) FROM target_intelligence_reports"),
            "advisory_snapshots": count_one("SELECT COUNT(*) FROM public_intel_snapshots"),
            "geo_threat_events": count_one("SELECT COUNT(*) FROM geo_threat_events"),
            "social_intel_items": count_one("SELECT COUNT(*) FROM social_intel_items"),
            "cve_cached": count_one("SELECT COUNT(*) FROM cve_cache"),
            "cve_match_runs": count_one("SELECT COUNT(*) FROM cve_match_runs"),
            "cve_alerts": count_one("SELECT COUNT(*) FROM cve_alerts"),
            "cve_alerts_unread": count_one(
                "SELECT COUNT(*) FROM cve_alerts WHERE acknowledged_at IS NULL"
            ),
            "cve_alerts_critical_unread": count_one(
                "SELECT COUNT(*) FROM cve_alerts WHERE severity = 'CRITICAL' AND acknowledged_at IS NULL"
            ),
            "graph_nodes": count_one("SELECT COUNT(*) FROM graph_nodes"),
            "graph_edges": count_one("SELECT COUNT(*) FROM graph_edges"),
            "feed_topic": feed_topic,
            "feed_updated_at": feed_updated_at,
            "latest_report_target": str(latest["target_raw"]) if latest else None,
            "latest_report_created_at": str(latest["created_at"]) if latest else None,
        }
    finally:
        conn.close()


def load_intel_graph_vis() -> dict[str, Any]:
    """vis-network shape: ``nodes`` with numeric ``id``; ``edges`` with ``from`` / ``to``."""
    conn = _connect()
    try:
        nrows = conn.execute(
            "SELECT id, kind, label FROM graph_nodes ORDER BY id ASC"
        ).fetchall()
        erows = conn.execute(
            "SELECT src_id, dst_id, relation FROM graph_edges ORDER BY id ASC"
        ).fetchall()
    finally:
        conn.close()

    colors = {
        "report": "#22d3ee",
        "domain": "#a78bfa",
        "ip": "#fbbf24",
        "cve": "#fb7185",
    }

    nodes: list[dict[str, Any]] = []
    for r in nrows:
        kind = str(r["kind"])
        nid = int(r["id"])
        label = str(r["label"] or "")
        short = label[:61] + "…" if len(label) > 64 else label
        nodes.append(
            {
                "id": nid,
                "label": short,
                "title": label,
                "group": kind,
                "shape": "box" if kind == "report" else "dot",
                "color": {
                    "background": colors.get(kind, "#64748b"),
                    "border": "#0f172a",
                    "highlight": {"background": "#38bdf8", "border": "#e2e8f0"},
                },
                "font": {"color": "#f1f5f9", "size": 13},
                "margin": 8,
            }
        )

    edges: list[dict[str, Any]] = []
    for e in erows:
        edges.append(
            {
                "from": int(e["src_id"]),
                "to": int(e["dst_id"]),
                "label": str(e["relation"] or ""),
                "font": {"color": "#94a3b8", "size": 10, "align": "middle"},
                "color": {"color": "#475569", "highlight": "#22d3ee"},
                "smooth": {"type": "continuous"},
                "arrows": "to",
            }
        )

    return {"nodes": nodes, "edges": edges}
