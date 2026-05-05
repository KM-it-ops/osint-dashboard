"""

NVD CVE API 2.0 client (https://services.nvd.nist.gov/rest/json/cves/2.0).

Respects rolling rate limits (~5 requests / 30s without API key; higher with key).

Optional env: ``NVD_API_KEY`` → passed as ``apiKey`` query parameter.

"""

from __future__ import annotations

import asyncio
import os
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from app.db import (
    find_reports_with_cves,
    get_app_metadata,
    get_cve_cached_payload,
    insert_cve_alert_if_new,
    insert_cve_match_run,
    set_app_metadata,
    upsert_cve_cache,
)

NVD_CVES_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NIST guidance: ~5 requests / 30s without key; ~50 / 30s with key — use conservative gaps.
_MIN_INTERVAL_NO_KEY = 6.6
_MIN_INTERVAL_WITH_KEY = 0.66

CVE_ID_PATTERN = re.compile(r"CVE-\d{4}-\d{4,12}", re.IGNORECASE)

_rate_lock = asyncio.Lock()
_last_request_mono: float = 0.0


class NvdError(Exception):
    """Raised when NVD returns an error or the response is unusable."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def _nvd_api_key() -> str | None:
    k = os.environ.get("NVD_API_KEY", "").strip()
    return k or None


async def _throttle() -> None:
    global _last_request_mono
    interval = _MIN_INTERVAL_WITH_KEY if _nvd_api_key() else _MIN_INTERVAL_NO_KEY
    async with _rate_lock:
        now = time.monotonic()
        wait = _last_request_mono + interval - now
        if wait > 0:
            await asyncio.sleep(wait)
        _last_request_mono = time.monotonic()


def _query_params_base() -> dict[str, str]:
    q: dict[str, str] = {}
    key = _nvd_api_key()
    if key:
        q["apiKey"] = key
    return q


def extract_cve_ids(text: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for m in CVE_ID_PATTERN.finditer(text or ""):
        cid = m.group(0).upper()
        if cid not in seen:
            seen.add(cid)
            out.append(cid)
    return out


def _keyword_from_target(target: str, *, skip_cve_spans: bool) -> str | None:
    if not target or not target.strip():
        return None
    t = target.strip()
    if skip_cve_spans:
        t = CVE_ID_PATTERN.sub(" ", t)
    t = re.sub(r"\s+", " ", t).strip()
    if len(t) < 2:
        return None
    # NVD keyword search: keep printable ASCII-ish fragment
    if len(t) > 240:
        t = t[:240]
    return t


def _severity_from_cve(cve_block: dict[str, Any]) -> str | None:
    metrics = cve_block.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if not isinstance(arr, list) or not arr:
            continue
        first = arr[0]
        if not isinstance(first, dict):
            continue
        data = first.get("cvssData") or {}
        if isinstance(data, dict):
            sev = data.get("baseSeverity")
            if isinstance(sev, str) and sev.strip():
                return sev.strip().upper()
            if key == "cvssMetricV2":
                score = data.get("baseScore")
                if isinstance(score, (int, float)):
                    if score >= 7:
                        return "HIGH"
                    if score >= 4:
                        return "MEDIUM"
                    return "LOW"
    return None


def _english_description(cve_block: dict[str, Any]) -> str:
    for d in cve_block.get("descriptions") or []:
        if isinstance(d, dict) and d.get("lang") == "en" and isinstance(d.get("value"), str):
            return d["value"].strip()
    return ""


def _normalize_vulnerability_item(item: dict[str, Any], *, rank: int) -> dict[str, Any] | None:
    cve = item.get("cve")
    if not isinstance(cve, dict):
        return None
    cid = cve.get("id")
    if not isinstance(cid, str) or not cid.upper().startswith("CVE-"):
        return None
    summary = _english_description(cve)
    snippet = summary[:320] + ("…" if len(summary) > 320 else "")
    return {
        "cve_id": cid.upper(),
        "severity": _severity_from_cve(cve),
        "summary": snippet,
        "source": "nvd",
        "rank": rank,
    }


async def _http_get_nvd(params: dict[str, str]) -> dict[str, Any]:
    await _throttle()
    q = _query_params_base()
    q.update(params)
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(60.0, connect=30.0),
        headers={"Accept": "application/json"},
    ) as client:
        resp = await client.get(NVD_CVES_URL, params=q)
    try:
        body = resp.json()
    except Exception as exc:  # noqa: BLE001 — surface HTML/text failures
        raise NvdError(
            f"NVD returned non-JSON ({resp.status_code}).",
            status_code=resp.status_code,
        ) from exc
    if resp.status_code == 403:
        raise NvdError(
            "NVD returned 403 — check rate limits or NVD_API_KEY.",
            status_code=403,
        )
    if resp.status_code >= 400:
        msg = ""
        if isinstance(body, dict) and isinstance(body.get("message"), str):
            msg = body["message"]
        raise NvdError(msg or f"NVD HTTP {resp.status_code}", status_code=resp.status_code)
    return body if isinstance(body, dict) else {}


async def fetch_cve_by_id(cve_id: str) -> dict[str, Any] | None:
    """
    Return one normalized match dict from cache or NVD, or None if not found.

    Upserts ``cve_cache`` on successful fetch.
    """
    clean = cve_id.strip().upper()
    if not CVE_ID_PATTERN.fullmatch(clean):
        raise NvdError("Invalid CVE identifier.", status_code=400)

    cached = get_cve_cached_payload(clean)
    if cached is not None:
        vulns = cached.get("vulnerabilities")
        if isinstance(vulns, list) and vulns:
            norm = _normalize_vulnerability_item(vulns[0], rank=0)
            return norm

    raw = await _http_get_nvd({"cveId": clean})
    upsert_cve_cache(clean, raw)
    vulns = raw.get("vulnerabilities")
    if not isinstance(vulns, list) or not vulns:
        return None
    return _normalize_vulnerability_item(vulns[0], rank=0)


async def search_cves_by_keyword(keyword: str, *, results_per_page: int = 15) -> list[dict[str, Any]]:
    """Keyword search on NVD; results are normalized and cached per CVE row."""
    kw = keyword.strip()
    if len(kw) < 2:
        return []
    rpp = max(1, min(results_per_page, 50))
    raw = await _http_get_nvd({"keywordSearch": kw, "resultsPerPage": str(rpp)})
    vulns = raw.get("vulnerabilities")
    if not isinstance(vulns, list):
        return []
    out: list[dict[str, Any]] = []
    for i, item in enumerate(vulns):
        if not isinstance(item, dict):
            continue
        cve = item.get("cve")
        if isinstance(cve, dict) and isinstance(cve.get("id"), str):
            upsert_cve_cache(cve["id"].upper(), {"vulnerabilities": [item], "format": raw.get("format"), "version": raw.get("version")})
        norm = _normalize_vulnerability_item(item, rank=i + 1)
        if norm:
            out.append(norm)
    return out


async def match_cves_for_target(target: str) -> dict[str, Any]:
    """
    Parse CVE IDs from ``target`` or fall back to NVD keyword search.

    Returns JSON-serializable dict with ``matches``, ``related_reports``, ``match_run_id``.
    """
    raw_target = target.strip()
    if not raw_target:
        raise NvdError("target is required.", status_code=400)
    if len(raw_target) > 512:
        raise NvdError("target too long (max 512).", status_code=400)

    ids = extract_cve_ids(raw_target)
    matches: list[dict[str, Any]] = []
    if ids:
        for i, cid in enumerate(ids):
            try:
                one = await fetch_cve_by_id(cid)
            except NvdError:
                raise
            if one:
                one = {**one, "rank": i + 1}
                matches.append(one)
    else:
        kw = _keyword_from_target(raw_target, skip_cve_spans=False)
        if kw:
            matches = await search_cves_by_keyword(kw, results_per_page=15)

    matched_ids = [m["cve_id"] for m in matches if isinstance(m.get("cve_id"), str)]
    related = find_reports_with_cves(matched_ids, limit=8) if matched_ids else []

    run_id = insert_cve_match_run(raw_target, matched_ids)

    return {
        "target": raw_target,
        "parsed_cve_ids": ids,
        "matches": matches,
        "related_reports": related,
        "match_run_id": run_id,
    }


def _utc_iso_z(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


_METADATA_KEY_LAST_POLL = "last_nvd_poll"
_DEFAULT_LOOKBACK_DAYS = 7
_RESULTS_PAGE = 2000


async def run_critical_cve_poll() -> dict[str, Any]:
    """
    Fetch Critical-severity CVEs from NVD published after the stored watermark (or last 7 days if unset).

    Updates ``last_nvd_poll`` on success. Persists new rows in ``cve_alerts`` (unique ``cve_id``) and
    upserts ``cve_cache`` for each vulnerability returned.
    """
    now = datetime.now(timezone.utc)
    end_iso = _utc_iso_z(now)
    prior = get_app_metadata(_METADATA_KEY_LAST_POLL)
    if prior and prior.strip():
        start_iso = prior.strip()
    else:
        start = now - timedelta(days=_DEFAULT_LOOKBACK_DAYS)
        start_iso = _utc_iso_z(start)

    if start_iso >= end_iso:
        return {"ok": True, "inserted": 0, "pages": 0, "skipped_range": True}

    inserted = 0
    pages = 0
    start_index = 0
    total_results: int | None = None

    while True:
        raw = await _http_get_nvd(
            {
                "cvssV3Severity": "CRITICAL",
                "pubStartDate": start_iso,
                "pubEndDate": end_iso,
                "resultsPerPage": str(_RESULTS_PAGE),
                "startIndex": str(start_index),
            }
        )
        pages += 1
        tr = raw.get("totalResults")
        if isinstance(tr, int):
            total_results = tr
        vulns = raw.get("vulnerabilities")
        if not isinstance(vulns, list) or not vulns:
            break

        for item in vulns:
            if not isinstance(item, dict):
                continue
            cve = item.get("cve")
            if not isinstance(cve, dict):
                continue
            cid_raw = cve.get("id")
            if not isinstance(cid_raw, str):
                continue
            cid = cid_raw.strip().upper()
            sev = _severity_from_cve(cve)
            if sev != "CRITICAL":
                continue
            summary_full = _english_description(cve)
            snippet = summary_full[:400] + ("…" if len(summary_full) > 400 else "")
            title = f"{cid} — Critical"
            upsert_cve_cache(
                cid,
                {"vulnerabilities": [item], "format": raw.get("format"), "version": raw.get("version")},
            )
            if insert_cve_alert_if_new(cid, sev or "CRITICAL", title, snippet):
                inserted += 1

        n = len(vulns)
        start_index += n
        if n < _RESULTS_PAGE:
            break
        if isinstance(total_results, int) and start_index >= total_results:
            break

    set_app_metadata(_METADATA_KEY_LAST_POLL, end_iso)
    return {
        "ok": True,
        "inserted": inserted,
        "pages": pages,
        "total_results": total_results if total_results is not None else start_index,
        "pub_start": start_iso,
        "pub_end": end_iso,
    }
