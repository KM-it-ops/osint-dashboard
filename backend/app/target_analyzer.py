"""

Live Target Analyzer: classify domain vs CVE, search via Firecrawl, normalize a report payload.

"""



from __future__ import annotations



import re

from typing import Any, Literal



from app.firecrawl_client import FirecrawlError, search_web



TargetKind = Literal["domain", "cve", "other"]



# CVE-YYYY-NNNN+

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Rough hostname: labels + TLD

_DOMAIN_RE = re.compile(

    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",

    re.IGNORECASE,

)





def classify_target(raw: str) -> tuple[str, TargetKind]:

    """

    Normalize input and infer type.

    Returns (canonical_target, kind).

    """

    s = " ".join(raw.strip().split())

    if not s:

        return "", "other"



    if len(s) > 256:

        s = s[:256]



    m = _CVE_RE.search(s)

    if m:

        return m.group(0).upper(), "cve"



    first = s.split()[0]

    candidate = first.lower()

    if _DOMAIN_RE.match(candidate):

        return candidate, "domain"



    if " " not in s and "." in s and len(s) < 200:

        lowered = s.lower()

        if _DOMAIN_RE.match(lowered):

            return lowered, "domain"



    return s, "other"





def build_search_query(canonical: str, kind: TargetKind) -> str:

    """Single high-signal query for OSINT-style web search."""

    if kind == "cve":

        return f"{canonical} vulnerability CVSS NVD security advisory"

    if kind == "domain":

        return f"{canonical} threat intelligence malware phishing reputation security"

    return f"{canonical} cybersecurity OSINT threat"





def _extract_items(api_body: dict[str, Any]) -> list[dict[str, Any]]:

    """Normalize Firecrawl /v1/search response shapes."""

    data = api_body.get("data")

    if isinstance(data, list):

        return [x for x in data if isinstance(x, dict)]

    if isinstance(data, dict):

        for key in ("web", "results", "items"):

            inner = data.get(key)

            if isinstance(inner, list):

                return [x for x in inner if isinstance(x, dict)]

    return []





def count_search_items(api_body: dict[str, Any]) -> int:

    """How many normalized web items are in a Firecrawl /v1/search body."""

    return len(_extract_items(api_body))





def normalize_search_results(api_body: dict[str, Any]) -> dict[str, Any]:

    """Build structured report: summary, key_findings, sources."""

    items = _extract_items(api_body)

    sources: list[dict[str, str]] = []

    for item in items[:20]:

        url = str(item.get("url") or item.get("link") or "").strip()

        title = str(item.get("title") or "Untitled").strip() or "Untitled"

        snippet = item.get("description") or item.get("snippet") or item.get("markdown") or ""

        if isinstance(snippet, str):

            snippet = snippet.strip()

        else:

            snippet = str(snippet) if snippet is not None else ""

        if len(snippet) > 600:

            snippet = snippet[:597] + "..."

        sources.append({"title": title, "url": url, "snippet": snippet})



    key_findings = [s["title"] for s in sources[:8] if s.get("title")]



    if sources:

        first_snips = [s["snippet"] for s in sources[:3] if s.get("snippet")]

        summary = (

            "Open-web snapshot for this target (Firecrawl search). "

            + (" ".join(first_snips)[:900])

        )

    else:

        summary = (

            "No web results were returned. The query may be too narrow, the API quota "

            "may be exhausted, or try rephrasing the target."

        )



    return {

        "summary": summary[:2000],

        "key_findings": key_findings,

        "sources": sources,

    }





async def run_target_analysis(user_input: str) -> tuple[str, TargetKind, str, dict[str, Any]]:

    """

    Run one search, return (canonical_target, kind, query_used, report_dict).

    Raises FirecrawlError on API/config errors.

    """

    canonical, kind = classify_target(user_input)

    if not canonical:

        raise FirecrawlError("Enter a domain, CVE ID, or search phrase.", status_code=400)



    query_used = build_search_query(canonical, kind)

    api_response = await search_web(query_used, limit=10)

    report = normalize_search_results(api_response)

    report["target_normalized"] = canonical

    report["target_kind"] = kind

    return canonical, kind, query_used, report


