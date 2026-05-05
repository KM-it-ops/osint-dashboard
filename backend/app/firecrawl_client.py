"""

HTTP client for Firecrawl's REST API (same capabilities as Firecrawl MCP search).



Set FIRECRAWL_API_KEY. Optional: FIRECRAWL_API_URL (default https://api.firecrawl.dev).

"""



from __future__ import annotations



import os

from typing import Any



import httpx



DEFAULT_BASE_URL = "https://api.firecrawl.dev"





class FirecrawlError(Exception):

    """Raised when the API key is missing or Firecrawl returns an error."""



    def __init__(self, message: str, status_code: int | None = None) -> None:

        super().__init__(message)

        self.status_code = status_code





def _api_key() -> str:

    key = os.environ.get("FIRECRAWL_API_KEY", "").strip()

    if not key:

        raise FirecrawlError(

            "FIRECRAWL_API_KEY is not set. Add it to your environment or a .env file next to requirements.txt.",

            status_code=503,

        )

    return key





def _base_url() -> str:

    return (os.environ.get("FIRECRAWL_API_URL") or DEFAULT_BASE_URL).rstrip("/")





async def search_web(query: str, *, limit: int = 8) -> dict[str, Any]:

    """

    POST /v1/search — web results with title, url, description.



    https://docs.firecrawl.dev/api-reference/v1-endpoint/search

    """

    if not query or not query.strip():

        raise FirecrawlError("Search query is empty.", status_code=400)



    limit = max(1, min(limit, 25))

    url = f"{_base_url()}/v1/search"

    # v1 /search accepts query + limit (+ optional tbs, scrapeOptions, etc.). Do not send

    # legacy "sources" — the API returns 400 "Unrecognized key: sources".

    payload: dict[str, Any] = {"query": query.strip(), "limit": limit}



    async with httpx.AsyncClient(timeout=httpx.Timeout(120.0, connect=30.0)) as client:

        response = await client.post(

            url,

            json=payload,

            headers={

                "Authorization": f"Bearer {_api_key()}",

                "Content-Type": "application/json",

            },

        )



    try:

        body = response.json()

    except Exception as exc:  # noqa: BLE001 — surface API HTML/text

        raise FirecrawlError(

            f"Firecrawl returned non-JSON ({response.status_code}).",

            status_code=response.status_code,

        ) from exc



    if response.status_code >= 400:

        err = body.get("error") if isinstance(body, dict) else None

        msg = err if isinstance(err, str) else response.text[:500]

        raise FirecrawlError(

            msg or f"Firecrawl request failed with HTTP {response.status_code}",

            status_code=response.status_code,

        )



    if isinstance(body, dict) and body.get("success") is False:

        err = body.get("error", "Firecrawl reported success=false")

        raise FirecrawlError(str(err), status_code=502)



    return body if isinstance(body, dict) else {}


