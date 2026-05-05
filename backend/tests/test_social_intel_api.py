"""Social threat monitor API tests (TestClient runs lifespan / init_db)."""

from __future__ import annotations

import os
import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from app.main import app


_FAKE_FC_BODY = {
    "success": True,
    "data": [
        {
            "url": "https://example.org/security/zero-day-test",
            "title": "Discussion: zero-day remediation",
            "description": "Synthetic unittest hit for social intel feed.",
            "publishedTime": "2026-01-01",
        },
        {
            "url": "not-a-valid-url",
            "title": "Skipped",
        },
    ],
}


class SocialIntelApiTests(unittest.TestCase):
    def test_get_social_feed_returns_items_key(self) -> None:
        with TestClient(app) as client:
            resp = client.get("/api/intel/social-feed?limit=5")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn("items", body)
        self.assertIsInstance(body["items"], list)

    @patch("app.main.search_web", new_callable=AsyncMock)
    def test_refresh_then_get_contains_url(self, mock_search: AsyncMock) -> None:
        mock_search.return_value = _FAKE_FC_BODY

        with TestClient(app) as client:
            post = client.post("/api/intel/refresh-social-feed")
            self.assertEqual(post.status_code, 200)
            pst = post.json()
            self.assertTrue(pst.get("ok"))
            self.assertGreaterEqual(pst.get("queries_run", 0), 1)
            self.assertGreaterEqual(pst.get("items_upserted", 0), 1)

            resp = client.get("/api/intel/social-feed?limit=50")
            self.assertEqual(resp.status_code, 200)
            urls = {row["url"] for row in resp.json().get("items", [])}

        self.assertIn("https://example.org/security/zero-day-test", urls)
        self.assertEqual(mock_search.await_count, 3)

    def test_refresh_without_firecrawl_key(self) -> None:
        key_backup = os.environ.pop("FIRECRAWL_API_KEY", None)
        try:
            with TestClient(app) as client:
                resp = client.post("/api/intel/refresh-social-feed")
        finally:
            if key_backup is not None:
                os.environ["FIRECRAWL_API_KEY"] = key_backup

        self.assertEqual(resp.status_code, 503)


if __name__ == "__main__":
    unittest.main()
