"""Intel relationship graph APIs (SQLite graph_* tables + vis JSON shape)."""

from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from app.db import init_db, insert_target_report
from app.main import app


class GraphApiTests(unittest.TestCase):
    def test_rebuild_then_get_vis_shape(self) -> None:
        init_db()
        insert_target_report(
            "evil.example.com",
            "domain",
            "unittest",
            {
                "summary": "Traffic to 192.0.2.10 and CVE-2024-1234 indicators.",
                "key_findings": ["See advisory.example.org/CVE-2024-1234 for details"],
                "sources": [{"url": "https://nist.gov/", "title": "NVD", "snippet": ""}],
            },
        )
        with TestClient(app) as client:
            rb = client.post("/api/graph/rebuild")
            self.assertEqual(rb.status_code, 200)
            body = rb.json()
            self.assertTrue(body.get("ok"))
            self.assertGreaterEqual(int(body.get("nodes_written") or 0), 1)
            self.assertGreaterEqual(int(body.get("edges_written") or 0), 1)

            rg = client.get("/api/graph")
            self.assertEqual(rg.status_code, 200)
            data = rg.json()
            self.assertIn("nodes", data)
            self.assertIn("edges", data)
            self.assertIsInstance(data["nodes"], list)
            self.assertIsInstance(data["edges"], list)
            if data["edges"]:
                e0 = data["edges"][0]
                self.assertIn("from", e0)
                self.assertIn("to", e0)
            if data["nodes"]:
                n0 = data["nodes"][0]
                self.assertIn("id", n0)
                self.assertIn("label", n0)


if __name__ == "__main__":
    unittest.main()
