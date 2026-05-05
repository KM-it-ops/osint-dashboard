"""Executive summary aggregates endpoint."""

from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from app.main import app


class ExecutiveSummaryApiTests(unittest.TestCase):
    def test_get_returns_shape_and_200(self) -> None:
        with TestClient(app) as client:
            resp = client.get("/api/intel/executive-summary")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("generated_at", data)
        self.assertIn("text", data)
        self.assertIn("stats", data)
        self.assertIsInstance(data["text"], str)
        self.assertTrue(len(data["text"]) > 0)

        stats = data["stats"]
        for key in (
            "zero_day_headlines",
            "target_reports",
            "advisory_snapshots",
            "geo_threat_events",
            "social_intel_items",
            "cve_cached",
            "cve_match_runs",
            "cve_alerts",
            "cve_alerts_unread",
            "cve_alerts_critical_unread",
            "graph_nodes",
            "graph_edges",
            "feed_topic",
            "feed_updated_at",
            "latest_report_target",
            "latest_report_created_at",
        ):
            self.assertIn(key, stats)


if __name__ == "__main__":
    unittest.main()
