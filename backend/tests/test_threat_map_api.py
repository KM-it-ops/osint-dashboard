"""Threat map API smoke tests (TestClient runs app lifespan / init_db)."""

from __future__ import annotations

import os
import unittest

from fastapi.testclient import TestClient

from app.main import app


class ThreatMapApiTests(unittest.TestCase):
    def test_get_returns_feature_collection(self) -> None:
        with TestClient(app) as client:
            resp = client.get("/api/threat-map/events?limit=10")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data.get("type"), "FeatureCollection")
        self.assertIn("features", data)
        self.assertIsInstance(data["features"], list)
        if data["features"]:
            f0 = data["features"][0]
            self.assertEqual(f0.get("type"), "Feature")
            self.assertIn("geometry", f0)
            self.assertEqual(f0["geometry"].get("type"), "Point")
            self.assertIn("coordinates", f0["geometry"])
            self.assertEqual(len(f0["geometry"]["coordinates"]), 2)

    def test_post_disabled_by_default(self) -> None:
        os.environ.pop("OSINT_DEV_THREAT_MAP_POST", None)
        with TestClient(app) as client:
            resp = client.post(
                "/api/threat-map/events",
                json={
                    "label": "unittest marker",
                    "country_code": "US",
                    "lat": 40.0,
                    "lon": -74.0,
                    "severity": "low",
                    "source_ref": "unittest",
                },
            )
        self.assertEqual(resp.status_code, 403)

    def test_post_enabled(self) -> None:
        os.environ["OSINT_DEV_THREAT_MAP_POST"] = "1"
        try:
            with TestClient(app) as client:
                resp = client.post(
                    "/api/threat-map/events",
                    json={
                        "label": "unittest dev insert",
                        "country_code": "CA",
                        "lat": 45.5,
                        "lon": -73.6,
                        "severity": "medium",
                        "source_ref": "unittest",
                    },
                )
            self.assertEqual(resp.status_code, 200)
            body = resp.json()
            self.assertTrue(body.get("ok"))
            self.assertIn("id", body)
        finally:
            os.environ.pop("OSINT_DEV_THREAT_MAP_POST", None)


if __name__ == "__main__":
    unittest.main()
