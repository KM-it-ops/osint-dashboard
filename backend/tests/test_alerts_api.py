"""CVE alerts API and background poll helpers (NVD calls mocked where needed)."""

from __future__ import annotations

import random
import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from app.db import insert_cve_alert_if_new, list_cve_alerts
from app.main import app


class AlertsApiTests(unittest.TestCase):
    def test_get_alerts_shape(self) -> None:
        with TestClient(app) as client:
            resp = client.get("/api/alerts?limit=10")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("alerts", data)
        self.assertIn("unread_count", data)
        self.assertIn("last_nvd_poll", data)
        self.assertIsInstance(data["alerts"], list)

    def test_ack_invalid_id_400(self) -> None:
        with TestClient(app) as client:
            resp = client.post("/api/alerts/0/ack")
        self.assertEqual(resp.status_code, 400)

    def test_ack_missing_404(self) -> None:
        with TestClient(app) as client:
            resp = client.post("/api/alerts/999999/ack")
        self.assertEqual(resp.status_code, 404)

    def test_ack_updates_unread(self) -> None:
        cid = f"CVE-2099-{random.randint(100_000, 999_999)}"
        inserted = insert_cve_alert_if_new(
            cid,
            "CRITICAL",
            f"{cid} — Critical",
            "Synthetic row for alert ack test.",
        )
        self.assertTrue(inserted)
        rows = list_cve_alerts(5)
        target = next((r for r in rows if r.get("cve_id") == cid), None)
        self.assertIsNotNone(target)
        aid = int(target["id"])  # type: ignore[arg-type]
        with TestClient(app) as client:
            resp = client.post(f"/api/alerts/{aid}/ack")
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertTrue(payload.get("ok"))
        self.assertIn("unread_count", payload)
        # second ack → 404
        with TestClient(app) as client:
            resp2 = client.post(f"/api/alerts/{aid}/ack")
        self.assertEqual(resp2.status_code, 404)


class CriticalPollTests(unittest.TestCase):
    def test_poll_inserts_critical_only(self) -> None:
        fake_page = {
            "totalResults": 2,
            "format": "NVD_CVE",
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2099-11111",
                        "descriptions": [{"lang": "en", "value": "Should alert."}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseSeverity": "CRITICAL",
                                        "version": "3.1",
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    }
                                }
                            ]
                        },
                    }
                },
                {
                    "cve": {
                        "id": "CVE-2099-22222",
                        "descriptions": [{"lang": "en", "value": "Not critical."}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseSeverity": "HIGH",
                                        "version": "3.1",
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
                                    }
                                }
                            ]
                        },
                    }
                },
            ],
        }
        with patch("app.cve_client.get_app_metadata", return_value=None):
            with patch("app.cve_client._http_get_nvd", new_callable=AsyncMock, return_value=fake_page):
                from app.cve_client import run_critical_cve_poll

                async def _run() -> None:
                    result = await run_critical_cve_poll()
                    self.assertTrue(result.get("ok"))

                import asyncio

                asyncio.run(_run())

        ids = {r["cve_id"] for r in list_cve_alerts(50)}
        self.assertIn("CVE-2099-11111", ids)
        self.assertNotIn("CVE-2099-22222", ids)


if __name__ == "__main__":
    unittest.main()
