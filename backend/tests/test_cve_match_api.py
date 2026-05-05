"""CVE match API tests (NVD calls mocked; TestClient runs lifespan / init_db)."""

from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from app.main import app


class CveMatchApiTests(unittest.TestCase):
    def test_empty_target_400(self) -> None:
        with TestClient(app) as client:
            resp = client.get("/api/cve/match?target=")
        self.assertEqual(resp.status_code, 400)

    def test_match_by_cve_id_mocked_nvd(self) -> None:
        fake_body = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-44228",
                        "descriptions": [{"lang": "en", "value": "Apache Log4j2 JNDI features used in configuration."}],
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseSeverity": "CRITICAL", "version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}}
                            ]
                        },
                    }
                }
            ]
        }
        with patch("app.cve_client._http_get_nvd", new_callable=AsyncMock, return_value=fake_body):
            with TestClient(app) as client:
                resp = client.get("/api/cve/match?target=CVE-2021-44228")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data.get("target"), "CVE-2021-44228")
        self.assertEqual(data.get("parsed_cve_ids"), ["CVE-2021-44228"])
        matches = data.get("matches") or []
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].get("cve_id"), "CVE-2021-44228")
        self.assertEqual(matches[0].get("severity"), "CRITICAL")
        self.assertIn("Log4j2", matches[0].get("summary") or "")
        self.assertIsNotNone(data.get("match_run_id"))

    def test_keyword_search_mocked_nvd(self) -> None:
        fake_kw = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-0001",
                        "descriptions": [{"lang": "en", "value": "Example keyword hit."}],
                        "metrics": {},
                    }
                }
            ]
        }
        with patch("app.cve_client._http_get_nvd", new_callable=AsyncMock, return_value=fake_kw):
            with TestClient(app) as client:
                resp = client.get("/api/cve/match?target=example%20product%20flaw")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data.get("parsed_cve_ids"), [])
        matches = data.get("matches") or []
        self.assertGreaterEqual(len(matches), 1)
        self.assertEqual(matches[0].get("cve_id"), "CVE-2023-0001")


if __name__ == "__main__":
    unittest.main()
