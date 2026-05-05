"""PDF export for saved target intelligence reports."""

from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from app.db import get_target_report, init_db, insert_target_report
from app.main import app


class ReportPdfApiTests(unittest.TestCase):
    def test_pdf_404_for_missing(self) -> None:
        init_db()
        with TestClient(app) as client:
            r = client.get("/api/report/pdf/999999999")
            self.assertEqual(r.status_code, 404)

    def test_pdf_400_for_invalid_id(self) -> None:
        init_db()
        with TestClient(app) as client:
            r = client.get("/api/report/pdf/0")
            self.assertEqual(r.status_code, 400)

    def test_pdf_stream_headers_and_magic(self) -> None:
        init_db()
        rid = insert_target_report(
            "pdf-test.example",
            "domain",
            "unit test query",
            {
                "summary": "Unit test summary line for PDF export.",
                "key_findings": ["Finding A", "Finding B"],
                "sources": [
                    {
                        "title": "Example",
                        "url": "https://example.com/path?q=1",
                        "snippet": "Short snippet.",
                    }
                ],
                "target_normalized": "pdf-test.example",
                "target_kind": "domain",
            },
        )
        row = get_target_report(rid)
        self.assertIsNotNone(row)
        with TestClient(app) as client:
            r = client.get(f"/api/report/pdf/{rid}")
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.headers.get("content-type", "").split(";")[0], "application/pdf")
            cd = r.headers.get("content-disposition") or ""
            self.assertIn("attachment", cd)
            self.assertIn(f"intel-report-{rid}.pdf", cd)
            body = r.content
            self.assertGreater(len(body), 100)
            self.assertTrue(body.startswith(b"%PDF"))


if __name__ == "__main__":
    unittest.main()
