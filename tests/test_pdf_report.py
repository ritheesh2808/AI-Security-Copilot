"""Tests for PDF report generation."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reports import pdf_generator
from database import db


class PDFReportTests(unittest.TestCase):
    """Validate that a PDF report file can be generated."""

    def test_generate_pdf_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "security_report.pdf"
            with patch.object(pdf_generator, "REPORT_PATH", report_path), patch(
                "cve.real_cve_lookup.search_nvd", return_value=[]
            ):
                generated_path = pdf_generator.generate_pdf_report()
                exists = report_path.exists()
                size = report_path.stat().st_size

        self.assertEqual(generated_path, report_path)
        self.assertTrue(exists)
        self.assertGreater(size, 0)

    def test_generate_scan_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            test_db = Path(temp_dir) / "security.db"
            report_path = Path(temp_dir) / "security_report.pdf"
            with patch.object(db, "DATABASE_PATH", test_db), patch.object(
                pdf_generator, "REPORT_PATH", report_path
            ):
                scan_id = db.create_scan("Report Scan", "report.xml", "test")
                host_id = db.create_host(scan_id, "10.0.0.9")
                service_id = db.create_service(host_id, 80, product="Apache httpd")
                db.create_finding(
                    service_id,
                    "CVE-REPORT",
                    7.5,
                    "High",
                    "High",
                    "Report finding.",
                    "local_fallback",
                )
                generated_path = pdf_generator.generate_scan_report(scan_id)
                exists = generated_path.exists()
                size = generated_path.stat().st_size

        self.assertTrue(str(generated_path).endswith("security_report_scan_1.pdf"))
        self.assertTrue(exists)
        self.assertGreater(size, 0)


if __name__ == "__main__":
    unittest.main()
