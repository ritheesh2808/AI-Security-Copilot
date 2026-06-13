"""Tests for PDF report generation."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reports import pdf_generator


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


if __name__ == "__main__":
    unittest.main()
