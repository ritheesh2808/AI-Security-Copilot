"""Tests for the Flask dashboard and upload workflow."""

import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from app import app
from config import settings
from database import db


class FlaskAppTests(unittest.TestCase):
    """Validate dashboard rendering and XML upload behavior."""

    def test_dashboard_loads(self) -> None:
        response = app.test_client().get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"AI Security Copilot", response.data)

    def test_valid_upload_analyzes_and_saves(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            test_db = Path(temp_dir) / "security.db"
            upload_dir = Path(temp_dir) / "uploads"
            scan_data = settings.sample_scan_path.read_bytes()
            original_upload_folder = app.config["UPLOAD_FOLDER"]

            app.config["UPLOAD_FOLDER"] = upload_dir
            try:
                with patch.object(db, "DATABASE_PATH", test_db), patch(
                    "cve.real_cve_lookup.search_nvd", return_value=[]
                ):
                    response = app.test_client().post(
                        "/upload",
                        data={"scan_file": (BytesIO(scan_data), "sample.xml")},
                        content_type="multipart/form-data",
                        follow_redirects=True,
                    )
                    rows = db.get_all_findings()
            finally:
                app.config["UPLOAD_FOLDER"] = original_upload_folder

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Scan imported successfully", response.data)
        self.assertEqual(len(rows), 3)

    def test_invalid_upload_extension_is_rejected(self) -> None:
        response = app.test_client().post(
            "/upload",
            data={"scan_file": (BytesIO(b"<nmaprun/>"), "scan.txt")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid file type", response.data)


if __name__ == "__main__":
    unittest.main()
