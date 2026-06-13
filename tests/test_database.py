"""Tests for SQLite persistence."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from database import db


class DatabaseTests(unittest.TestCase):
    """Validate database initialization and duplicate-safe saves."""

    def test_save_and_get_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            test_db = Path(temp_dir) / "security.db"
            finding = {
                "ip_address": "10.0.0.1",
                "port": 443,
                "product": "nginx",
                "version": "1.24.0",
                "cve": "CVE-TEST",
                "cvss": 5.0,
                "risk_rating": "Medium",
                "description": "Test finding.",
            }

            with patch.object(db, "DATABASE_PATH", test_db):
                db.init_db()
                db.save_finding(finding)
                db.save_finding(finding)
                rows = db.get_all_findings()

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["product"], "nginx")


if __name__ == "__main__":
    unittest.main()
