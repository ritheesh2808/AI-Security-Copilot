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

    def test_normalized_scan_workflow(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            test_db = Path(temp_dir) / "security.db"

            with patch.object(db, "DATABASE_PATH", test_db):
                db.init_db()
                scan_id = db.create_scan("Unit Scan", "unit.xml", "test")
                host_id = db.create_host(scan_id, "10.0.0.5", "demo.local")
                service_id = db.create_service(
                    host_id,
                    22,
                    "tcp",
                    "ssh",
                    "OpenSSH",
                    "9.6p1",
                    "cpe:/a:openbsd:openssh:9.6p1",
                )
                finding_id = db.create_finding(
                    service_id,
                    "CVE-UNIT",
                    9.0,
                    "Critical",
                    "Critical",
                    "Unit test finding.",
                    "nvd",
                )
                history = db.get_scan_history()
                services = db.get_host_services(scan_id)
                findings = db.get_findings_for_scan(scan_id)

        self.assertGreater(scan_id, 0)
        self.assertGreater(host_id, 0)
        self.assertGreater(service_id, 0)
        self.assertGreater(finding_id, 0)
        self.assertEqual(history[0]["host_count"], 1)
        self.assertEqual(history[0]["finding_count"], 1)
        self.assertEqual(services[0]["hostname"], "demo.local")
        self.assertEqual(findings[0]["provider_source"], "nvd")


if __name__ == "__main__":
    unittest.main()
