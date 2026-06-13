"""SQLite persistence helpers for scan-centric security findings."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from config import settings


DATABASE_PATH = settings.database_path


def get_connection() -> sqlite3.Connection:
    """Open a database connection that returns rows like dictionaries."""
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def _execute(script: str) -> None:
    """Execute a schema script and always close the connection."""
    connection = get_connection()
    try:
        connection.executescript(script)
        connection.commit()
    finally:
        connection.close()


def _migrate_legacy_findings_table() -> None:
    """Move the old flat findings table aside before creating Module 11 tables."""
    connection = get_connection()
    try:
        table = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'findings'"
        ).fetchone()
        if not table:
            return

        columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(findings)")
        }
        if "service_id" not in columns:
            connection.execute(
                "ALTER TABLE findings RENAME TO legacy_findings_module_1_to_10"
            )
            connection.commit()
    finally:
        connection.close()


def _import_legacy_findings() -> None:
    """Copy old flat findings into the normalized schema when present."""
    connection = get_connection()
    try:
        legacy = connection.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type = 'table' AND name = 'legacy_findings_module_1_to_10'
            """
        ).fetchone()
        if not legacy:
            return

        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(legacy_findings_module_1_to_10)")
        }
        required = {
            "ip_address",
            "port",
            "product",
            "version",
            "cve",
            "cvss",
            "risk_rating",
            "description",
        }
        if not required.issubset(columns):
            return

        scan_row = connection.execute(
            """
            SELECT id FROM scans
            WHERE scan_name = 'Legacy Import' AND source = 'legacy_migration'
            """
        ).fetchone()
        if scan_row:
            scan_id = int(scan_row["id"])
        else:
            cursor = connection.execute(
                """
                INSERT INTO scans (scan_name, uploaded_filename, source, notes)
                VALUES ('Legacy Import', 'database/security.db', 'legacy_migration',
                        'Imported from the Module 1-10 flat findings table.')
                """
            )
            scan_id = int(cursor.lastrowid)

        rows = connection.execute("SELECT * FROM legacy_findings_module_1_to_10").fetchall()
        for row in rows:
            connection.execute(
                """
                INSERT INTO hosts (scan_id, ip_address, hostname)
                VALUES (?, ?, '')
                ON CONFLICT(scan_id, ip_address) DO NOTHING
                """,
                (scan_id, row["ip_address"]),
            )
            host = connection.execute(
                "SELECT id FROM hosts WHERE scan_id = ? AND ip_address = ?",
                (scan_id, row["ip_address"]),
            ).fetchone()
            host_id = int(host["id"])

            connection.execute(
                """
                INSERT INTO services (
                    host_id, port, protocol, service_name, product, version, cpe
                )
                VALUES (?, ?, 'tcp', 'Unknown', ?, ?, '')
                ON CONFLICT(host_id, port, protocol) DO UPDATE SET
                    product = excluded.product,
                    version = excluded.version
                """,
                (host_id, row["port"], row["product"], row["version"]),
            )
            service = connection.execute(
                """
                SELECT id FROM services
                WHERE host_id = ? AND port = ? AND protocol = 'tcp'
                """,
                (host_id, row["port"]),
            ).fetchone()
            service_id = int(service["id"])

            connection.execute(
                """
                INSERT INTO findings (
                    service_id, cve, cvss, risk_rating, severity,
                    description, provider_source
                )
                VALUES (?, ?, ?, ?, ?, ?, 'legacy_migration')
                ON CONFLICT(service_id, cve) DO UPDATE SET
                    cvss = excluded.cvss,
                    risk_rating = excluded.risk_rating,
                    severity = excluded.severity,
                    description = excluded.description,
                    provider_source = excluded.provider_source
                """,
                (
                    service_id,
                    row["cve"],
                    row["cvss"],
                    row["risk_rating"],
                    row["risk_rating"],
                    row["description"],
                ),
            )

        connection.commit()
    finally:
        connection.close()


def init_db() -> None:
    """Create normalized scan, host, service, and finding tables."""
    _migrate_legacy_findings_table()
    _execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_name TEXT NOT NULL,
            uploaded_filename TEXT NOT NULL,
            scan_timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            source TEXT NOT NULL DEFAULT 'upload',
            notes TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            ip_address TEXT NOT NULL,
            hostname TEXT NOT NULL DEFAULT '',
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
            UNIQUE (scan_id, ip_address)
        );

        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL DEFAULT 'tcp',
            service_name TEXT NOT NULL DEFAULT 'Unknown',
            product TEXT NOT NULL DEFAULT 'Unknown',
            version TEXT NOT NULL DEFAULT 'Unknown',
            cpe TEXT NOT NULL DEFAULT '',
            FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
            UNIQUE (host_id, port, protocol)
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service_id INTEGER NOT NULL,
            cve TEXT NOT NULL,
            cvss REAL NOT NULL,
            risk_rating TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'Unknown',
            description TEXT NOT NULL,
            provider_source TEXT NOT NULL DEFAULT 'unknown',
            FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE,
            UNIQUE (service_id, cve)
        );

        CREATE INDEX IF NOT EXISTS idx_hosts_scan_id ON hosts(scan_id);
        CREATE INDEX IF NOT EXISTS idx_services_host_id ON services(host_id);
        CREATE INDEX IF NOT EXISTS idx_findings_service_id ON findings(service_id);
        CREATE INDEX IF NOT EXISTS idx_findings_risk_rating ON findings(risk_rating);
        """
    )
    _import_legacy_findings()


def create_scan(
    scan_name: str,
    uploaded_filename: str,
    source: str = "upload",
    notes: str = "",
) -> int:
    """Create a scan record and return its ID."""
    init_db()
    connection = get_connection()
    try:
        cursor = connection.execute(
            """
            INSERT INTO scans (scan_name, uploaded_filename, source, notes)
            VALUES (?, ?, ?, ?)
            """,
            (scan_name, uploaded_filename, source, notes),
        )
        connection.commit()
        return int(cursor.lastrowid)
    finally:
        connection.close()


def get_or_create_scan(
    scan_name: str,
    uploaded_filename: str,
    source: str = "upload",
    notes: str = "",
) -> int:
    """Return an existing matching scan or create one when missing."""
    init_db()
    connection = get_connection()
    try:
        row = connection.execute(
            """
            SELECT id FROM scans
            WHERE scan_name = ? AND uploaded_filename = ? AND source = ?
            ORDER BY id ASC LIMIT 1
            """,
            (scan_name, uploaded_filename, source),
        ).fetchone()
        if row:
            return int(row["id"])

        cursor = connection.execute(
            """
            INSERT INTO scans (scan_name, uploaded_filename, source, notes)
            VALUES (?, ?, ?, ?)
            """,
            (scan_name, uploaded_filename, source, notes),
        )
        connection.commit()
        return int(cursor.lastrowid)
    finally:
        connection.close()


def create_host(scan_id: int, ip_address: str, hostname: str = "") -> int:
    """Create or reuse a host record for a scan."""
    init_db()
    connection = get_connection()
    try:
        connection.execute(
            """
            INSERT INTO hosts (scan_id, ip_address, hostname)
            VALUES (?, ?, ?)
            ON CONFLICT(scan_id, ip_address) DO UPDATE SET
                hostname = excluded.hostname
            """,
            (scan_id, ip_address, hostname),
        )
        row = connection.execute(
            "SELECT id FROM hosts WHERE scan_id = ? AND ip_address = ?",
            (scan_id, ip_address),
        ).fetchone()
        connection.commit()
        return int(row["id"])
    finally:
        connection.close()


def create_service(
    host_id: int,
    port: int,
    protocol: str = "tcp",
    service_name: str = "Unknown",
    product: str = "Unknown",
    version: str = "Unknown",
    cpe: str = "",
) -> int:
    """Create or reuse a service record for a host."""
    init_db()
    connection = get_connection()
    try:
        connection.execute(
            """
            INSERT INTO services (
                host_id, port, protocol, service_name, product, version, cpe
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(host_id, port, protocol) DO UPDATE SET
                service_name = excluded.service_name,
                product = excluded.product,
                version = excluded.version,
                cpe = excluded.cpe
            """,
            (host_id, port, protocol, service_name, product, version, cpe),
        )
        row = connection.execute(
            """
            SELECT id FROM services
            WHERE host_id = ? AND port = ? AND protocol = ?
            """,
            (host_id, port, protocol),
        ).fetchone()
        connection.commit()
        return int(row["id"])
    finally:
        connection.close()


def create_finding(
    service_id: int,
    cve: str,
    cvss: float,
    risk_rating: str,
    severity: str,
    description: str,
    provider_source: str = "unknown",
) -> int:
    """Create or update a finding for a service."""
    init_db()
    connection = get_connection()
    try:
        connection.execute(
            """
            INSERT INTO findings (
                service_id, cve, cvss, risk_rating, severity,
                description, provider_source
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(service_id, cve) DO UPDATE SET
                cvss = excluded.cvss,
                risk_rating = excluded.risk_rating,
                severity = excluded.severity,
                description = excluded.description,
                provider_source = excluded.provider_source
            """,
            (service_id, cve, cvss, risk_rating, severity, description, provider_source),
        )
        row = connection.execute(
            "SELECT id FROM findings WHERE service_id = ? AND cve = ?",
            (service_id, cve),
        ).fetchone()
        connection.commit()
        return int(row["id"])
    finally:
        connection.close()


def get_scan_history() -> list[dict[str, Any]]:
    """Return scan records with host and finding counts."""
    init_db()
    connection = get_connection()
    try:
        rows = connection.execute(
            """
            SELECT
                scans.id,
                scans.scan_name,
                scans.uploaded_filename,
                scans.scan_timestamp,
                scans.source,
                scans.notes,
                COUNT(DISTINCT hosts.id) AS host_count,
                COUNT(DISTINCT findings.id) AS finding_count
            FROM scans
            LEFT JOIN hosts ON hosts.scan_id = scans.id
            LEFT JOIN services ON services.host_id = hosts.id
            LEFT JOIN findings ON findings.service_id = services.id
            GROUP BY scans.id
            ORDER BY scans.id DESC
            """
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def get_scan_details(scan_id: int) -> dict[str, Any] | None:
    """Return one scan record by ID."""
    init_db()
    connection = get_connection()
    try:
        row = connection.execute(
            "SELECT * FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        connection.close()


def get_host_services(scan_id: int) -> list[dict[str, Any]]:
    """Return hosts and services for a scan."""
    init_db()
    connection = get_connection()
    try:
        rows = connection.execute(
            """
            SELECT
                hosts.id AS host_id,
                hosts.ip_address,
                hosts.hostname,
                services.id AS service_id,
                services.port,
                services.protocol,
                services.service_name,
                services.product,
                services.version,
                services.cpe
            FROM hosts
            LEFT JOIN services ON services.host_id = hosts.id
            WHERE hosts.scan_id = ?
            ORDER BY hosts.ip_address, services.port
            """,
            (scan_id,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def get_findings_for_scan(scan_id: int) -> list[dict[str, Any]]:
    """Return enriched findings for one scan."""
    init_db()
    connection = get_connection()
    try:
        rows = connection.execute(
            """
            SELECT
                findings.id,
                hosts.ip_address,
                hosts.hostname,
                services.port,
                services.protocol,
                services.service_name,
                services.product,
                services.version,
                services.cpe,
                findings.cve,
                findings.cvss,
                findings.risk_rating,
                findings.severity,
                findings.description,
                findings.provider_source
            FROM findings
            JOIN services ON services.id = findings.service_id
            JOIN hosts ON hosts.id = services.host_id
            WHERE hosts.scan_id = ?
            ORDER BY findings.cvss DESC, hosts.ip_address, services.port
            """,
            (scan_id,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def get_all_findings() -> list[dict[str, Any]]:
    """Return all persisted findings in the legacy dashboard-friendly shape."""
    init_db()
    connection = get_connection()
    try:
        rows = connection.execute(
            """
            SELECT
                findings.id,
                hosts.ip_address,
                services.port,
                services.product,
                services.version,
                findings.cve,
                findings.cvss,
                findings.risk_rating,
                findings.description,
                findings.severity,
                findings.provider_source
            FROM findings
            JOIN services ON services.id = findings.service_id
            JOIN hosts ON hosts.id = services.host_id
            ORDER BY findings.cvss DESC, findings.id ASC
            """
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def save_finding(finding: dict[str, Any]) -> None:
    """Backward-compatible helper that saves a standalone finding.

    New code should prefer create_scan(), create_host(), create_service(), and
    create_finding(). This wrapper keeps older modules and tests working.
    """
    scan_id = get_or_create_scan("Legacy Analysis", "sample_scan.xml", "legacy")
    host_id = create_host(scan_id, str(finding["ip_address"]))
    service_id = create_service(
        host_id=host_id,
        port=int(finding["port"]),
        product=str(finding["product"]),
        version=str(finding["version"]),
    )
    create_finding(
        service_id=service_id,
        cve=str(finding["cve"]),
        cvss=float(finding["cvss"]),
        risk_rating=str(finding["risk_rating"]),
        severity=str(finding.get("severity", finding.get("risk_rating", "Unknown"))),
        description=str(finding["description"]),
        provider_source=str(finding.get("provider_source", "unknown")),
    )


if __name__ == "__main__":
    init_db()
    print("Database initialized successfully.")
