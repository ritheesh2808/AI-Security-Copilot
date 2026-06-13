"""SQLite persistence helpers for security findings."""

import sqlite3
import sys
from pathlib import Path


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


def init_db() -> None:
    """Create the findings table when it does not already exist."""
    connection = get_connection()
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                port INTEGER NOT NULL,
                product TEXT NOT NULL,
                version TEXT NOT NULL,
                cve TEXT NOT NULL,
                cvss REAL NOT NULL,
                risk_rating TEXT NOT NULL,
                description TEXT NOT NULL,
                UNIQUE (ip_address, port, cve)
            )
            """
        )
        connection.commit()
    finally:
        connection.close()


def save_finding(finding: dict[str, str | float | int]) -> None:
    """Insert a finding, or update it when the same finding already exists."""
    init_db()

    connection = get_connection()
    try:
        connection.execute(
            """
            INSERT INTO findings (
                ip_address, port, product, version, cve, cvss,
                risk_rating, description
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip_address, port, cve) DO UPDATE SET
                product = excluded.product,
                version = excluded.version,
                cvss = excluded.cvss,
                risk_rating = excluded.risk_rating,
                description = excluded.description
            """,
            (
                finding["ip_address"],
                finding["port"],
                finding["product"],
                finding["version"],
                finding["cve"],
                finding["cvss"],
                finding["risk_rating"],
                finding["description"],
            ),
        )
        connection.commit()
    finally:
        connection.close()


def get_all_findings() -> list[dict[str, str | float | int]]:
    """Return every stored finding ordered by highest CVSS score first."""
    init_db()

    connection = get_connection()
    try:
        rows = connection.execute(
            "SELECT * FROM findings ORDER BY cvss DESC, id ASC"
        ).fetchall()
    finally:
        connection.close()

    return [dict(row) for row in rows]


if __name__ == "__main__":
    # This test section creates database/security.db and the findings table.
    init_db()
    print("Database initialized successfully.")
