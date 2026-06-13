"""SQLite persistence helpers for security findings."""

import sqlite3
from pathlib import Path


DATABASE_PATH = Path(__file__).resolve().parent / "security.db"


def get_connection() -> sqlite3.Connection:
    """Open a database connection that returns rows like dictionaries."""
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    """Create the findings table when it does not already exist."""
    with get_connection() as connection:
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


def save_finding(finding: dict[str, str | float | int]) -> None:
    """Insert a finding, or update it when the same finding already exists."""
    init_db()

    with get_connection() as connection:
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


def get_all_findings() -> list[dict[str, str | float | int]]:
    """Return every stored finding ordered by highest CVSS score first."""
    init_db()

    with get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM findings ORDER BY cvss DESC, id ASC"
        ).fetchall()

    return [dict(row) for row in rows]


if __name__ == "__main__":
    # This test section creates database/security.db and the findings table.
    init_db()
    print("Database initialized successfully.")
