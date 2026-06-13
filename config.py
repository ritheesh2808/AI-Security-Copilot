"""Central configuration for AI Security Copilot."""

from __future__ import annotations

import logging
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

from utils.logger import configure_logging as _configure_logging


PROJECT_ROOT = Path(__file__).resolve().parent


def _env_bool(name: str, default: bool) -> bool:
    """Read a boolean setting from an environment variable."""
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    """Application settings with safe defaults for local development."""

    project_root: Path = PROJECT_ROOT
    database_path: Path = Path(os.getenv("DATABASE_PATH", str(PROJECT_ROOT / "database" / "security.db")))
    upload_folder: Path = Path(os.getenv("UPLOAD_FOLDER", str(PROJECT_ROOT / "uploads")))
    report_path: Path = PROJECT_ROOT / "reports" / "security_report.pdf"
    sample_scan_path: Path = PROJECT_ROOT / "scans" / "sample_scan.xml"
    secret_key: str = os.getenv("SECRET_KEY") or secrets.token_hex(32)
    flask_debug: bool = _env_bool("FLASK_DEBUG", False)
    max_upload_bytes: int = int(
        os.getenv("MAX_UPLOAD_SIZE", os.getenv("MAX_UPLOAD_BYTES", str(5 * 1024 * 1024)))
    )
    nvd_api_key: str | None = os.getenv("NVD_API_KEY")
    nvd_timeout: int = int(os.getenv("NVD_TIMEOUT", "15"))
    nvd_enabled: bool = _env_bool("NVD_ENABLED", True)
    log_level: str = os.getenv("LOG_LEVEL", "INFO")


settings = Settings()


def configure_logging(level: str | None = None) -> None:
    """Configure consistent logging for command-line scripts and Flask."""
    _configure_logging(level or settings.log_level)
