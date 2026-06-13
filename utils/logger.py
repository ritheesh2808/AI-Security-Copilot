"""Centralized logging helpers for AI Security Copilot."""

from __future__ import annotations

import logging


LOG_FORMAT = "%(levelname)s:%(name)s:%(message)s"


def configure_logging(level: str = "INFO") -> None:
    """Configure application-wide logging once."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format=LOG_FORMAT,
    )


def get_logger(name: str) -> logging.Logger:
    """Return a module logger using the standard project configuration."""
    return logging.getLogger(name)
