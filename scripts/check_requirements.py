"""Validate that required runtime packages are importable."""

from __future__ import annotations

import importlib
import sys


REQUIRED_MODULES = {
    "Flask": "flask",
    "lxml": "lxml",
    "reportlab": "reportlab",
    "requests": "requests",
}


def main() -> int:
    """Import each runtime dependency and report missing packages."""
    missing: list[str] = []

    for package_name, module_name in REQUIRED_MODULES.items():
        try:
            importlib.import_module(module_name)
        except ImportError:
            missing.append(package_name)

    if missing:
        print("Missing required packages: " + ", ".join(missing))
        return 1

    print("All runtime requirements are importable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
