"""Look up known vulnerabilities for products found in an Nmap scan."""

import sys
from pathlib import Path


# Add the project root to Python's import path when this file is run directly.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from parser.nmap_parser import DEFAULT_SCAN_PATH, parse_nmap_scan


# This small local database maps a product and version to known CVE information.
# The entries are examples for demonstrating the lookup workflow.
VULNERABILITY_DATABASE = {
    ("Apache httpd", "2.4.58"): [
        {
            "cve_id": "CVE-2024-12345",
            "cvss": 8.1,
            "severity": "High",
            "description": "Example vulnerability affecting Apache httpd 2.4.58.",
        }
    ],
    ("OpenSSH", "9.6p1"): [
        {
            "cve_id": "CVE-2024-6387",
            "cvss": 9.8,
            "severity": "Critical",
            "description": "Example OpenSSH signal handler race condition.",
        }
    ],
    ("nginx", "1.24.0"): [
        {
            "cve_id": "CVE-2024-24989",
            "cvss": 6.5,
            "severity": "Medium",
            "description": "Example vulnerability affecting nginx 1.24.0.",
        }
    ],
}


def lookup_local_cves(product: str, version: str) -> list[dict[str, str | float]]:
    """Return local CVEs that exactly match the supplied product and version."""
    return VULNERABILITY_DATABASE.get((product, version), [])


def lookup_cves(product: str, version: str) -> list[dict[str, str | float]]:
    """Return CVEs using the common provider interface.

    This wrapper keeps older imports working while new modules use
    lookup_real_cves() directly.
    """
    from cve.real_cve_lookup import lookup_real_cves

    return lookup_real_cves(product, version)


def print_findings() -> None:
    """Parse the sample Nmap scan, look up CVEs, and print each finding."""
    scan_results = parse_nmap_scan(DEFAULT_SCAN_PATH)

    for service in scan_results:
        product = str(service["product"])
        version = str(service["version"])
        matching_cves = lookup_cves(product, version)

        # Print one finding for every CVE matched to the scanned service.
        for cve in matching_cves:
            print(f"IP Address: {service['ip_address']}")
            print(f"Port: {service['port']}")
            print(f"Product: {product}")
            print(f"Version: {version}")
            print()
            print(f"CVE: {cve['cve_id']}")
            print(f"CVSS Score: {cve['cvss']}")
            print(f"Severity: {cve['severity']}")
            print(f"Description: {cve['description']}")
            print("-" * 50)


if __name__ == "__main__":
    # This test section demonstrates the complete parser-to-CVE workflow.
    print_findings()
