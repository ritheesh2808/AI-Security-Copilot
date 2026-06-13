"""Assess the risk of vulnerabilities found in an Nmap scan."""

import sys
from pathlib import Path


# Add the project root so imports work when this file is run directly.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from cve.real_cve_lookup import lookup_real_cves
from parser.nmap_parser import DEFAULT_SCAN_PATH, parse_nmap_scan


def calculate_risk(cvss: float) -> str:
    """Convert a CVSS score into a human-readable risk rating."""
    if not 0.0 <= cvss <= 10.0:
        raise ValueError("CVSS score must be between 0.0 and 10.0")

    if cvss <= 3.9:
        return "Low"
    if cvss <= 6.9:
        return "Medium"
    if cvss <= 8.9:
        return "High"
    return "Critical"


def print_risk_assessment() -> None:
    """Parse the sample scan and print the risk for each matching CVE."""
    scan_results = parse_nmap_scan(DEFAULT_SCAN_PATH)

    for service in scan_results:
        product = str(service["product"])
        version = str(service["version"])
        matching_cves = lookup_real_cves(product, version)

        # Each matched CVE becomes one risk assessment finding.
        for cve in matching_cves:
            cvss_score = float(cve["cvss"])
            risk_rating = calculate_risk(cvss_score)

            print(f"IP Address: {service['ip_address']}")
            print(f"Port: {service['port']}")
            print(f"Product: {product}")
            print(f"Version: {version}")
            print(f"CVE: {cve['cve_id']}")
            print(f"CVSS Score: {cvss_score}")
            print(f"Risk Rating: {risk_rating}")
            print("-" * 50)


if __name__ == "__main__":
    # This test section runs the complete scan, lookup, and risk workflow.
    print_risk_assessment()
