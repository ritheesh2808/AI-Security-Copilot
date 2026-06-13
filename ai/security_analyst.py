"""Generate local security analysis for vulnerabilities found in a scan."""

import logging
import sys
from pathlib import Path


# Add the project root so imports work when this file is run directly.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from cve.real_cve_lookup import lookup_real_cves
from database.db import save_finding
from parser.nmap_parser import DEFAULT_SCAN_PATH, parse_nmap_scan
from risk.risk_assessor import calculate_risk


logger = logging.getLogger(__name__)

# Local explanations are used for now. Later, generate_analysis() can call
# Ollama or another AI provider without changing the reporting functions.
SECURITY_EXPLANATIONS = {
    "OpenSSH": {
        "impact": (
            "An attacker may disrupt SSH access or attempt to gain unauthorized "
            "remote access to the system."
        ),
        "recommendation": (
            "Upgrade OpenSSH to a patched version, restrict SSH access to trusted "
            "networks, and review authentication logs."
        ),
    },
    "Apache httpd": {
        "impact": (
            "An attacker may affect the web server's confidentiality, integrity, "
            "or availability."
        ),
        "recommendation": (
            "Upgrade Apache httpd to a patched version, review enabled modules, "
            "and limit public access where possible."
        ),
    },
    "nginx": {
        "impact": (
            "An attacker may cause unexpected web server behavior, expose data, "
            "or interrupt service."
        ),
        "recommendation": (
            "Upgrade nginx to a patched version, review the server configuration, "
            "and monitor web server logs."
        ),
    },
}


def generate_analysis(
    product: str, version: str, cve: str, severity: str
) -> dict[str, str]:
    """Return a local security explanation for a vulnerability."""
    explanation = SECURITY_EXPLANATIONS.get(
        product,
        {
            "impact": "The vulnerability may affect the security of this service.",
            "recommendation": (
                "Review the CVE details and update the product to a patched version."
            ),
        },
    )

    return {
        "analysis": (
            f"{cve} affects {product} {version} and has a {severity} severity rating."
        ),
        "impact": explanation["impact"],
        "recommendation": explanation["recommendation"],
    }


def build_security_findings(
    scan_path: Path = DEFAULT_SCAN_PATH,
) -> list[dict[str, str | float | int]]:
    """Analyze an Nmap scan, save its findings, and return the results."""
    findings: list[dict[str, str | float | int]] = []
    services = parse_nmap_scan(scan_path)

    for service in services:
        product = str(service["product"])
        version = str(service["version"])
        matching_cves = lookup_real_cves(product, version)

        for cve_data in matching_cves:
            cvss = float(cve_data["cvss"])
            severity = str(cve_data["severity"])
            cve_id = str(cve_data["cve_id"])
            analysis = generate_analysis(product, version, cve_id, severity)

            finding = {
                "ip_address": service["ip_address"],
                "port": service["port"],
                "product": product,
                "version": version,
                "cve": cve_id,
                "cvss": cvss,
                "risk_rating": calculate_risk(cvss),
                "description": str(cve_data["description"]),
                **analysis,
            }
            findings.append(finding)

            # Automatically persist every completed analysis finding.
            save_finding(finding)

        # Keep scanned services even when the CVE provider has no matching entry.
        if not matching_cves:
            analysis = generate_analysis(product, version, "NO-CVE-MATCH", "Low")
            finding = {
                "ip_address": service["ip_address"],
                "port": service["port"],
                "product": product,
                "version": version,
                "cve": "NO-CVE-MATCH",
                "cvss": 0.0,
                "risk_rating": calculate_risk(0.0),
                "description": "No matching CVE was found by the configured providers.",
                **analysis,
            }
            findings.append(finding)
            save_finding(finding)

    logger.info("Findings saved count: %d", len(findings))
    return findings


def print_security_analysis() -> None:
    """Print the complete local AI security analysis report."""
    for finding in build_security_findings():
        print(f"IP Address: {finding['ip_address']}")
        print(f"Port: {finding['port']}")
        print(f"Product: {finding['product']}")
        print(f"Version: {finding['version']}")
        print(f"CVE: {finding['cve']}")
        print(f"CVSS: {finding['cvss']}")
        print(f"Risk Rating: {finding['risk_rating']}")
        print()
        print(f"AI Analysis: {finding['analysis']}")
        print(f"Potential Impact: {finding['impact']}")
        print(f"Recommendations: {finding['recommendation']}")
        print("-" * 70)


if __name__ == "__main__":
    # This test section runs the complete scan-to-analysis workflow.
    print_security_analysis()
