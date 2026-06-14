"""Generate local security analysis for vulnerabilities found in a scan."""

import logging
import sys
from pathlib import Path


# Add the project root so imports work when this file is run directly.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from cve.real_cve_lookup import lookup_real_cves
from database.db import (
    create_finding,
    create_host,
    create_scan,
    create_service,
)
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
    scan_id: int | None = None,
    scan_name: str | None = None,
    uploaded_filename: str | None = None,
    source: str = "sample",
) -> list[dict[str, str | float | int]]:
    """Analyze an Nmap scan, save its findings, and return the results."""
    findings: list[dict[str, str | float | int]] = []
    services = parse_nmap_scan(scan_path)
    saved_host_ids: set[int] = set()
    saved_service_count = 0

    if scan_id is None:
        scan_id = create_scan(
            scan_name or Path(scan_path).stem,
            uploaded_filename or Path(scan_path).name,
            source=source,
        )

    for service in services:
        host_id = create_host(
            scan_id=scan_id,
            ip_address=str(service["ip_address"]),
            hostname=str(service.get("hostname", "")),
        )
        saved_host_ids.add(host_id)
        service_id = create_service(
            host_id=host_id,
            port=int(service["port"]),
            protocol=str(service.get("protocol", "tcp")),
            service_name=str(service.get("service_name", "Unknown")),
            product=str(service["product"]),
            version=str(service["version"]),
            cpe=str(service.get("cpe", "")),
        )
        saved_service_count += 1
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
                "hostname": service.get("hostname", ""),
                "port": service["port"],
                "protocol": service.get("protocol", "tcp"),
                "service_name": service.get("service_name", "Unknown"),
                "product": product,
                "version": version,
                "cpe": service.get("cpe", ""),
                "cve": cve_id,
                "cvss": cvss,
                "risk_rating": calculate_risk(cvss),
                "severity": severity,
                "description": str(cve_data["description"]),
                "provider_source": str(cve_data.get("provider_source", "unknown")),
                **analysis,
            }
            findings.append(finding)

            # Automatically persist every completed analysis finding.
            create_finding(
                service_id=service_id,
                cve=cve_id,
                cvss=cvss,
                risk_rating=str(finding["risk_rating"]),
                severity=severity,
                description=str(finding["description"]),
                provider_source=str(finding["provider_source"]),
            )

        # Keep scanned services even when the CVE provider has no matching entry.
        if not matching_cves:
            analysis = generate_analysis(product, version, "NO-CVE-MATCH", "Low")
            finding = {
                "ip_address": service["ip_address"],
                "hostname": service.get("hostname", ""),
                "port": service["port"],
                "protocol": service.get("protocol", "tcp"),
                "service_name": service.get("service_name", "Unknown"),
                "product": product,
                "version": version,
                "cpe": service.get("cpe", ""),
                "cve": "NO-CVE-MATCH",
                "cvss": 0.0,
                "risk_rating": calculate_risk(0.0),
                "severity": "Low",
                "description": "No matching CVE was found by the configured providers.",
                "provider_source": "no_match",
                **analysis,
            }
            findings.append(finding)
            create_finding(
                service_id=service_id,
                cve="NO-CVE-MATCH",
                cvss=0.0,
                risk_rating=str(finding["risk_rating"]),
                severity="Low",
                description=str(finding["description"]),
                provider_source="no_match",
            )

    logger.info("Scan ID: %d", scan_id)
    logger.info("Hosts saved count: %d", len(saved_host_ids))
    logger.info("Services saved count: %d", saved_service_count)
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
