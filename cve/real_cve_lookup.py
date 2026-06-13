"""Common CVE provider with a local database fallback."""

import logging
import sys
from pathlib import Path


# Add the project root so imports work when this file is run directly.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from cve.cve_lookup import lookup_local_cves
from cve.nvd_provider import NVDProviderError, search_nvd
from parser.nmap_parser import DEFAULT_SCAN_PATH, parse_nmap_scan


logger = logging.getLogger(__name__)

# Common aliases are converted to the names used by the CVE providers.
PRODUCT_NAME_ALIASES = {
    "apache": "Apache httpd",
    "apache http server": "Apache httpd",
    "apache httpd": "Apache httpd",
    "nginx": "nginx",
    "openssh": "OpenSSH",
    "open ssh": "OpenSSH",
}


def normalize_product_name(product: str) -> str:
    """Return a consistent product name for CVE lookups."""
    cleaned_name = " ".join(product.strip().split())
    return PRODUCT_NAME_ALIASES.get(cleaned_name.casefold(), cleaned_name)


def query_real_cve_source(product: str, version: str) -> list[dict[str, str | float]]:
    """Query the configured real CVE provider."""
    return search_nvd(product, version)


def lookup_real_cves(product: str, version: str) -> list[dict[str, str | float]]:
    """Return real CVE results, or local fallback data when none are available."""
    normalized_product = normalize_product_name(product)
    try:
        real_results = query_real_cve_source(normalized_product, version)
    except NVDProviderError as error:
        logger.warning(
            "NVD lookup failed for %s %s; using local fallback",
            normalized_product,
            version,
        )
        logger.debug("NVD error details: %s", error)
        real_results = []

    if real_results:
        return real_results

    logger.debug("Using local CVE fallback for %s %s", normalized_product, version)
    return lookup_local_cves(normalized_product, version)


def print_cve_results() -> None:
    """Parse the sample scan and print results from the common CVE provider."""
    for service in parse_nmap_scan(DEFAULT_SCAN_PATH):
        product = normalize_product_name(str(service["product"]))
        version = str(service["version"])

        for cve in lookup_real_cves(product, version):
            print(f"Product: {product}")
            print(f"Version: {version}")
            print(f"CVE: {cve['cve_id']}")
            print(f"Severity: {cve['severity']}")
            print(f"CVSS: {cve['cvss']}")
            print(f"Description: {cve['description']}")
            print("-" * 50)


if __name__ == "__main__":
    # This test section demonstrates the real-provider-to-local-fallback flow.
    print_cve_results()
