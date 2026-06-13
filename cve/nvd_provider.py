"""NVD CVE provider using the official NVD API."""

import logging
import sys
from pathlib import Path
from typing import Any

import requests


# Add the project root so this provider can be run directly.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from config import settings


logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_TIMEOUT = 15
DEFAULT_RESULT_LIMIT = 20


class NVDProviderError(Exception):
    """Raised when the NVD provider cannot complete a search."""


def get_english_description(descriptions: list[dict[str, Any]]) -> str:
    """Return the English CVE description when one is available."""
    for description in descriptions:
        if description.get("lang") == "en":
            return str(description.get("value", "No description available."))

    return "No description available."


def get_cvss_details(metrics: dict[str, Any]) -> tuple[float, str]:
    """Return the best available CVSS score and severity from NVD metrics."""
    # Prefer newer CVSS versions when the CVE contains multiple metric types.
    metric_names = (
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    )

    for metric_name in metric_names:
        metric_entries = metrics.get(metric_name, [])
        if not metric_entries:
            continue

        cvss_data = metric_entries[0].get("cvssData", {})
        score = float(cvss_data.get("baseScore", 0.0))
        severity = cvss_data.get("baseSeverity")

        # CVSS v2 stores severity outside the cvssData object.
        if not severity:
            severity = metric_entries[0].get("baseSeverity", "Unknown")

        return score, str(severity).title()

    return 0.0, "Unknown"


def parse_nvd_response(response_data: dict[str, Any]) -> list[dict[str, str | float]]:
    """Convert the NVD response into the project's common CVE format."""
    results: list[dict[str, str | float]] = []

    for vulnerability in response_data.get("vulnerabilities", []):
        cve = vulnerability.get("cve", {})
        cvss, severity = get_cvss_details(cve.get("metrics", {}))
        results.append(
            {
                "cve_id": str(cve.get("id", "Unknown")),
                "cvss": cvss,
                "severity": severity,
                "description": get_english_description(cve.get("descriptions", [])),
                "provider_source": "nvd",
            }
        )

    return results


def search_nvd(
    product: str, version: str, timeout: int | None = None
) -> list[dict[str, str | float]]:
    """Search NVD for CVEs matching a product and version."""
    if not settings.nvd_enabled:
        logger.debug("NVD provider disabled by configuration")
        return []

    keyword = f"{product} {version}".strip()

    # NVD's CVE 2.0 API supports keywordSearch for text matching. Keeping this
    # provider isolated means another provider can be added later without
    # changing the rest of the application.
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": DEFAULT_RESULT_LIMIT,
        "noRejected": "",
    }
    headers = {"User-Agent": "AI-Security-Copilot/1.0"}

    # An optional NVD API key can improve rate limits without changing callers.
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key

    logger.debug("Searching NVD for product=%r version=%r", product, version)
    request_timeout = timeout if timeout is not None else settings.nvd_timeout

    try:
        response = requests.get(
            NVD_API_URL,
            params=params,
            headers=headers,
            timeout=request_timeout,
        )
        response.raise_for_status()
        results = parse_nvd_response(response.json())
        logger.debug("NVD returned %d CVE result(s) for %s", len(results), keyword)
        return results
    except requests.Timeout as error:
        logger.warning("NVD request timed out for %s", keyword)
        raise NVDProviderError("NVD request timed out") from error
    except (requests.RequestException, ValueError, TypeError, KeyError) as error:
        logger.warning("NVD request failed for %s: %s", keyword, error)
        raise NVDProviderError("NVD request failed") from error


def print_nvd_results() -> None:
    """Search NVD for a sample product and print the results."""
    product = "OpenSSH"
    version = "9.6p1"

    try:
        results = search_nvd(product, version)
    except NVDProviderError as error:
        print(f"NVD search failed: {error}")
        return

    if not results:
        print(f"Product: {product}")
        print(f"Version: {version}")
        print("CVE: No NVD results found")
        print("CVSS: 0.0")
        print("Severity: Unknown")
        print("Description: NVD did not return a matching CVE for this query.")
        return

    for cve in results:
        print(f"Product: {product}")
        print(f"Version: {version}")
        print(f"CVE: {cve['cve_id']}")
        print(f"CVSS: {cve['cvss']}")
        print(f"Severity: {cve['severity']}")
        print(f"Description: {cve['description']}")
        print("-" * 50)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")
    print_nvd_results()
