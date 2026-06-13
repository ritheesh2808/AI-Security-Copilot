"""Tests for CVE provider behavior."""

import unittest
from unittest.mock import patch

from cve.nvd_provider import NVDProviderError, parse_nvd_response
from cve.real_cve_lookup import lookup_real_cves, normalize_product_name


class CVEProviderTests(unittest.TestCase):
    """Validate NVD parsing and local fallback behavior."""

    def test_normalize_product_name(self) -> None:
        self.assertEqual(normalize_product_name("apache HTTP server"), "Apache httpd")
        self.assertEqual(normalize_product_name(" openssh "), "OpenSSH")

    def test_parse_nvd_response(self) -> None:
        response = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2030-0001",
                        "descriptions": [{"lang": "en", "value": "Example issue."}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 7.5,
                                        "baseSeverity": "HIGH",
                                    }
                                }
                            ]
                        },
                    }
                }
            ]
        }

        self.assertEqual(
            parse_nvd_response(response),
            [
                {
                    "cve_id": "CVE-2030-0001",
                    "cvss": 7.5,
                    "severity": "High",
                    "description": "Example issue.",
                    "provider_source": "nvd",
                }
            ],
        )

    def test_nvd_failure_uses_local_fallback(self) -> None:
        with patch(
            "cve.real_cve_lookup.search_nvd",
            side_effect=NVDProviderError("offline"),
        ):
            results = lookup_real_cves("Apache httpd", "2.4.58")

        self.assertEqual(results[0]["cve_id"], "CVE-2024-12345")


if __name__ == "__main__":
    unittest.main()
