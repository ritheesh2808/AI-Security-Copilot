"""Tests for the Nmap XML parser."""

import unittest

from parser.nmap_parser import DEFAULT_SCAN_PATH, parse_nmap_scan


class NmapParserTests(unittest.TestCase):
    """Validate parsing of the bundled sample Nmap scan."""

    def test_sample_scan_parses_services(self) -> None:
        services = parse_nmap_scan(DEFAULT_SCAN_PATH)

        self.assertEqual(len(services), 3)
        self.assertEqual(services[0]["ip_address"], "192.168.1.10")
        self.assertEqual(services[0]["port"], 22)
        self.assertEqual(services[0]["product"], "OpenSSH")


if __name__ == "__main__":
    unittest.main()
