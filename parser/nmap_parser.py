"""Parse service information from an Nmap XML scan."""

import logging
from pathlib import Path

from lxml import etree


logger = logging.getLogger(__name__)

# Build the scan path from this file so the script works from any directory.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SCAN_PATH = PROJECT_ROOT / "scans" / "sample_scan.xml"


def parse_nmap_scan(scan_path: Path) -> list[dict[str, str | int]]:
    """Return a dictionary for every port with service information."""
    scan_path = Path(scan_path).resolve()
    logger.info("Parsing Nmap XML file: %s", scan_path)

    # Disable network access while parsing because scan files are untrusted input.
    xml_parser = etree.XMLParser(no_network=True, resolve_entities=False)
    tree = etree.parse(str(scan_path), xml_parser)
    results: list[dict[str, str | int]] = []
    hosts = tree.xpath("/nmaprun/host")

    # Each host owns its IP addresses and the ports discovered by Nmap.
    for host in hosts:
        ipv4_addresses = host.xpath("./address[@addrtype='ipv4']/@addr")
        ip_address = ipv4_addresses[0] if ipv4_addresses else "Unknown"

        for port in host.xpath("./ports/port"):
            service = port.find("service")
            service_name = (
                service.get("name", "Unknown") if service is not None else "Unknown"
            )
            results.append(
                {
                    "ip_address": ip_address,
                    "port": int(port.get("portid", "0")),
                    "service_name": service_name,
                    # Some Nmap services, such as tcpwrapped, have no product.
                    "product": service.get("product", service_name)
                    if service is not None
                    else service_name,
                    "version": service.get("version", "Unknown")
                    if service is not None
                    else "Unknown",
                }
            )

    logger.info("Parsed host count: %d", len(hosts))
    logger.info("Parsed service count: %d", len(results))
    return results


def main() -> None:
    """Parse the sample scan and print each result as a Python dictionary."""
    for result in parse_nmap_scan(DEFAULT_SCAN_PATH):
        print(result)


if __name__ == "__main__":
    main()
