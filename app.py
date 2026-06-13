"""Flask dashboard and Nmap XML upload workflow."""

import logging
from pathlib import Path
from uuid import uuid4

from flask import Flask, flash, redirect, render_template, request, url_for
# lxml is required for this project; parser instances disable entities and network.
from lxml import etree  # nosec B410
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from ai.security_analyst import build_security_findings
from config import configure_logging, settings
from database.db import (
    create_scan,
    get_all_findings,
    get_findings_for_scan,
    get_host_services,
    get_scan_details,
    get_scan_history,
)
from version import __version__


configure_logging()
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config["SECRET_KEY"] = settings.secret_key
app.config["MAX_CONTENT_LENGTH"] = settings.max_upload_bytes
app.config["UPLOAD_FOLDER"] = settings.upload_folder


def get_security_findings() -> list[dict[str, str | float | int]]:
    """Return findings stored in SQLite."""
    return get_all_findings()


def allowed_xml_file(filename: str) -> bool:
    """Return True only when the uploaded filename ends with .xml."""
    return Path(filename).suffix.lower() == ".xml"


def validate_nmap_xml(file_path: Path) -> None:
    """Safely validate that an uploaded file contains Nmap XML."""
    xml_parser = etree.XMLParser(no_network=True, resolve_entities=False)
    tree = etree.parse(str(file_path), xml_parser)  # nosec B320

    if tree.getroot().tag != "nmaprun":
        raise ValueError("The uploaded XML is not an Nmap scan.")


def build_summary(findings: list[dict[str, str | float | int]]) -> dict[str, int]:
    """Calculate the values displayed in the dashboard summary cards."""
    unique_hosts = {str(finding["ip_address"]) for finding in findings}

    return {
        "total_hosts": len(unique_hosts),
        "total_findings": len(findings),
        "critical_findings": sum(
            finding["risk_rating"] == "Critical" for finding in findings
        ),
        "high_findings": sum(
            finding["risk_rating"] == "High" for finding in findings
        ),
    }


@app.route("/")
def index() -> str:
    """Display the security findings dashboard."""
    findings = get_security_findings()
    summary = build_summary(findings)
    return render_template(
        "index.html", findings=findings, summary=summary, version=__version__
    )


@app.route("/history")
def history() -> str:
    """Display historical scan imports."""
    return render_template(
        "history.html", scans=get_scan_history(), version=__version__
    )


@app.route("/scan/<int:scan_id>")
def scan_details(scan_id: int) -> str:
    """Display hosts, services, and findings for one scan."""
    scan = get_scan_details(scan_id)
    if scan is None:
        flash("Scan not found.", "danger")
        return redirect(url_for("history"))

    return render_template(
        "scan_details.html",
        scan=scan,
        services=get_host_services(scan_id),
        findings=get_findings_for_scan(scan_id),
        version=__version__,
    )


@app.route("/upload", methods=["POST"])
def upload_scan():
    """Save, validate, analyze, and persist an uploaded Nmap XML scan."""
    uploaded_file = request.files.get("scan_file")

    if uploaded_file is None or uploaded_file.filename == "":
        flash("Please select an XML scan file.", "danger")
        return redirect(url_for("index"))

    if not allowed_xml_file(uploaded_file.filename):
        flash("Invalid file type. Please upload an .xml file.", "danger")
        return redirect(url_for("index"))

    upload_folder = Path(app.config["UPLOAD_FOLDER"])
    upload_folder.mkdir(parents=True, exist_ok=True)
    safe_name = secure_filename(uploaded_file.filename)
    file_path = upload_folder / f"{uuid4().hex}_{safe_name}"

    try:
        uploaded_file.save(file_path)
        logger.info("Uploaded filename: %s", file_path.resolve())
        validate_nmap_xml(file_path)
        scan_id = create_scan(
            scan_name=safe_name,
            uploaded_filename=safe_name,
            source="upload",
        )
        findings = build_security_findings(
            file_path,
            scan_id=scan_id,
            scan_name=safe_name,
            uploaded_filename=safe_name,
            source="upload",
        )
    except (etree.XMLSyntaxError, OSError, ValueError) as error:
        file_path.unlink(missing_ok=True)
        flash(f"Scan import failed: {error}", "danger")
        return redirect(url_for("index"))

    flash(f"Scan imported successfully. {len(findings)} finding(s) saved.", "success")
    return redirect(url_for("index"))


@app.errorhandler(RequestEntityTooLarge)
def handle_large_upload(error: RequestEntityTooLarge):
    """Redirect oversized uploads back to the dashboard with a safe message."""
    flash("Scan import failed: the XML file must be 5 MB or smaller.", "danger")
    return redirect(url_for("index"))


if __name__ == "__main__":
    # Run the local development dashboard at http://127.0.0.1:5000.
    app.run(debug=settings.flask_debug)
