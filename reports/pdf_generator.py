"""Generate a PDF security assessment report."""

import sys
from collections import Counter
from datetime import datetime
from pathlib import Path


# Add the project root so imports work when this file is run directly.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from ai.security_analyst import build_security_findings
from config import settings


REPORT_PATH = settings.report_path


def build_findings_table(findings: list[dict[str, str | float | int]]) -> Table:
    """Create a table containing the important fields for each finding."""
    rows = [["IP Address", "Port", "Product", "Version", "CVE", "CVSS", "Risk Rating"]]

    for finding in findings:
        rows.append(
            [
                str(finding["ip_address"]),
                str(finding["port"]),
                str(finding["product"]),
                str(finding["version"]),
                str(finding["cve"]),
                str(finding["cvss"]),
                str(finding["risk_rating"]),
            ]
        )

    table = Table(rows, repeatRows=1, colWidths=[30, 15, 35, 25, 35, 18, 27])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#212529")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f2f2")]),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def build_report_content(
    findings: list[dict[str, str | float | int]],
) -> list[object]:
    """Build the sections that will be written to the PDF."""
    styles = getSampleStyleSheet()
    content: list[object] = []
    unique_hosts = {str(finding["ip_address"]) for finding in findings}
    risk_counts = Counter(str(finding["risk_rating"]) for finding in findings)

    content.append(Paragraph("AI Security Copilot Assessment Report", styles["Title"]))
    content.append(
        Paragraph(
            f"Generated: {datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}",
            styles["Normal"],
        )
    )
    content.append(Spacer(1, 8 * mm))

    content.append(Paragraph("Executive Summary", styles["Heading1"]))
    content.append(
        Paragraph(
            f"The assessment reviewed {len(unique_hosts)} host(s) and identified "
            f"{len(findings)} vulnerability finding(s).",
            styles["BodyText"],
        )
    )

    content.append(Paragraph("Findings", styles["Heading1"]))
    if findings:
        content.append(build_findings_table(findings))
    else:
        content.append(Paragraph("No security findings were identified.", styles["BodyText"]))

    content.append(Paragraph("Risk Ratings", styles["Heading1"]))
    for rating in ("Critical", "High", "Medium", "Low"):
        content.append(
            Paragraph(f"{rating}: {risk_counts.get(rating, 0)}", styles["BodyText"])
        )

    content.append(Paragraph("Recommendations", styles["Heading1"]))
    recommendations = dict.fromkeys(str(finding["recommendation"]) for finding in findings)
    if recommendations:
        for recommendation in recommendations:
            content.append(Paragraph(f"- {recommendation}", styles["BodyText"]))
    else:
        content.append(Paragraph("Continue regular security monitoring.", styles["BodyText"]))

    content.append(Paragraph("Conclusion", styles["Heading1"]))
    content.append(
        Paragraph(
            "Prioritize Critical and High findings, apply available security updates, "
            "and validate remediation with a follow-up scan.",
            styles["BodyText"],
        )
    )
    return content


def generate_pdf_report() -> Path:
    """Generate the security assessment PDF and return its file path."""
    findings = build_security_findings()
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)

    document = SimpleDocTemplate(
        str(REPORT_PATH),
        pagesize=landscape(A4),
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        title="AI Security Copilot Assessment Report",
    )
    document.build(build_report_content(findings))
    return REPORT_PATH


if __name__ == "__main__":
    # This test section creates the PDF report using the sample scan findings.
    generate_pdf_report()
    print("PDF report generated successfully.")
