# Architecture

AI Security Copilot uses a modular pipeline so each security-processing stage can be developed, tested, and replaced independently.

## Processing Flow

```text
Nmap Upload
    |
    v
Parser
    |
    v
CVE Engine
    |
    v
Risk Engine
    |
    v
AI Analysis
    |
    v
SQLite
   / \
  v   v
Dashboard
      |
      v
PDF Report
```

## Components

### Nmap Upload

The Flask `/upload` route accepts `.xml` files, validates that they contain an Nmap document, and stores them in the local `uploads/` directory before analysis.

### Parser

`parser/nmap_parser.py` safely parses Nmap XML with `lxml`. It extracts IP addresses, ports, service names, products, and versions.

### CVE Engine

`cve/real_cve_lookup.py` provides the common CVE lookup interface. It normalizes product names, supports a future real CVE source, and falls back to the local database in `cve/cve_lookup.py`.

### Risk Engine

`risk/risk_assessor.py` converts CVSS scores into Low, Medium, High, or Critical risk ratings.

### AI Analysis

`ai/security_analyst.py` combines parsed services, CVE results, risk ratings, local impact explanations, and recommendations. Its analysis interface is designed so an Ollama provider can be added later.

### SQLite

`database/db.py` stores findings in `database/security.db`. Its uniqueness rules prevent repeated analysis from creating duplicate host, port, and CVE records.

### Dashboard

`app.py` and `templates/index.html` provide the Flask and Bootstrap dashboard. The dashboard reads persisted findings from SQLite and displays summary metrics and risk-colored results.

### PDF Report

`reports/pdf_generator.py` creates a local PDF assessment report containing an executive summary, findings, risk ratings, recommendations, and conclusion.

## Data Flow Summary

1. A user uploads an Nmap XML scan.
2. The parser extracts discovered services.
3. The CVE engine returns matching vulnerabilities or fallback results.
4. The risk engine calculates risk ratings.
5. The AI analysis module creates impact and remediation guidance.
6. Findings are saved to SQLite.
7. The dashboard displays persisted findings.
8. The PDF generator creates a shareable assessment report.
