# Architecture

AI Security Copilot is organized as a modular pipeline. Each stage has a focused responsibility and can be tested independently.

## End-to-End Flow

```text
Nmap Upload
    |
    v
Parser
    |
    v
CVE Engine
    |
    +--> NVD Provider
    |
    +--> Local Fallback Database
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

`app.py` exposes the Flask dashboard and `/upload` route. The upload workflow:

1. Accepts `.xml` files only.
2. Enforces a maximum upload size.
3. Saves uploads to `uploads/`.
4. Parses XML safely with `lxml`.
5. Confirms the root tag is `nmaprun`.
6. Sends the uploaded path into the analysis pipeline.

### Parser

`parser/nmap_parser.py` extracts:

- IP address
- Port
- Service name
- Product
- Version

The parser disables XML entity resolution and network access.

### CVE Engine

`cve/real_cve_lookup.py` is the common provider interface used by the rest of the app.

Provider order:

1. Normalize the product name.
2. Query the official NVD API through `cve/nvd_provider.py`.
3. If NVD fails or returns no matches, use `cve/cve_lookup.py` as local fallback.

All providers return the same structure:

```python
{
    "cve_id": "CVE-...",
    "cvss": 7.5,
    "severity": "High",
    "description": "..."
}
```

### Risk Engine

`risk/risk_assessor.py` converts CVSS scores into risk ratings:

- `0.0 - 3.9`: Low
- `4.0 - 6.9`: Medium
- `7.0 - 8.9`: High
- `9.0 - 10.0`: Critical

### AI Analysis

`ai/security_analyst.py` combines parser output, CVE data, and risk ratings. It currently uses local security explanations and is structured so an Ollama provider can be added later.

When no CVE is found, the service is still stored as an informational `NO-CVE-MATCH` finding.

### SQLite

`database/db.py` stores findings in `database/security.db`.

The uniqueness rule uses:

```text
ip_address + port + cve
```

This prevents duplicate rows when the same scan is analyzed multiple times.

### Dashboard

`templates/index.html` displays:

- Upload form
- Total hosts
- Total findings
- Critical findings
- High findings
- Risk-colored findings table

The dashboard reads persisted data from SQLite.

### PDF Report

`reports/pdf_generator.py` builds `reports/security_report.pdf` with:

- Executive Summary
- Findings
- Risk Ratings
- Recommendations
- Conclusion

### Configuration

`config.py` centralizes paths, upload limits, NVD settings, logging level, and Flask secret configuration.

### Automated Quality Gates

The test suite lives in `tests/` and covers:

- XML parsing
- CVE provider fallback
- Risk rating boundaries
- SQLite persistence
- Flask dashboard and upload workflow
- PDF generation

GitHub Actions runs dependency validation, compile checks, tests, and Bandit security scanning.
