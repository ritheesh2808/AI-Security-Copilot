# AI Security Copilot

![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![Flask](https://img.shields.io/badge/Flask-3.x-black)
![SQLite](https://img.shields.io/badge/SQLite-Persistence-lightgrey)
![CI](https://img.shields.io/badge/CI-GitHub%20Actions-success)
![Security Scan](https://img.shields.io/badge/Security-Bandit-success)
![License](https://img.shields.io/badge/License-MIT-green)

> Portfolio-grade security analysis dashboard for importing Nmap XML scans, enriching services with CVE intelligence, assessing risk, tracking historical scans, and generating PDF reports.

Current version: `v1.0.0`

## Features

- Safe Nmap XML upload workflow with extension, size, XML, and Nmap-root validation
- Nmap parser for hosts, hostnames, ports, protocols, service names, products, versions, and CPEs
- Official NVD API integration with local CVE fallback
- Provider source tracking: `nvd`, `local_fallback`, and `no_match`
- CVSS-based risk engine
- Local AI-style security analyst summaries, impacts, and recommendations
- Normalized SQLite schema for scans, hosts, services, and findings
- Historical scan dashboard at `/history`
- Scan detail dashboard at `/scan/<scan_id>`
- Bootstrap dashboard with risk-colored findings
- PDF report generation from sample scans or selected scan records
- Automated tests and GitHub Actions CI
- Bandit security scanning

## Architecture Diagram

```text
Nmap XML Upload
       |
       v
Create Scan Record
       |
       v
Parser -> Hosts -> Services
       |
       v
CVE Provider -> NVD API / Local Fallback / No Match
       |
       v
Risk Engine -> AI Analysis
       |
       v
SQLite Findings
       |
       +--> Dashboard
       +--> History
       +--> Scan Details
       +--> PDF Reports
```

More detail is available in [docs/architecture.md](docs/architecture.md).

## Installation

```bash
git clone <repository-url>
cd AI-Security-Copilot
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python scripts/check_requirements.py
python database/db.py
```

## Configuration

Copy `.env.example` or export values directly:

```text
SECRET_KEY       Flask secret key
NVD_API_KEY      Optional NVD API key
UPLOAD_FOLDER    Upload directory
DATABASE_PATH    SQLite database path
MAX_UPLOAD_SIZE  Maximum upload size in bytes
NVD_ENABLED      Set false for offline demos
LOG_LEVEL        Logging level
```

## Usage

Start the dashboard:

```bash
python app.py
```

Open:

[http://127.0.0.1:5000](http://127.0.0.1:5000)

Useful routes:

- `/` - Dashboard
- `/upload` - Upload handler
- `/history` - Historical scans
- `/scan/<scan_id>` - Scan details

Generate a PDF report:

```bash
python reports/pdf_generator.py
```

Run tests:

```bash
python -m unittest discover -s tests
bandit -r . -x ./venv,./tests
```

## Dashboard Screenshots

Screenshots should be added before public portfolio publishing:

- [Dashboard placeholder](screenshots/dashboard-placeholder.md)
- [PDF report placeholder](screenshots/pdf-report-placeholder.md)

## PDF Report Screenshots

Add a PDF preview screenshot to `screenshots/` after generating `reports/security_report.pdf`.

## Security Disclaimer

This project is intended for educational, portfolio, and authorized security assessment workflows only. Do not upload scans from systems you do not own or have permission to test. NVD lookups may send product and version information to an external API; use `NVD_ENABLED=false` for offline demonstrations.

## Contribution Guide

1. Fork the repository.
2. Create a feature branch.
3. Run tests and Bandit.
4. Submit a pull request using the PR template.

```bash
python scripts/check_requirements.py
python -m unittest discover -s tests
bandit -r . -x ./venv,./tests
```

## Future Roadmap

- Authentication and CSRF protection
- CPE-based NVD queries
- CISA KEV and EPSS enrichment
- Remediation tracking
- Scan diffing
- Docker and production WSGI deployment
- Richer PDF branding
- Type checking and coverage reports

## License

This project is released under the [MIT License](LICENSE).
