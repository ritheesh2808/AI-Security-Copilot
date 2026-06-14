# AI Security Copilot

![Python](https://img.shields.io/badge/Python-3.11+-blue)
![Flask](https://img.shields.io/badge/Flask-3.x-black)
![SQLite](https://img.shields.io/badge/SQLite-Database-lightgrey)
![CI](https://img.shields.io/badge/CI-GitHub%20Actions-success)
![Security](https://img.shields.io/badge/Security-Bandit-success)
![Version](https://img.shields.io/badge/Version-v1.1.0-green)

A security analysis platform that imports Nmap XML scans, enriches discovered services with CVE intelligence, performs risk assessment, stores historical findings, and generates PDF security reports.

---

## Key Features

### Scan Processing

* Import Nmap XML scan results
* Secure XML validation and parsing
* Automatic host and service extraction
* Historical scan storage

### Vulnerability Intelligence

* Official NVD API integration
* Local CVE fallback database
* CVE source tracking
* CVSS score enrichment

### Risk Assessment

* Automated risk classification
* Critical, High, Medium, and Low severity mapping
* Security impact summaries
* Remediation recommendations

### Dashboard

* Flask-based web interface
* Security findings overview
* Historical scan browsing
* Individual scan detail pages

### Reporting

* PDF report generation
* Executive-friendly findings summaries
* Structured vulnerability reporting

### Engineering Quality

* Automated unit tests
* GitHub Actions CI pipeline
* Security scanning with Bandit
* Modular architecture
* Configuration management
* Environment-based settings

---

## Architecture

```text
Nmap XML Upload
        |
        v
  Scan Creation
        |
        v
   XML Parser
        |
        v
 Host Discovery
        |
        v
Service Discovery
        |
        v
 CVE Intelligence
   /         \
 NVD API   Local DB
        |
        v
 Risk Engine
        |
        v
 AI Analysis
        |
        v
 SQLite Storage
     /      \
    v        v
Dashboard  PDF Report
```

Detailed documentation:

docs/architecture.md

---

## Project Structure

```text
AI-Security-Copilot/
│
├── ai/
├── cve/
├── database/
├── docs/
├── parser/
├── reports/
├── risk/
├── scans/
├── screenshots/
├── scripts/
├── templates/
├── tests/
│
├── app.py
├── config.py
├── requirements.txt
├── requirements-dev.txt
├── version.py
└── README.md
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/ritheesh2808/AI-Security-Copilot.git
cd AI-Security-Copilot
```

Create a virtual environment:

```bash
python -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Verify requirements:

```bash
python scripts/check_requirements.py
```

Initialize the database:

```bash
python database/db.py
```

---

## Configuration

Environment variables:

```text
SECRET_KEY
NVD_API_KEY
NVD_ENABLED
DATABASE_PATH
UPLOAD_FOLDER
MAX_UPLOAD_SIZE
LOG_LEVEL
```

Offline demonstration mode:

```bash
export NVD_ENABLED=false
python app.py
```

---

## Running The Application

Start the dashboard:

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

---

## Available Routes

| Route           | Purpose          |
| --------------- | ---------------- |
| /               | Main Dashboard   |
| /upload         | Upload Nmap Scan |
| /history        | Historical Scans |
| /scan/<scan_id> | Scan Details     |

---

## Testing

Run all tests:

```bash
python -m unittest discover -s tests
```

Dependency validation:

```bash
python scripts/check_requirements.py
```

Security scan:

```bash
bandit -r . -x ./venv,./tests
```

---

## Screenshots

Add screenshots before showcasing the project publicly.

Recommended screenshots:

* Dashboard Overview
* Upload Workflow
* Scan History
* Scan Details
* PDF Report Preview

Place images inside:

```text
screenshots/
```

---

## Security Considerations

* XML parsing is performed with external entities disabled.
* Uploaded files are validated before processing.
* Runtime artifacts are excluded from Git.
* NVD requests include timeout handling.
* Local CVE fallback ensures continued functionality.

---

## Roadmap

### Planned Enhancements

* Docker deployment
* Gunicorn production setup
* CISA KEV integration
* EPSS scoring integration
* Authentication and authorization
* Scan comparison engine
* Remediation workflow tracking
* Ollama-powered local security assistant

---

## Technologies Used

* Python
* Flask
* SQLite
* Nmap
* NVD API
* ReportLab
* lxml
* Requests
* Bootstrap
* GitHub Actions
* Bandit

---

## Version

Current Release:

```text
v1.1.0
```

---

## Author

Ritheesh MG

Cyber Security Engineering Student

GitHub:

https://github.com/ritheesh2808

---

## License

This project is released under the MIT License.
