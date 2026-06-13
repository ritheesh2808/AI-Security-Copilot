# AI Security Copilot

## Project Overview

AI Security Copilot is a beginner-friendly pentesting assistant that converts Nmap XML scans into structured security findings. It parses discovered services, looks up CVEs, calculates risk ratings, generates local security analysis, stores results in SQLite, displays them in a Flask dashboard, and creates PDF assessment reports.

The current AI analysis uses local explanations and does not send scan data to external APIs.

## Features

- Upload and safely validate Nmap XML scans
- Parse host, port, product, service, and version information
- Look up vulnerabilities through a common CVE provider with local fallback data
- Calculate Low, Medium, High, and Critical risk ratings from CVSS scores
- Generate local impact analysis and remediation recommendations
- Persist findings in SQLite without creating duplicate records
- Review findings through a Bootstrap Flask dashboard
- Generate PDF security assessment reports

## Architecture Diagram

```text
Nmap XML Upload
       |
       v
   XML Parser
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
      /   \
     v     v
Dashboard PDF Report
```

See [docs/architecture.md](docs/architecture.md) for additional details.

## Installation Instructions

1. Clone the repository and enter the project directory:

   ```bash
   git clone <repository-url>
   cd AI-Security-Copilot
   ```

2. Create and activate a virtual environment:

   ```bash
   python -m venv venv
   source venv/bin/activate
   ```

3. Install the dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Initialize the SQLite database:

   ```bash
   python database/db.py
   ```

## Usage Instructions

Start the Flask dashboard:

```bash
python app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000), select an Nmap `.xml` file, and click **Upload and Analyze**.

Run individual modules from the project root:

```bash
python parser/nmap_parser.py
python cve/real_cve_lookup.py
python risk/risk_assessor.py
python ai/security_analyst.py
python reports/pdf_generator.py
```

Generated reports are saved locally to `reports/security_report.pdf`.

## Screenshots

Project screenshots will be added to the `screenshots/` directory.

## Future Roadmap

- Connect the common CVE provider to a live vulnerability API
- Add optional Ollama-powered security analysis
- Track scan history and remediation status
- Add authentication and role-based dashboard access
- Export findings in additional formats
- Add automated tests and continuous integration
- Prepare production deployment configuration

## Technologies Used

- Python
- Flask
- SQLite
- lxml
- ReportLab
- Bootstrap
- Nmap XML
