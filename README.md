# AI Security Copilot

AI Security Copilot is a Python security-analysis dashboard for pentesters. It imports Nmap XML scans, extracts discovered services, enriches them with CVE data, calculates risk, generates beginner-friendly security analysis, persists findings in SQLite, displays results in Flask, and creates PDF assessment reports.

Current version: `0.10.0`

## Features

- Safe Nmap XML upload workflow with file type, size, and XML structure validation
- Nmap parser built with `lxml` using network-disabled XML parsing
- Common CVE provider interface with official NVD API integration
- Local fallback CVE database when NVD is unavailable or returns no results
- CVSS-to-risk engine for Low, Medium, High, and Critical ratings
- Local AI-style security analysis with impact and recommendation text
- SQLite persistence with duplicate-safe upserts
- Bootstrap dashboard with summary cards and risk color coding
- PDF report generation with ReportLab
- Standard-library automated tests
- GitHub Actions CI with compile, tests, dependency validation, and Bandit security scan

## Architecture

```text
Nmap XML Upload
       |
       v
   XML Parser
       |
       v
   CVE Provider
   /         \
NVD API   Local Fallback
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

More detail is available in [docs/architecture.md](docs/architecture.md).

## Project Structure

```text
AI-Security-Copilot/
├── ai/                 # Local security analysis layer
├── cve/                # NVD and local CVE providers
├── database/           # SQLite persistence helpers
├── docs/               # Architecture and project documentation
├── parser/             # Nmap XML parser
├── reports/            # PDF report generator
├── risk/               # CVSS risk rating logic
├── scans/              # Sample scan data
├── scripts/            # Maintenance and validation scripts
├── templates/          # Flask HTML templates
├── tests/              # Automated test suite
├── uploads/            # Local uploaded scans, ignored by Git
├── app.py              # Flask dashboard entry point
├── config.py           # Central configuration
└── version.py          # Project version
```

## Installation

1. Clone the repository:

   ```bash
   git clone <repository-url>
   cd AI-Security-Copilot
   ```

2. Create and activate a virtual environment:

   ```bash
   python -m venv venv
   source venv/bin/activate
   ```

3. Install runtime dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Validate dependencies:

   ```bash
   python scripts/check_requirements.py
   ```

5. Initialize SQLite:

   ```bash
   python database/db.py
   ```

## Configuration

Configuration is read in [config.py](config.py). Useful environment variables:

```text
SECRET_KEY       Flask secret key for sessions and flash messages
FLASK_DEBUG      Set true to enable Flask debug mode locally
MAX_UPLOAD_BYTES Maximum upload size in bytes, default 5242880
NVD_API_KEY      Optional NVD API key for better rate limits
NVD_TIMEOUT      NVD request timeout in seconds, default 15
NVD_ENABLED      Set false to disable live NVD lookups
LOG_LEVEL        Logging level, default INFO
```

For local offline development, run commands with:

```bash
NVD_ENABLED=false python app.py
```

## Usage

Start the Flask dashboard:

```bash
python app.py
```

Open:

[http://127.0.0.1:5000](http://127.0.0.1:5000)

Upload an Nmap `.xml` file. The app will parse, analyze, store, and display findings.

Run individual modules:

```bash
python parser/nmap_parser.py
python cve/nvd_provider.py
python cve/real_cve_lookup.py
python risk/risk_assessor.py
python ai/security_analyst.py
python reports/pdf_generator.py
```

Generate a PDF report:

```bash
python reports/pdf_generator.py
```

Output:

```text
reports/security_report.pdf
```

## Testing

Run all automated tests:

```bash
python -m unittest discover -s tests
```

Run core validation commands:

```bash
python scripts/check_requirements.py
python -m compileall -q .
```

## Screenshots

Add dashboard screenshots to `screenshots/` before publishing the portfolio page.

Suggested screenshots:

- Dashboard summary cards
- Nmap upload form
- Findings table
- Generated PDF report preview

## Security Notes

- Uploaded XML is parsed with network access and entity resolution disabled.
- Uploads are limited by file extension, maximum size, and expected Nmap root tag.
- Runtime artifacts such as uploads, SQLite files, PDFs, virtual environments, and bytecode are ignored by Git.
- The NVD provider has timeout and exception handling with local fallback.

## Future Roadmap

- Add authenticated user accounts
- Store scan history and remediation status
- Add provider adapters for additional CVE sources
- Add Ollama-backed optional security analysis
- Add Docker and production WSGI deployment files
- Add richer PDF branding and screenshots
- Add type checking with mypy or pyright

## Technologies Used

- Python
- Flask
- SQLite
- lxml
- requests
- ReportLab
- Bootstrap
- Nmap XML
- GitHub Actions
