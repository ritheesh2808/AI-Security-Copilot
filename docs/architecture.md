# Architecture

AI Security Copilot is a scan-centric security analysis pipeline. Module 11 normalizes the database so scans, hosts, services, and findings are tracked as separate records.

## Component Diagram

```text
            +------------------+
            |  Flask Dashboard |
            +---------+--------+
                      |
                      v
            +------------------+
            | Upload Workflow  |
            +---------+--------+
                      |
                      v
+-------------+  +----------+  +----------------+
| Nmap XML    +->+ Parser   +->+ Scan Analyzer  |
+-------------+  +----------+  +-------+--------+
                                      |
                                      v
                         +------------------------+
                         | CVE Provider Interface |
                         +-----+------------+-----+
                               |            |
                               v            v
                          +---------+  +------------+
                          | NVD API |  | Local DB   |
                          +---------+  +------------+
                                      |
                                      v
                              +-------------+
                              | Risk Engine |
                              +------+------+
                                     |
                                     v
                              +-------------+
                              | SQLite DB   |
                              +------+------+
                                     |
                         +-----------+-----------+
                         v                       v
                  +-------------+         +--------------+
                  | Dashboard   |         | PDF Reports  |
                  +-------------+         +--------------+
```

## Data Flow

```text
Upload XML
  -> Validate file extension, size, and nmaprun root
  -> Create scans row
  -> Parse host and service data
  -> Create hosts rows
  -> Create services rows
  -> Query CVE providers
  -> Calculate risk ratings
  -> Create findings rows
  -> Display dashboard/history/details
  -> Generate PDF report when requested
```

## Sequence Flow

```text
User -> Flask /upload
Flask -> SQLite: create_scan()
Flask -> Parser: parse_nmap_scan(uploaded_path)
Parser -> Flask: parsed services
Flask -> Analyzer: build_security_findings(scan_id)
Analyzer -> SQLite: create_host()
Analyzer -> SQLite: create_service()
Analyzer -> CVE Provider: lookup_real_cves()
CVE Provider -> NVD API: search_nvd()
CVE Provider -> Local DB: fallback if needed
Analyzer -> Risk Engine: calculate_risk()
Analyzer -> SQLite: create_finding()
Flask -> User: redirect dashboard with success
```

## Database Diagram

```text
scans
  id PK
  scan_name
  uploaded_filename
  scan_timestamp
  source
  notes
    |
    | 1-to-many
    v
hosts
  id PK
  scan_id FK -> scans.id
  ip_address
  hostname
    |
    | 1-to-many
    v
services
  id PK
  host_id FK -> hosts.id
  port
  protocol
  service_name
  product
  version
  cpe
    |
    | 1-to-many
    v
findings
  id PK
  service_id FK -> services.id
  cve
  cvss
  risk_rating
  severity
  description
  provider_source
```

## Module 11 Notes

Module 11 adds historical scan tracking and database normalization. The app now supports:

- Scan history at `/history`
- Scan detail pages at `/scan/<scan_id>`
- Provider source persistence
- Hostname, protocol, and CPE parsing
- PDF generation from selected scan records through `generate_scan_report(scan_id)`

## Security Controls

- XML parsing disables entity resolution and network access.
- Uploads enforce file size limits.
- SQL uses parameterized queries.
- Runtime artifacts are ignored by Git.
- Bandit security scanning runs in CI.

## Known Future Improvements

- Authentication
- CSRF protection
- CPE-based NVD queries
- Scan diffing
- Remediation status tracking
- Production WSGI deployment
