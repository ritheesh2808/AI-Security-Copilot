# Module 11A Migration Report: Database Normalization

## Objective

Module 11A converts AI Security Copilot from a flat `findings` database design into a scan-centric SQLite architecture.

The normalized model separates:

- Scans
- Hosts
- Services
- Findings

This creates a stronger foundation for scan history, scan detail pages, selected-scan reports, provider tracking, and future remediation workflows.

## Status

**Implemented and verified.**

The current `database/db.py` includes all required Module 11A functions:

- `init_db()`
- `create_scan()`
- `create_host()`
- `create_service()`
- `create_finding()`
- `get_scan_history()`
- `get_scan_details()`

It also preserves existing functionality with:

- `save_finding()`
- `get_all_findings()`
- Legacy flat-table migration support

## Schema Created

### `scans`

```sql
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_name TEXT NOT NULL,
    uploaded_filename TEXT NOT NULL,
    scan_timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    source TEXT NOT NULL DEFAULT 'upload',
    notes TEXT NOT NULL DEFAULT ''
);
```

### `hosts`

```sql
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    ip_address TEXT NOT NULL,
    hostname TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    UNIQUE (scan_id, ip_address)
);
```

### `services`

```sql
CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    service_name TEXT NOT NULL DEFAULT 'Unknown',
    product TEXT NOT NULL DEFAULT 'Unknown',
    version TEXT NOT NULL DEFAULT 'Unknown',
    cpe TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
    UNIQUE (host_id, port, protocol)
);
```

### `findings`

```sql
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id INTEGER NOT NULL,
    cve TEXT NOT NULL,
    cvss REAL NOT NULL,
    risk_rating TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'Unknown',
    description TEXT NOT NULL,
    provider_source TEXT NOT NULL DEFAULT 'unknown',
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE,
    UNIQUE (service_id, cve)
);
```

## Indexes Added

```sql
CREATE INDEX IF NOT EXISTS idx_hosts_scan_id ON hosts(scan_id);
CREATE INDEX IF NOT EXISTS idx_services_host_id ON services(host_id);
CREATE INDEX IF NOT EXISTS idx_findings_service_id ON findings(service_id);
CREATE INDEX IF NOT EXISTS idx_findings_risk_rating ON findings(risk_rating);
```

## Backward Compatibility

Existing Module 1-10 behavior is preserved:

- `save_finding()` still accepts the old dictionary-style finding shape.
- `get_all_findings()` still returns dashboard-friendly finding dictionaries.
- If an old flat `findings` table is detected, it is renamed to `legacy_findings_module_1_to_10`.
- Legacy flat findings are imported into the normalized schema under a `Legacy Import` scan.

## Unit Tests Added

Database tests verify:

- Database initialization
- Legacy-compatible `save_finding()`
- Duplicate-safe saves
- Scan creation
- Host creation
- Service creation
- Finding creation
- Scan history aggregation
- Host/service retrieval
- Finding retrieval
- Provider source persistence

## Verification Commands

```bash
python -m unittest discover -s tests
python database/db.py
sqlite3 database/security.db '.tables'
```

## Verification Results

The database initializes successfully:

```text
Database initialized successfully.
```

The normalized tables exist:

```text
scans
hosts
services
findings
```

The local development database also contains:

```text
legacy_findings_module_1_to_10
```

This table is retained only to preserve data from the old Module 1-10 flat schema.

## Notes

This report covers Module 11A only. Flask route and dashboard changes are intentionally not part of this report.
