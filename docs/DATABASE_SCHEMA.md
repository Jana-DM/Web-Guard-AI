# Database Schema — Web Guard AI

All 15 core tables are defined with SQLAlchemy 2.0 ORM models under `backend/app/models/` and managed via Alembic migrations in `backend/app/database/migrations/`.

| Table | Model File | Purpose |
|---|---|---|
| `users` | `user.py` | Accounts, hashed passwords (`bcrypt`), roles (`admin`, `analyst`, `viewer`), active status |
| `projects` | `project.py` | Logical grouping for targets, scans, and findings owned by a user |
| `authorized_targets` | `authorized_target.py` | Domains/repositories with scope configuration and authorization status |
| `target_verifications` | `authorized_target.py` | Verification tokens (`dns_txt`, `http_well_known`, `signed_authorization`), expiry, and check results |
| `scan_jobs` | `scan_job.py` | Scan execution lifecycle (`queued`, `running`, `completed`, `failed`), target reference, progress |
| `scan_results` | `scan_result.py` | Structured raw summary outputs per scan job (DNS, TLS, headers, file counts) |
| `technology_fingerprints` | `scan_result.py` | Detected frameworks, servers, libraries, and versions linked to scans |
| `vulnerabilities` | `vulnerability.py` | Normalized findings with severity, CVSS, CWE, classification, confidence score, and status |
| `evidence_records` | `evidence.py` | Concrete proof artifacts (HTTP snippets, AST lines, rule matches, version proof) |
| `cve_intelligence` | `cve.py` | Daily synced CVE catalog with CVSS, CISA KEV status, affected ranges, and deduplication hash |
| `security_advisories` | `advisory.py` | Vendor, GitHub, and OWASP advisories cross-linked to CVEs |
| `sync_logs` | `advisory.py` | Execution history of daily intelligence synchronization runs |
| `remediation_records` | `remediation.py` | Original vs. proposed patches, backup paths, approval state, timestamps |
| `verification_results` | `remediation.py` | Post-remediation re-scan outcomes, regression checks, and final status |
| `audit_logs` | `audit_log.py` | Immutable security audit trail for auth, authorization, scans, and remediation approvals |
