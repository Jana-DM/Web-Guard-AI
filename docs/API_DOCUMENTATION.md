# API Documentation — Web Guard AI (`/api/v1`)

Interactive OpenAPI/Swagger documentation is served at `/docs` and ReDoc at `/redoc`.

## Authentication (`/api/v1/auth`, `/api/v1/users`)
- `POST /auth/register` — Register a user account (first user or admin-created; returns JWT).
- `POST /auth/login` — Authenticate with email/username and password, returns access + refresh tokens.
- `POST /auth/refresh` — Exchange refresh token for a new access token.
- `GET /users/me` — Retrieve authenticated user profile.

## Dashboard (`/api/v1/dashboard`)
- `GET /dashboard/summary` — Live database metrics (findings by severity & classification, verified targets, recent scans, KEV alerts, last intelligence sync).

## Threat Intelligence & CVE Database (`/api/v1/intelligence`, `/api/v1/cve`)
- `GET /intelligence/overview` — Sync status, feed breakdown, latest advisories, KEV highlights.
- `POST /intelligence/sync` — Trigger manual intelligence synchronization across configured sources.
- `GET /intelligence/sync-logs` — Historical sync runs.
- `GET /cve` — Paginated, filterable CVE search (severity, KEV only, source, query).
- `GET /cve/{cve_id}` — Detailed CVE record with affected versions, references, and grounded AI explanation.
- `POST /cve/correlate` — Run CVE correlation against detected technologies/versions.

## Domain Scanner & Attack Surface (`/api/v1/domain-scans`, `/api/v1/attack-surface`)
- `POST /domain-scans/targets` — Register a domain target and generate a verification challenge token.
- `POST /domain-scans/targets/{id}/verify` — Verify ownership (`dns_txt`, `http_well_known`, or `explicit_authorization`).
- `GET /domain-scans/targets` — List authorized targets and verification state.
- `POST /domain-scans` — Launch non-destructive domain assessment (requires verified/authorized target).
- `GET /domain-scans/{scan_id}` — Retrieve scan status, DNS/TLS/header results, fingerprints, and findings.
- `GET /attack-surface/{target_id}` — Consolidated endpoints, technologies, DNS records, and correlated CVEs.

## Source Code Scanner (`/api/v1/code-scans`)
- `POST /code-scans/upload` — Upload individual files, multi-file sets, or ZIP archives for static analysis.
- `POST /code-scans/github` — Clone (shallow, non-executing) and scan a public GitHub repository.
- `GET /code-scans/{scan_id}` — Detailed SAST findings, dependency issues, and evidence.

## Findings, Validation, Remediation & Verification
- `GET /vulnerabilities` / `GET /vulnerabilities/{id}` — Filterable vulnerabilities with full evidence records.
- `POST /validation/run/{scan_id}` — Execute or re-run multi-stage AI validation pipeline.
- `POST /validation/ai-analyze` — Grounded AI analyst Q&A on specific findings, CVEs, or scan contexts.
- `POST /remediation/generate/{vulnerability_id}` — Generate proposed patch and diff preview.
- `POST /remediation/{id}/approve` — Explicitly approve and apply patch with backup.
- `POST /verification/run/{remediation_id}` — Re-scan patched code and record verification results.

## Reports & Settings (`/api/v1/reports`, `/api/v1/settings`)
- `POST /reports/generate` — Generate JSON, Markdown, or HTML security report for a scan or project.
- `GET /reports/{id}/download` — Download generated report artifact.
- `GET /settings` / `PUT /settings` — View and update scanner safety thresholds and sync schedule configuration.
