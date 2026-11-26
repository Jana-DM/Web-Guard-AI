# Project Overview — Web Guard AI

## Purpose
Web Guard AI is an AI-powered continuous cybersecurity intelligence and vulnerability assessment platform built around a strict engineering principle: **accuracy and verifiable evidence take precedence over alert volume**.

## Core Modules
1. **Daily Vulnerability Intelligence Engine**
   - Collects, normalizes, deduplicates, and stores CVE and security advisory feeds from NVD, CVE Program, CISA KEV, GitHub Security Advisories, Vendor Advisories, and OWASP resources.
   - Scheduled via Celery Beat with full `sync_logs` auditability.
2. **Authorized Domain Security Scanner**
   - Enforces ownership verification (DNS TXT, HTTP token, or signed authorization) and scope boundaries prior to active assessment.
   - Protects against SSRF, DNS rebinding, private IP scanning, and unsafe redirects.
   - Performs DNS, TLS, header, cookie, CORS, technology fingerprinting, endpoint discovery, and safe non-destructive OWASP checks.
3. **Source Code Security Scanner**
   - Scans Python, JavaScript, and TypeScript across single files, directories, ZIP archives (zip-slip protected), and public GitHub repositories.
   - Executes static AST inspection, Bandit, Semgrep (when available), custom security rules, and dependency manifest/lockfile auditing without executing uploaded code.
4. **Multi-Stage AI Vulnerability Validation**
   - Pipeline: Detection → Context Analysis → Cross Validation → Evidence Collection → Confidence Assessment → Classification (`CONFIRMED`, `POTENTIAL`, `NEEDS REVIEW`, `NOT REPRODUCED`).
   - Ensures AI reasoning never confirms a finding without concrete recorded evidence.
5. **CVE Correlation Engine**
   - Evaluates detected technology fingerprints and versions against official CVE affected-version ranges using semantic/PEP-440 version comparison.
6. **Remediation & Verification Engine**
   - Generates grounded source-code fixes with explicit diff preview and mandatory user approval.
   - Creates backups, applies patches, and automatically re-scans to confirm remediation and detect regressions.
7. **Reporting & Auditability**
   - Produces JSON, Markdown, and HTML security reports alongside immutable audit logs.
