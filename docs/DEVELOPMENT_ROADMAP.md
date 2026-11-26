# Development Roadmap — Web Guard AI

1. **Phase 1–2 (Foundation & Architecture)**: Monorepo structure, environment templates, Docker Compose stack, documentation, and database schema design.
2. **Phase 3–4 (Core Backend & Frontend Shell)**: FastAPI app, JWT auth, RBAC, SQLAlchemy models, Alembic migrations, React dark SaaS dashboard shell.
3. **Phase 5 (Daily Threat Intelligence)**: NVD, CISA KEV, CVE Program, GitHub Security Advisories, Vendor & OWASP collectors with Celery Beat daily sync.
4. **Phase 6 (Authorized Domain Scanner)**: Ownership verification, SSRF/rebinding guards, DNS/TLS/header/CORS/cookie/fingerprint/endpoint engines.
5. **Phase 7 (Source Code Scanner)**: AST analysis, Bandit, Semgrep integration, custom rules, ZIP/GitHub/folder ingestion, dependency scanner.
6. **Phase 8 (AI Vulnerability Validation)**: Multi-stage evidence pipeline reducing false positives (`CONFIRMED`, `POTENTIAL`, `NEEDS REVIEW`, `NOT REPRODUCED`).
7. **Phase 9 (CVE Correlation)**: Technology fingerprint to CVE affected-version matching engine.
8. **Phase 10 (Remediation & Verification)**: Diff preview, explicit approval, backup creation, patch application, automated post-fix re-scan.
9. **Phase 11 (Reports & Scan History)**: Executive & technical reports (JSON/Markdown/HTML) and scan history explorer.
10. **Phase 12 (Verification & Hardening)**: Comprehensive unit, integration, security, and API test suites plus CI/CD workflow.
