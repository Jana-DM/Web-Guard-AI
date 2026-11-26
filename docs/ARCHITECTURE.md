# System Architecture — Web Guard AI

## High-Level Topology

```
[ React + Vite + Tailwind UI ]
             |
       HTTPS / REST + WS
             |
       [ Nginx Proxy ]
             |
      [ FastAPI API v1 ] <---> [ PostgreSQL 16 ]
             |
       [ Redis 7 Broker ]
        /              \
[ Celery Worker ]   [ Celery Beat ]
 (Scans, Validation,  (Daily Threat
  Remediation, Reports) Intel Sync)
```

## Backend Layered Design (`backend/app/`)
- **`api/v1/endpoints/`**: Versioned HTTP controllers validating inputs via Pydantic schemas and enforcing RBAC + target authorization.
- **`services/`**: Orchestration layer coordinating database transactions, engines, and asynchronous job dispatch.
- **`engines/`**: Pure, modular domain logic split into six specialized engines:
  - `domain_scanner/`: Target validation, authorization, SSRF/DNS rebinding guard, DNS/TLS/header/CORS/cookie/endpoint/technology analyzers, safe OWASP checks.
  - `code_scanner/`: Safe archive/repo ingestion, language detection, AST analyzer, Bandit runner, Semgrep integration, custom rules, dependency vulnerability scanner.
  - `intelligence/`: Feed collectors (NVD, CVE Program, CISA KEV, GitHub Advisories, Vendor Advisories), normalizer, deduplicator, sync manager.
  - `validation/`: Multi-stage context analyzer, cross-validator, evidence collector, confidence scorer, false-positive filter, finding classifier.
  - `correlation/`: Technology-to-CVE matcher, version range evaluator, exposure analyzer.
  - `remediation/`: Grounded patch generator, backup manager, patch applicator, post-fix verification engine.
- **`ai/`**: Optional LLM client (OpenAI / Gemini / deterministic local fallback) strictly grounded in collected evidence and CVE records.
- **`workers/`**: Celery tasks for asynchronous scans, daily intelligence sync, and report generation.

## Security Boundaries
1. **No Untrusted Code Execution**: Uploaded source files and repositories are parsed statically (AST, regex, JSON/TOML manifest parsing, Bandit/Semgrep static analysis); code is never imported or executed.
2. **SSRF & Network Isolation**: Domain scanner resolves DNS, rejects loopback/private/link-local/reserved IPs, validates every HTTP redirect hop, and enforces per-target rate limits.
3. **Human-in-the-Loop Remediation**: Source code patches remain in `PENDING_APPROVAL` until explicitly approved by an authorized user, with automatic backup before modification and zero automated edits against live remote websites.
