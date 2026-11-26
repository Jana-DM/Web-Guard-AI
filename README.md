# Web Guard AI

**AI-Powered Continuous Cybersecurity Intelligence and Vulnerability Assessment Platform**

Web Guard AI prioritizes **accuracy, reproducibility, and verifiable evidence** over raw alert volume. It combines automated daily threat intelligence synchronization, strictly authorized non-destructive domain assessment, sandboxed multi-language source code analysis, evidence-based AI validation, CVE version correlation, and human-approved remediation with automated post-fix re-verification.

---

## Key Capabilities

1. **Daily Vulnerability Intelligence Engine**
   - Automated scheduled sync via Celery Beat across NVD, CVE Program, CISA KEV, GitHub Security Advisories, Vendor Advisories, and OWASP references.
   - Deduplication, CVSS normalization, affected version tracking, KEV exploitation tagging, and sync audit history.
2. **Authorized Domain Security Scanner**
   - Mandatory domain ownership verification (DNS TXT, HTTP well-known token, or signed authorization record) and explicit scope enforcement before active checks.
   - SSRF protection, private/reserved IP blocking, DNS rebinding guards, safe redirect validation, rate limiting, DNS/TLS inspection, security header/cookie/CORS audits, technology fingerprinting, and non-destructive OWASP checks.
3. **Source Code Security Scanner**
   - Supports Python, JavaScript, and TypeScript via single/multi-file upload, folder upload, ZIP archives (with zip-slip & size guards), and public GitHub repository cloning.
   - Combines Python AST analysis, Bandit, Semgrep (when installed), custom security rules, and dependency manifest/lockfile vulnerability scanning without ever executing untrusted code.
4. **Multi-Stage AI Vulnerability Validation**
   - Pipeline: `Detection -> Context Analysis -> Cross Validation -> Evidence Collection -> Confidence Assessment -> Final Classification` (`CONFIRMED`, `POTENTIAL`, `NEEDS REVIEW`, `NOT REPRODUCED`).
   - Enforces the core rule: *AI hypotheses alone never mark a finding `CONFIRMED`; concrete verifiable evidence is required.*
5. **CVE Correlation Engine**
   - Matches detected domain/code technologies and versions against synced CVE affected-version ranges (`Verified affected configuration`, `Potentially affected`, `Not affected`, `Insufficient information`).
6. **Remediation & Verification Center**
   - Generates grounded code patches showing exact original vs. proposed diffs, requires explicit user approval before modifying stored code, creates timestamped backups, and re-runs targeted + regression scans to confirm resolution.
7. **Executive & Technical Reporting**
   - Generates JSON, Markdown, and HTML/PDF-ready security assessment reports with evidence trails, compliance mappings, and AI-grounded executive summaries.

---

## Architecture Overview

- **Frontend:** React 18, TypeScript, Vite, Tailwind CSS, Lucide Icons, Recharts
- **Backend:** Python, FastAPI, SQLAlchemy 2.0, Pydantic v2, Alembic
- **Database & Broker:** PostgreSQL 16, Redis 7
- **Async Workers:** Celery Worker + Celery Beat
- **Reverse Proxy:** Nginx (production Docker profile)

See the [docs/](docs/) directory for full technical specifications:
- [Project Overview](docs/PROJECT_OVERVIEW.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Database Schema](docs/DATABASE_SCHEMA.md)
- [API Documentation](docs/API_DOCUMENTATION.md)
- [Security Policy](docs/SECURITY_POLICY.md)
- [Development Roadmap](docs/DEVELOPMENT_ROADMAP.md)
- [Setup Guide](docs/SETUP_GUIDE.md)

---

## Quick Start

### Option 1: Docker Compose (Full Stack)
```bash
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env
docker compose up --build
```
- Frontend UI: `http://localhost:5173` (or `http://localhost` via Nginx)
- Backend API & OpenAPI Docs: `http://localhost:8000/docs`

### Option 2: Local Development
Run the setup script for your OS:
- **Windows PowerShell:** `.\scripts\setup.ps1`
- **Linux/macOS:** `./scripts/setup.sh`

Then run backend tests:
```bash
cd backend
.\.venv\Scripts\pytest
```
