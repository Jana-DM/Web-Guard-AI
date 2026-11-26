# Setup Guide — Web Guard AI

## Prerequisites
- Python 3.11+ (tested on Python 3.14)
- Node.js 20+ and npm 10+
- Optional for full containerized stack: Docker & Docker Compose

## Quick Local Setup

### Windows (PowerShell)
```powershell
.\scripts\setup.ps1
```

### Linux / macOS
```bash
chmod +x scripts/setup.sh scripts/run_dev.sh
./scripts/setup.sh
```

## Running Locally
1. Start the backend API:
   ```bash
   cd backend
   # Windows: .\.venv\Scripts\uvicorn app.main:app --reload --port 8000
   uvicorn app.main:app --reload --port 8000
   ```
2. Start the frontend dev server:
   ```bash
   cd frontend
   npm run dev
   ```
3. Open `http://localhost:5173`.

## Running with Docker Compose
```bash
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env
docker compose up --build
```
Services started:
- `postgres` (PostgreSQL 16)
- `redis` (Redis 7)
- `backend` (FastAPI + Uvicorn)
- `celery_worker` (Async scanning, validation, remediation, reports)
- `celery_beat` (Daily CVE & advisory sync)
- `frontend` (Production Vite/Nginx bundle)
- `nginx` (Unified reverse proxy on port 80)

## Running Tests
```bash
cd backend
.\.venv\Scripts\pytest -v
```
