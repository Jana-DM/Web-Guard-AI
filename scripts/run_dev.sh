#!/usr/bin/env bash
set -euo pipefail

cleanup() {
  kill 0 || true
}
trap cleanup EXIT

cd backend
source .venv/bin/activate
uvicorn app.main:app --reload --port 8000 &
cd ..

cd frontend
npm run dev &
cd ..

wait
