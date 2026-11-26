#!/usr/bin/env bash
set -euo pipefail

echo "=== Web Guard AI Setup ==="

if [ ! -f backend/.env ]; then
  cp backend/.env.example backend/.env
  echo "Created backend/.env from template."
fi

if [ ! -f frontend/.env ]; then
  cp frontend/.env.example frontend/.env
  echo "Created frontend/.env from template."
fi

cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python ../scripts/database_init.py
cd ..

cd frontend
npm install
cd ..

echo "Setup complete."
