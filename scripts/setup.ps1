$ErrorActionPreference = "Stop"

Write-Host "=== Web Guard AI Setup (Windows) ==="

if (-not (Test-Path "backend/.env")) {
    Copy-Item "backend/.env.example" "backend/.env"
    Write-Host "Created backend/.env from template."
}

if (-not (Test-Path "frontend/.env")) {
    Copy-Item "frontend/.env.example" "frontend/.env"
    Write-Host "Created frontend/.env from template."
}

if (-not (Test-Path "backend/.venv")) {
    py -3.14 -m venv backend/.venv
}

& "backend/.venv/Scripts/python.exe" -m pip install --upgrade pip
& "backend/.venv/Scripts/pip.exe" install -r backend/requirements.txt
& "backend/.venv/Scripts/python.exe" scripts/database_init.py

Push-Location frontend
npm install
Pop-Location

Write-Host "Setup complete."
