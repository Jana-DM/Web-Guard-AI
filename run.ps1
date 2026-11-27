# Web Guard AI - Single Command Runner
$root = $PSScriptRoot

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "       Starting Web Guard AI (Backend + Frontend)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

Write-Host "`n[1/2] Starting Backend (FastAPI on http://localhost:8000)..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$root\backend'; .\.venv\Scripts\uvicorn.exe app.main:app --reload --port 8000"

Write-Host "[2/2] Starting Frontend (React on http://localhost:5173)..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$root\frontend'; npm run dev"

Start-Sleep -Seconds 3
Write-Host "`nOpening Web Guard AI in browser..." -ForegroundColor Yellow
Start-Process "http://localhost:5173"

Write-Host "`nBoth servers started successfully! Press Ctrl+C in their respective windows to stop." -ForegroundColor Cyan
