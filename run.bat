@echo off
title Web Guard AI Launcher
echo ============================================================
echo           Starting Web Guard AI (Backend + Frontend)
echo ============================================================

set ROOT=%~dp0

echo [1/2] Starting Backend Server (FastAPI on Port 8000)...
start "Web Guard AI - Backend" cmd /k "cd /d %ROOT%backend && .venv\Scripts\activate && uvicorn app.main:app --reload --port 8000"

echo [2/2] Starting Frontend Server (Vite on Port 5173)...
start "Web Guard AI - Frontend" cmd /k "cd /d %ROOT%frontend && npm run dev"

timeout /t 3 >nul
echo.
echo Opening browser at http://localhost:5173 ...
start http://localhost:5173

echo.
echo ============================================================
echo  Web Guard AI is now running!
echo  - Frontend: http://localhost:5173
echo  - Backend API: http://localhost:8000
echo ============================================================
pause
