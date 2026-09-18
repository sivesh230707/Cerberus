@echo off
title Cerberus Sandbox Dashboard
cd /d "%~dp0"

echo ========================================================
echo  Starting Cerberus Sandbox & Behavioral Monitor
echo  Dashboard: http://127.0.0.1:8000
echo ========================================================

set VENV_PY=%USERPROFILE%\.gemini\antigravity-ide\scratch\cerberus\.venv\Scripts\python.exe

if exist "%VENV_PY%" (
    "%VENV_PY%" -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
) else (
    python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
)

pause
