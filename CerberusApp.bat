@echo off
title Cerberus Desktop
cd /d "%~dp0"

set VENV_PY=%USERPROFILE%\.gemini\antigravity-ide\scratch\cerberus\.venv\Scripts\python.exe

if exist "%VENV_PY%" (
    "%VENV_PY%" desktop_app.py
) else (
    python desktop_app.py
)
