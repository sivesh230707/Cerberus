# Cerberus Dashboard Launcher
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $scriptDir

$venvPy = "$env:USERPROFILE\.gemini\antigravity-ide\scratch\cerberus\.venv\Scripts\python.exe"

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host " Starting Cerberus Sandbox Localhost Server" -ForegroundColor Cyan
Write-Host " Dashboard: http://127.0.0.1:8000" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Cyan

if (Test-Path $venvPy) {
    & $venvPy -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
} else {
    python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
}
