# Cerberus Standalone Desktop Application
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $scriptDir

$venvPy = "$env:USERPROFILE\.gemini\antigravity-ide\scratch\cerberus\.venv\Scripts\python.exe"

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host " Starting Cerberus Native Desktop Application" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

if (Test-Path $venvPy) {
    & $venvPy desktop_app.py
} else {
    python desktop_app.py
}
