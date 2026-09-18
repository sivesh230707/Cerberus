@echo off
rem =========================================================
rem Cerberus Test Payload: Clean / Benign Sample
rem Calculates numbers and exits gracefully with ExitCode 0
rem =========================================================

echo [*] Starting Clean Test Calculation...
set /a num1=42
set /a num2=108
set /a total=%num1% + %num2%
echo [*] Calculation result: %total%
echo [*] Execution completed safely.
exit /b 0
