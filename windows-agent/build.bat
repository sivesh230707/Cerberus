@echo off
rem Cerberus Windows Agent Build Script (Batch)
setlocal enabledelayedexpansion

set SCRIPT_DIR=%~dp0
set BIN_DIR=%SCRIPT_DIR%bin
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"

set OUTPUT_EXE=%BIN_DIR%\CerberusAgent.exe
set CSC_PATH=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe

if not exist "%CSC_PATH%" (
    set CSC_PATH=C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe
)

if not exist "%CSC_PATH%" (
    echo [ERROR] Could not find csc.exe.
    exit /b 1
)

echo Compiling CerberusAgent.exe...
"%CSC_PATH%" /nologo /target:exe /platform:x64 /optimize+ /warn:1 /out:"%OUTPUT_EXE%" "%SCRIPT_DIR%AssemblyInfo.cs" "%SCRIPT_DIR%JobObjectWrapper.cs" "%SCRIPT_DIR%ResponseAgent.cs" "%SCRIPT_DIR%EtwListener.cs" "%SCRIPT_DIR%Program.cs"

if %ERRORLEVEL% equ 0 (
    echo [SUCCESS] CerberusAgent.exe built successfully at %OUTPUT_EXE%
    "%OUTPUT_EXE%" --help
    exit /b 0
) else (
    echo [ERROR] Compilation failed.
    exit /b %ERRORLEVEL%
)
