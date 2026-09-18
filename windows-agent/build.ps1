# Cerberus Windows Agent Build Script (PowerShell)
# Compiles all C# files using Windows-native C# compiler (csc.exe) into bin\CerberusAgent.exe

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$binDir = Join-Path $scriptDir "bin"
if (!(Test-Path $binDir)) {
    New-Item -ItemType Directory -Path $binDir -Force | Out-Null
}

$outputExe = Join-Path $binDir "CerberusAgent.exe"
$cscPath = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"

if (!(Test-Path $cscPath)) {
    $cscPath = "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"
}

if (!(Test-Path $cscPath)) {
    Write-Error "Could not locate .NET Framework csc.exe compiler."
    exit 1
}

$sourceFiles = @(
    (Join-Path $scriptDir "AssemblyInfo.cs"),
    (Join-Path $scriptDir "JobObjectWrapper.cs"),
    (Join-Path $scriptDir "ResponseAgent.cs"),
    (Join-Path $scriptDir "EtwListener.cs"),
    (Join-Path $scriptDir "Program.cs")
)

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host " Building Cerberus Windows Host Agent" -ForegroundColor Cyan
Write-Host " Compiler: $cscPath" -ForegroundColor Gray
Write-Host " Target:   $outputExe" -ForegroundColor Gray
Write-Host "========================================================" -ForegroundColor Cyan

$manifestFile = Join-Path $scriptDir "app.manifest"

$params = @(
    "/nologo",
    "/target:exe",
    "/platform:x64",
    "/optimize+",
    "/warn:1",
    "/win32manifest:$manifestFile",
    "/out:$outputExe"
) + $sourceFiles

& $cscPath $params

if ($LASTEXITCODE -eq 0 -and (Test-Path $outputExe)) {
    Write-Host "[SUCCESS] CerberusAgent.exe built successfully with UAC manifest (app.manifest)!" -ForegroundColor Green
    Write-Host "Output binary: $outputExe" -ForegroundColor Green
    exit 0
} else {
    Write-Host "[ERROR] Build failed with exit code $LASTEXITCODE." -ForegroundColor Red
    exit 1
}
