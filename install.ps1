#!/usr/bin/env pwsh
<#
.SYNOPSIS
    God's Eye (Eye of Horus) - One-Click Zero-Config Installer for Windows (CMD & PowerShell)
#>
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING = "utf-8"
$ErrorActionPreference = "Stop"

$ScriptDir = (Split-Path -Parent $MyInvocation.MyCommand.Definition).TrimEnd('\')
Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host "  GOD'S EYE - ZERO-CONFIG AUTOMATIC INSTALLER (WINDOWS)" -ForegroundColor Yellow
Write-Host "======================================================================`n" -ForegroundColor Cyan

# 1. Create .venv if missing
$VenvPython = Join-Path $ScriptDir ".venv\Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    Write-Host "[1/4] Creating isolated Python virtual environment (.venv)..." -ForegroundColor Cyan
    if (Get-Command py -ErrorAction SilentlyContinue) {
        & py -m venv (Join-Path $ScriptDir ".venv")
    } else {
        & python -m venv (Join-Path $ScriptDir ".venv")
    }
} else {
    Write-Host "[1/4] Virtual environment (.venv) already present." -ForegroundColor Green
}

# 2. Install dependencies
Write-Host "[2/4] Ensuring all OSINT engine packages are installed..." -ForegroundColor Cyan
& $VenvPython -m pip install --quiet --upgrade pip
& $VenvPython -m pip install --quiet fastapi uvicorn httpx pydantic pydantic-settings rich typer truststore

# 3. Add to Windows User PATH so `godseye` works from any folder in CMD & PowerShell
Write-Host "[3/4] Registering '$ScriptDir' in Windows User PATH..." -ForegroundColor Cyan
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not $UserPath) { $UserPath = "" }
$PathParts = $UserPath -split ";" | Where-Object { $_ -ne "" }
if ($PathParts -notcontains $ScriptDir) {
    $NewUserPath = ($PathParts + $ScriptDir) -join ";"
    [Environment]::SetEnvironmentVariable("Path", $NewUserPath, "User")
    $env:Path = "$env:Path;$ScriptDir"
    Write-Host "      [OK] Added '$ScriptDir' to User PATH!" -ForegroundColor Green
} else {
    Write-Host "      [OK] '$ScriptDir' is already in User PATH." -ForegroundColor Green
}

# 4. Run self-diagnostics (godseye doctor)
Write-Host "[4/4] Running zero-config self-check (godseye doctor)..." -ForegroundColor Cyan
& $VenvPython -m godseye doctor

Write-Host "`n[OK] God's Eye is 100% ready! You can now run 'godseye' from any CMD or PowerShell window." -ForegroundColor Green
