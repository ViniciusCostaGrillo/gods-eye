#!/usr/bin/env pwsh
<#
.SYNOPSIS
    God's Eye (Eye of Horus) - Zero-Config CLI Installer for Windows (CMD & PowerShell)
#>
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING = "utf-8"
$ErrorActionPreference = "Stop"

$ScriptDir = (Split-Path -Parent $MyInvocation.MyCommand.Definition).TrimEnd('\')
$VenvScripts = Join-Path $ScriptDir ".venv\Scripts"
$VenvPython = Join-Path $VenvScripts "python.exe"

Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host "  GOD'S EYE - ZERO-CONFIG CLI INSTALLER (WINDOWS CMD & POWERSHELL)" -ForegroundColor Yellow
Write-Host "======================================================================`n" -ForegroundColor Cyan

# 1. Create .venv if missing
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

# 2. Install dependencies & native godseye.exe CLI entry point
Write-Host "[2/4] Installing OSINT engine packages & native godseye CLI..." -ForegroundColor Cyan
& $VenvPython -m pip install --quiet --upgrade pip
& $VenvPython -m pip install --quiet fastapi uvicorn httpx pydantic pydantic-settings rich typer truststore
& $VenvPython -m pip install --quiet -e $ScriptDir

# 3. Register CLI in WindowsApps (instant PATH) + User PATH + PowerShell $PROFILE
Write-Host "[3/4] Registering 'godseye' CLI globally for CMD and PowerShell..." -ForegroundColor Cyan
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not $UserPath) { $UserPath = "" }
$Parts = [System.Collections.Generic.List[string]]($UserPath -split ";" | Where-Object { $_ -ne "" })
foreach ($p in @($ScriptDir, $VenvScripts)) {
    if (-not ($Parts -contains $p)) {
        $Parts.Add($p)
    }
}
[Environment]::SetEnvironmentVariable("Path", ($Parts -join ";"), "User")
$env:Path = "$env:Path;$ScriptDir;$VenvScripts"

# Place shim in %LOCALAPPDATA%\Microsoft\WindowsApps so 'godseye' works immediately in any open CMD/PowerShell
$WinAppsDir = Join-Path $env:LOCALAPPDATA "Microsoft\WindowsApps"
if (Test-Path $WinAppsDir) {
    $CmdShim = Join-Path $WinAppsDir "godseye.cmd"
    $LauncherBat = Join-Path $ScriptDir "godseye.bat"
    Set-Content -Path $CmdShim -Value "@echo off`r`ncall `"$LauncherBat`" %*" -Encoding ASCII
}

$ProfileDir = Split-Path -Parent $PROFILE
if (-not (Test-Path $ProfileDir)) {
    New-Item -ItemType Directory -Path $ProfileDir -Force | Out-Null
}
$LauncherPs1 = Join-Path $ScriptDir "godseye.ps1"
$ProfileBlock = @"
# --- God's Eye (Eye of Horus) OSINT CLI ---
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
`$env:PYTHONIOENCODING = "utf-8"
function godseye { & "$LauncherPs1" @args }
"@
if (-not (Test-Path $PROFILE)) {
    Set-Content -Path $PROFILE -Value $ProfileBlock -Encoding UTF8
} else {
    $CurrentProfile = Get-Content -Path $PROFILE -Raw -ErrorAction SilentlyContinue
    if ($CurrentProfile -notmatch "God's Eye") {
        Add-Content -Path $PROFILE -Value "`n$ProfileBlock" -Encoding UTF8
    }
}

# 4. Run CLI self-diagnostics (godseye doctor)
Write-Host "[4/4] Verifying CLI installation (godseye doctor)..." -ForegroundColor Cyan
& $VenvPython -m godseye doctor

Write-Host "`n[OK] 'godseye' CLI is installed! Run 'godseye' or 'godseye scan <target>' in any CMD or PowerShell terminal." -ForegroundColor Green
