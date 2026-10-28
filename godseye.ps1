#!/usr/bin/env pwsh
<#
.SYNOPSIS
    God's Eye (Eye of Horus) - Zero-Config Windows & Cross-Platform PowerShell Launcher
    Automatically creates .venv and installs dependencies on first run.
#>
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING = "utf-8"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$VenvPython = Join-Path $ScriptDir ".venv\Scripts\python.exe"
$VenvPythonUnix = Join-Path $ScriptDir ".venv/bin/python"

if (-not (Test-Path $VenvPython) -and -not (Test-Path $VenvPythonUnix)) {
    Write-Host "[*] God's Eye: First-time zero-config setup - creating virtual environment..." -ForegroundColor Cyan
    $VenvDir = Join-Path $ScriptDir ".venv"
    if (Get-Command py -ErrorAction SilentlyContinue) {
        & py -m venv $VenvDir
    } elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
        & python3 -m venv $VenvDir
    } else {
        & python -m venv $VenvDir
    }

    $TargetPy = if (Test-Path $VenvPython) { $VenvPython } else { $VenvPythonUnix }
    if (Test-Path $TargetPy) {
        Write-Host "[*] God's Eye: Installing OSINT engine dependencies automatically..." -ForegroundColor Cyan
        & $TargetPy -m pip install --quiet --upgrade pip
        & $TargetPy -m pip install --quiet fastapi uvicorn httpx pydantic pydantic-settings rich typer truststore
    }
}

if (Test-Path $VenvPython) {
    & $VenvPython -m godseye @args
} elseif (Test-Path $VenvPythonUnix) {
    & $VenvPythonUnix -m godseye @args
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    & py -m godseye @args
} else {
    & python -m godseye @args
}
