#!/usr/bin/env pwsh
<#
.SYNOPSIS
    𓂀 God's Eye — Windows & Cross-Platform PowerShell Launcher
#>
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING = "utf-8"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$VenvPython = Join-Path $ScriptDir ".venv\Scripts\python.exe"
$VenvPythonUnix = Join-Path $ScriptDir ".venv/bin/python"

if (Test-Path $VenvPython) {
    & $VenvPython -m godseye @args
} elseif (Test-Path $VenvPythonUnix) {
    & $VenvPythonUnix -m godseye @args
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    & py -m godseye @args
} else {
    & python -m godseye @args
}
