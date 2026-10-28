#!/usr/bin/env pwsh
<#
.SYNOPSIS
    God's Eye (Eye of Horus) - One-Click Zero-Config Installer for Windows (CMD, PowerShell, Desktop & Start Menu)
#>
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING = "utf-8"
$ErrorActionPreference = "Stop"

$ScriptDir = (Split-Path -Parent $MyInvocation.MyCommand.Definition).TrimEnd('\')
$VenvScripts = Join-Path $ScriptDir ".venv\Scripts"
$VenvPython = Join-Path $VenvScripts "python.exe"

Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host "  GOD'S EYE - ZERO-CONFIG AUTOMATIC INSTALLER (WINDOWS)" -ForegroundColor Yellow
Write-Host "======================================================================`n" -ForegroundColor Cyan

# 1. Create .venv if missing
if (-not (Test-Path $VenvPython)) {
    Write-Host "[1/5] Creating isolated Python virtual environment (.venv)..." -ForegroundColor Cyan
    if (Get-Command py -ErrorAction SilentlyContinue) {
        & py -m venv (Join-Path $ScriptDir ".venv")
    } else {
        & python -m venv (Join-Path $ScriptDir ".venv")
    }
} else {
    Write-Host "[1/5] Virtual environment (.venv) already present." -ForegroundColor Green
}

# 2. Install dependencies & native godseye.exe entry point
Write-Host "[2/5] Installing OSINT engine packages & native godseye.exe..." -ForegroundColor Cyan
& $VenvPython -m pip install --quiet --upgrade pip
& $VenvPython -m pip install --quiet fastapi uvicorn httpx pydantic pydantic-settings rich typer truststore
& $VenvPython -m pip install --quiet -e $ScriptDir

# 3. Register both project root and .venv\Scripts in Windows User PATH
Write-Host "[3/5] Registering God's Eye in Windows User PATH & PowerShell Profile..." -ForegroundColor Cyan
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

# 4. Create Desktop and Start Menu Shortcuts
Write-Host "[4/5] Creating Desktop and Start Menu shortcuts ('God's Eye OSINT')..." -ForegroundColor Cyan
$WshShell = New-Object -ComObject WScript.Shell
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$StartMenuPath = [Environment]::GetFolderPath("Programs")
$LauncherBat = Join-Path $ScriptDir "godseye.bat"

foreach ($Folder in @($DesktopPath, $StartMenuPath)) {
    if ($Folder -and (Test-Path $Folder)) {
        $ShortcutFile = Join-Path $Folder "God's Eye OSINT.lnk"
        $Shortcut = $WshShell.CreateShortcut($ShortcutFile)
        $Shortcut.TargetPath = "cmd.exe"
        $Shortcut.Arguments = "/k `"chcp 65001 >nul && `"$LauncherBat`"`""
        $Shortcut.WorkingDirectory = $ScriptDir
        $Shortcut.Description = "God's Eye (Eye of Horus) - OSINT Cybersecurity Platform"
        $Shortcut.Save()
    }
}

# 5. Run self-diagnostics (godseye doctor)
Write-Host "[5/5] Running zero-config self-check (godseye doctor)..." -ForegroundColor Cyan
& $VenvPython -m godseye doctor

Write-Host "`n[OK] God's Eye is installed on your PC! Open any CMD, PowerShell, or click the Desktop shortcut 'God's Eye OSINT'." -ForegroundColor Green
