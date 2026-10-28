@echo off
REM ============================================================================
REM  God's Eye (Eye of Horus) - One-Click Zero-Config Installer for Windows
REM  Sets up .venv, installs packages, and adds God's Eye to User PATH
REM ============================================================================
chcp 65001 >nul 2>&1
set SCRIPT_DIR=%~dp0
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%install.ps1"
