@echo off
REM ============================================================================
REM  God's Eye (Eye of Horus) - Windows CMD Launcher
REM  Configures UTF-8 codepage (65001) so the Eye of Horus renders in CMD.exe
REM ============================================================================
chcp 65001 >nul 2>&1
set PYTHONIOENCODING=utf-8
set SCRIPT_DIR=%~dp0

if exist "%SCRIPT_DIR%.venv\Scripts\python.exe" (
    "%SCRIPT_DIR%.venv\Scripts\python.exe" -m godseye %*
) else (
    py -m godseye %* 2>nul || python -m godseye %*
)
