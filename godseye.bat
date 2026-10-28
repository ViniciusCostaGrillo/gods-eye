@echo off
REM ============================================================================
REM  God's Eye (Eye of Horus) - Zero-Config Windows CMD Launcher
REM  Auto-provisions .venv and dependencies on first run if needed.
REM ============================================================================
chcp 65001 >nul 2>&1
set PYTHONIOENCODING=utf-8
set SCRIPT_DIR=%~dp0

if not exist "%SCRIPT_DIR%.venv\Scripts\python.exe" (
    echo [*] God's Eye: First-time zero-config setup - creating virtual environment...
    where py >nul 2>&1
    if %ERRORLEVEL% EQU 0 (
        py -m venv "%SCRIPT_DIR%.venv"
    ) else (
        python -m venv "%SCRIPT_DIR%.venv"
    )
    if exist "%SCRIPT_DIR%.venv\Scripts\python.exe" (
        echo [*] God's Eye: Installing dependencies automatically...
        "%SCRIPT_DIR%.venv\Scripts\python.exe" -m pip install --quiet --upgrade pip
        "%SCRIPT_DIR%.venv\Scripts\python.exe" -m pip install --quiet fastapi uvicorn httpx pydantic pydantic-settings rich typer truststore
    )
)

if exist "%SCRIPT_DIR%.venv\Scripts\python.exe" (
    "%SCRIPT_DIR%.venv\Scripts\python.exe" -m godseye %*
) else (
    py -m godseye %* 2>nul || python -m godseye %*
)
