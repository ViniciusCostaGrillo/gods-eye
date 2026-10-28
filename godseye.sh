#!/usr/bin/env bash
# ============================================================================
#  𓂀 God's Eye — Zero-Config Linux / Kali Linux / macOS Bash Launcher
#  Automatically creates .venv and installs dependencies on first run.
# ============================================================================
set -e
export PYTHONIOENCODING="utf-8"
export LC_ALL="${LC_ALL:-C.UTF-8}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -x "${SCRIPT_DIR}/.venv/bin/python" ] && [ ! -x "${SCRIPT_DIR}/.venv/Scripts/python.exe" ]; then
    echo "[*] 𓂀 God's Eye: First-time zero-config setup — creating virtual environment..."
    if command -v python3 >/dev/null 2>&1; then
        python3 -m venv "${SCRIPT_DIR}/.venv"
    else
        python -m venv "${SCRIPT_DIR}/.venv"
    fi
    if [ -x "${SCRIPT_DIR}/.venv/bin/python" ]; then
        echo "[*] 𓂀 God's Eye: Installing OSINT engine dependencies..."
        "${SCRIPT_DIR}/.venv/bin/python" -m pip install --quiet --upgrade pip
        "${SCRIPT_DIR}/.venv/bin/python" -m pip install --quiet -e "${SCRIPT_DIR}"
    fi
fi

if [ -x "${SCRIPT_DIR}/.venv/bin/python" ]; then
    exec "${SCRIPT_DIR}/.venv/bin/python" -m godseye "$@"
elif [ -x "${SCRIPT_DIR}/.venv/Scripts/python.exe" ]; then
    exec "${SCRIPT_DIR}/.venv/Scripts/python.exe" -m godseye "$@"
elif command -v python3 >/dev/null 2>&1; then
    exec python3 -m godseye "$@"
else
    exec python -m godseye "$@"
fi
