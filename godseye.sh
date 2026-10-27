#!/usr/bin/env bash
# ============================================================================
#  𓂀 God's Eye — Linux / macOS Bash Launcher
# ============================================================================
set -e
export PYTHONIOENCODING="utf-8"
export LC_ALL="${LC_ALL:-C.UTF-8}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -x "${SCRIPT_DIR}/.venv/bin/python" ]; then
    exec "${SCRIPT_DIR}/.venv/bin/python" -m godseye "$@"
elif [ -x "${SCRIPT_DIR}/.venv/Scripts/python.exe" ]; then
    exec "${SCRIPT_DIR}/.venv/Scripts/python.exe" -m godseye "$@"
elif command -v python3 >/dev/null 2>&1; then
    exec python3 -m godseye "$@"
else
    exec python -m godseye "$@"
fi
