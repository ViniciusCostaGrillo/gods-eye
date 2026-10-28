#!/usr/bin/env bash
# ============================================================================
#  𓂀 God's Eye — One-Click Zero-Config Installer for Linux & Kali Linux
# ============================================================================
set -e
export PYTHONIOENCODING="utf-8"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "======================================================================"
echo "  𓂀 GOD'S EYE — ZERO-CONFIG AUTOMATIC INSTALLER (LINUX / KALI)"
echo "======================================================================"

# 1. Install python3-venv and Noto Hieroglyphs font if apt is available
if command -v apt-get >/dev/null 2>&1; then
    echo "[1/4] Checking system packages (python3-venv, fonts-noto-core)..."
    if ! dpkg -s python3-venv >/dev/null 2>&1; then
        sudo apt-get update -qq && sudo apt-get install -y -qq python3-venv python3-pip fonts-noto-core
    fi
fi

# 2. Create .venv & install dependencies
if [ ! -x "${SCRIPT_DIR}/.venv/bin/python" ]; then
    echo "[2/4] Creating isolated virtual environment (.venv)..."
    python3 -m venv "${SCRIPT_DIR}/.venv"
fi

echo "[3/4] Installing OSINT engine dependencies..."
"${SCRIPT_DIR}/.venv/bin/python" -m pip install --quiet --upgrade pip
"${SCRIPT_DIR}/.venv/bin/python" -m pip install --quiet -e "${SCRIPT_DIR}"
chmod +x "${SCRIPT_DIR}/godseye.sh"

# 3. Symlink to /usr/local/bin/godseye or ~/.local/bin/godseye
if [ -w "/usr/local/bin" ]; then
    ln -sf "${SCRIPT_DIR}/godseye.sh" /usr/local/bin/godseye
    echo "      ✔ Linked /usr/local/bin/godseye"
elif command -v sudo >/dev/null 2>&1; then
    sudo ln -sf "${SCRIPT_DIR}/godseye.sh" /usr/local/bin/godseye
    echo "      ✔ Linked /usr/local/bin/godseye"
else
    mkdir -p "${HOME}/.local/bin"
    ln -sf "${SCRIPT_DIR}/godseye.sh" "${HOME}/.local/bin/godseye"
    echo "      ✔ Linked ${HOME}/.local/bin/godseye"
fi

echo "[4/4] Running zero-config self-check (godseye doctor)..."
"${SCRIPT_DIR}/.venv/bin/python" -m godseye doctor

echo ""
echo "[✔] 𓂀 God's Eye is 100% ready! Type 'godseye' or 'godseye menu' in any terminal."
