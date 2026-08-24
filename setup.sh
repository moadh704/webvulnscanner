#!/usr/bin/env bash
# WebVulnScanner - Installation script for Linux / macOS
# Run: bash setup.sh

set -e

cd "$(dirname "$0")"

echo "========================================"
echo "  WebVulnScanner - Installation"
echo "========================================"
echo

if ! command -v python3 &>/dev/null; then
    echo "[ERROR] python3 not found. Install Python 3.8+ and try again."
    exit 1
fi

PYVER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "[INFO] Found Python $PYVER"

echo "[1/4] Creating venv..."
if [ ! -f "venv/bin/python" ]; then
    python3 -m venv venv
fi

# shellcheck source=/dev/null
source venv/bin/activate

echo "[2/4] Installing dependencies..."
python -m pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet

echo "[3/4] Installing wvs..."
pip install -e . --quiet

echo "[4/4] Checking config..."
if [ ! -f "config.py" ] && [ -f "config.example.py" ]; then
    cp config.example.py config.py
fi

echo
echo "Installation complete!"
echo "  Run:  streamlit run app.py"
echo "  Or:   python main.py --help"
echo "  Or:   ./ui.sh  (if created)"
