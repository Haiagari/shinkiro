#!/bin/bash

# OzyRecon v6.0 - Advanced Setup Wizard (Phantom Blade Edition)
# -------------------------------------------------------------

set -e # Exit on error

echo "🧠 OzyRecon v6.0 — Advanced Setup (Phantom Blade)"
echo "-------------------------------------------------------------"

# 1. Check Python version
echo "[+] Checking Python version..."
if ! command -v python3 &> /dev/null; then
    echo "[-] Error: Python3 is not installed."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
echo "[*] Found Python $PYTHON_VERSION"

# 2. Check and Create Virtual Environment
if [ ! -d "venv" ]; then
    echo "[+] Creating virtual environment..."
    python3 -m venv venv
else
    echo "[*] Virtual environment already exists."
fi

# 3. Activate and Install
echo "[+] Activating environment and installing dependencies..."
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .

# 4. Configure Environment Variables
if [ ! -f ".env" ]; then
    echo "[+] Initializing .env from example..."
    cp .env.example .env
    echo "[!] IMPORTANT: Edit the .env file with your Shodan/Censys API keys."
else
    echo "[*] .env file already exists."
fi

# 5. Create necessary directories
echo "[+] Creating data and evidence directories..."
mkdir -p data evidence assets

# 6. Final Verification (v6.0 Stealth Check)
echo "-------------------------------------------------------------"
echo "[+] Running system & stealth check..."
if python3 -c "import src; import curl_cffi; print('✅ OzyRecon v6.0 Stealth Layer Loaded')" &> /dev/null; then
    echo "💎 OzyRecon v6.0 Setup Complete!"
    echo ""
    echo "To start your operation, run:"
    echo "  source venv/bin/activate"
    echo "  ./ozy.py"
else
    echo "❌ Stealth Layer failed (check curl_cffi installation)."
    exit 1
fi
