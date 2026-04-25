#!/bin/bash

# OzyRecon v5.7 - Automated Setup Wizard
# -------------------------------------

set -e # Exit on error

echo "🧠 OzyRecon v5.7 — Automated Setup"
echo "-------------------------------------"

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

# 6. Final Verification
echo "-------------------------------------"
echo "[+] Running quick system check..."
if python3 -c "import src; print('OzyRecon modules loaded successfully')" &> /dev/null; then
    echo "✅ Setup Complete!"
    echo ""
    echo "To start, run:"
    echo "  source venv/bin/activate"
    echo "  ozy --help"
else
    echo "❌ Verification failed. Check your installation."
    exit 1
fi
