#!/bin/bash

echo "[*] Setting up NATASHA environment..."

# Ensure Python 3
if ! command -v python3 &>/dev/null; then
    echo "[-] Python3 not found. Please install Python 3.9+"
    exit 1
fi

# Create virtual environment
if [ ! -d "natasha-venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv natasha-venv
fi

# Activate venv
source natasha-venv/bin/activate

# Upgrade pip
echo "[*] Upgrading pip..."
pip install --upgrade pip

# Install requirements
echo "[*] Installing dependencies..."
pip install -r requirements.txt

# Create required directories
echo "[*] Creating directories..."
mkdir -p logs
touch logs/events.json

echo "[✓] Setup complete"
echo "[*] Activate with: source natasha-venv/bin/activate"
echo "[*] Run with: python natasha.py"
