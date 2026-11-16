#!/usr/bin/env bash
# run.sh -- convenience launcher (VERSION 1.0.0)
cd "$(dirname "$0")"
python3 -m venv .venv 2>/dev/null || true
source .venv/bin/activate 2>/dev/null || true
pip install -q -r requirements.txt
exec python run.py
