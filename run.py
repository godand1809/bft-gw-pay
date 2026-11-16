#!/usr/bin/env python3
"""
run.py -- Entry point for the BFT QR Pay server.

VERSION: 1.0.0

Usage:
    python run.py                 # http://127.0.0.1:8000
    PORT=8080 python run.py       # custom port
"""
import os

import uvicorn

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run("app.main:app", host="127.0.0.1", port=port, reload=False)
