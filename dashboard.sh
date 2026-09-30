#!/usr/bin/env bash
cd "$(dirname "$0")/dashboard"
python3 -m pip install -q -r requirements.txt
exec python3 app.py
