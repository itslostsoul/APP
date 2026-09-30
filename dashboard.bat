@echo off
cd /d "%~dp0dashboard"
python -m pip install -q -r requirements.txt
python app.py
