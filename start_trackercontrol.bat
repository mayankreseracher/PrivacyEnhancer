@echo off
chcp 65001 >nul
title TrackerControl PC — Sovereign Desktop Privacy Guard
echo ======================================================================
echo    🛡️ TrackerControl PC — Initializing Cyber Defense Engine...
echo ======================================================================
cd /d "%~dp0"

:: Prefer compiled standalone binary if available
if exist "dist\TrackerControl-PC.exe" (
    echo [+] Launching optimized standalone binary...
    start "" "dist\TrackerControl-PC.exe"
    exit /b
)

:: Check Python installation fallback
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH!
    pause
    exit /b
)

:: Run TrackerControl PC via Python
python main.py
pause
