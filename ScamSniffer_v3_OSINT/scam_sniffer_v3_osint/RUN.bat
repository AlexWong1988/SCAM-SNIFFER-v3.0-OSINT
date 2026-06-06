@echo off
title SCAM SNIFFER v3.0 OSINT EDITION
echo.
echo  ================================================
echo   SCAM SNIFFER v3.0 — OSINT EDITION
echo   Singapore Forum ^& Threat Intelligence Scanner
echo  ================================================
echo.
echo   No API key needed. Pure OSINT.
echo.

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found!
    echo         Install Python 3.10+ from https://python.org
    echo         Check "Add Python to PATH" during install.
    echo.
    pause
    exit /b 1
)

echo [*] Launching OSINT Scam Sniffer...
echo.
python "%~dp0scam_sniffer_osint.py"

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Something went wrong. See error above.
    pause
)
