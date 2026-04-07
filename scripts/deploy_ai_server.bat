@echo off
REM ========================================
REM OBSOLETE SCRIPT - DO NOT USE
REM ========================================
setlocal

echo ========================================
echo deploy_ai_server.bat is obsolete
echo ========================================
echo.
echo This script used an outdated backend startup path and should not be
echo used for deployment or local development.
echo.
echo Supported options:
echo.
echo   1. Docker-first local/dev startup:
echo      QUICK_START.bat
echo.
echo   2. Manual backend:
echo      python -m uvicorn --app-dir vm_deployment fastapi_server:app --host 0.0.0.0 --port 5000
echo.
echo   3. Manual frontend:
echo      python -m http.server 8000 --directory vm_deployment
echo.
echo   4. Open UI:
echo      http://localhost:8000/nexus.html
echo.
echo For packaged/EXE-style local serving, use:
echo      vm_deployment\launcher.py
echo.
pause
exit /b 1
