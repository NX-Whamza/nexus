@echo off
REM ========================================
REM NEXUS - Unified Backend Startup
REM Starts all required backend services in one script
REM ========================================
setlocal enabledelayedexpansion
set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%..") do set "REPO_ROOT=%%~fI"
cd /d "%REPO_ROOT%"

echo ========================================
echo NEXUS - Unified Backend Startup
echo ========================================
echo.
echo This script will start:
echo   1. Backend API (port 5000)
echo   2. HTML Frontend Server (port 8000)
echo.
echo ========================================
echo.

REM ===== Resolve Python Runner =====
set "PY_CMD="
if exist "%REPO_ROOT%\.venv\Scripts\python.exe" (
    set "PY_CMD=%REPO_ROOT%\.venv\Scripts\python.exe"
) else (
    py -3.13 --version >nul 2>&1
    if %ERRORLEVEL% EQU 0 (
        set "PY_CMD=py -3.13"
    ) else (
        py -3.11 --version >nul 2>&1
        if %ERRORLEVEL% EQU 0 (
            set "PY_CMD=py -3.11"
        ) else (
            python --version >nul 2>&1
            if %ERRORLEVEL% EQU 0 set "PY_CMD=python"
        )
    )
)

if not defined PY_CMD (
    echo [ERROR] No supported Python runtime found
    echo Install Python 3.11 or 3.13, or create .venv in the repo root
    pause
    exit /b 1
)
echo [INFO] Using Python runner: %PY_CMD%

REM ===== Step 1: Start Backend API =====
echo [1/2] Starting Backend API...

REM Check if backend is already running
curl -s http://localhost:5000/api/health >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [1/2] WARNING: Backend API is already running on port 5000
    echo [1/2]    Skipping startup to avoid conflicts
) else (
    echo [1/2] Launching FastAPI backend (uvicorn)...
    start "NOC Backend API" /min cmd /c "cd /d %REPO_ROOT% && %PY_CMD% -m uvicorn --app-dir vm_deployment fastapi_server:app --host 0.0.0.0 --port 5000"
    echo [1/2] Waiting for backend to initialize...
    timeout /t 5 /nobreak >nul
    
    REM Verify backend started
    curl -s http://localhost:5000/api/health >nul 2>&1
    if %ERRORLEVEL% EQU 0 (
        echo [1/2] Backend API started successfully
    ) else (
        echo [1/2] NOTE: Backend may still be starting (check window for errors)
    )
)
echo.

REM ===== Step 2: Start HTML Frontend Server =====
echo [2/2] Starting HTML Frontend Server...
REM Check if frontend is already running
curl -s http://localhost:8000/nexus.html >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [2/2] WARNING: Frontend server is already running on port 8000
    echo [2/2]    Skipping startup to avoid conflicts
) else (
    echo [2/2] Launching builtin HTTP server for vm_deployment\...
    start "NOC HTML Frontend" /min cmd /c "cd /d %REPO_ROOT% && %PY_CMD% -m http.server 8000 --directory vm_deployment"
    echo [2/2] Waiting for frontend to initialize...
    timeout /t 2 /nobreak >nul
    echo [2/2] Frontend server started
)
echo.

REM ===== Get IP Address for Network Access =====
echo ========================================
echo Service Status Summary
echo ========================================
echo.
echo Backend Services:
echo   Backend API:   http://localhost:5000
echo   Frontend:      http://localhost:8000/nexus.html
echo.

REM Try to get local IP address (multiple methods)
set "LOCAL_IP="
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /i /c:"IPv4"') do (
    set "ip_line=%%a"
    set "ip_line=!ip_line:~1!"
    for /f "tokens=1" %%b in ("!ip_line!") do (
        set "LOCAL_IP=%%b"
        goto :found_ip
    )
)
:found_ip
if defined LOCAL_IP (
    echo Network Access (for coworkers):
    echo   Frontend:      http://%LOCAL_IP%:8000/nexus.html
    echo   Backend API:   http://%LOCAL_IP%:5000/api
    echo.
) else (
    echo Network Access:
    echo   Run 'ipconfig' to find your IP address
    echo   Then use: http://YOUR_IP:8000/nexus.html
    echo.
)

echo ========================================
echo.
echo [INFO] All services are running in separate windows
echo [INFO] Close those windows to stop the services
echo.
echo [NOTE] If coworkers can't access from network:
echo        1. Run setup_network_access.bat as Administrator
echo        2. Or manually allow ports 5000 and 8000 in Windows Firewall
echo.
echo ========================================
echo.
echo Press any key to close this window...
pause >nul
endlocal
exit /b 0
