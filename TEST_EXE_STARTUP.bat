@echo off
REM ========================================
REM Test NEXUS.exe Startup
REM ========================================
title NEXUS - Startup Test
color 0B

echo ========================================
echo  NEXUS - Startup Tester
echo ========================================
echo.
echo This script will:
echo   1. Kill any running instances
echo   2. Clear ports 5000 and 8000
echo   3. Run the EXE with visible console
echo   4. Show you what SHOULD happen
echo.
echo ========================================
echo.

REM Step 1: Kill any existing instances
echo [1/4] Checking for existing instances...
taskkill /F /IM "NEXUS.exe" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [1/4] Killed existing NEXUS.exe
) else (
    echo [1/4] No existing instances found
)
timeout /t 2 /nobreak >nul

REM Step 2: Check ports
echo [2/4] Checking ports 5000 and 8000...
netstat -ano | findstr ":5000" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [2/4] WARNING: Port 5000 is in use!
    echo [2/4] Finding process...
    for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":5000"') do (
        echo [2/4] Killing process ID: %%a
        taskkill /F /PID %%a >nul 2>&1
    )
) else (
    echo [2/4] Port 5000 is available
)

netstat -ano | findstr ":8000" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [2/4] WARNING: Port 8000 is in use!
    echo [2/4] Finding process...
    for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8000"') do (
        echo [2/4] Killing process ID: %%a
        taskkill /F /PID %%a >nul 2>&1
    )
) else (
    echo [2/4] Port 8000 is available
)

timeout /t 2 /nobreak >nul

REM Step 3: Check if EXE exists
echo [3/4] Checking for EXE file...
if exist "dist\NEXUS.exe" (
    echo [3/4] Found: dist\NEXUS.exe
    for %%A in ("dist\NEXUS.exe") do echo [3/4] Size: %%~zA bytes
) else (
    echo [3/4] ERROR: dist\NEXUS.exe not found!
    echo [3/4] Please run: python build_exe.py
    pause
    exit /b 1
)

echo.
echo ========================================
echo  EXPECTED BEHAVIOR
echo ========================================
echo.
echo When you run the EXE, you should see:
echo.
echo 1. A console window with this banner:
echo    ╔════════════════════════════════════╗
echo    ║  NOC CONFIG MAKER - UNIFIED APP    ║
echo    ║    Backend + AI + Frontend         ║
echo    ╚════════════════════════════════════╝
echo.
echo 2. Startup messages:
echo    [BACKEND] Starting API server on port 5000...
echo    [FRONTEND] Starting web server on port 8000...
echo.
echo 3. Service status summary:
echo    Backend API:  ✓ READY - http://localhost:5000
echo    Frontend:     ✓ READY - http://localhost:8000/nexus.html
echo.
echo 4. Browser opens automatically to:
echo    http://localhost:8000/nexus.html
echo.
echo 5. Console stays open with message:
echo    "Application is running. Keep this window open."
echo    "Press Ctrl+C to stop all services."
echo.
echo ========================================
echo.
echo [4/4] Starting NEXUS.exe NOW...
echo       Watch the console for startup messages!
echo.
echo ========================================
timeout /t 3 /nobreak

REM Step 4: Run the EXE
cd /d "%~dp0"
start "NEXUS" "dist\NEXUS.exe"

echo.
echo ========================================
echo  EXE STARTED
echo ========================================
echo.
echo CHECK:
echo   - Did a NEW console window open?
echo   - Does it show the startup banner?
echo   - Did backend start? (look for "[BACKEND] Started successfully")
echo   - Did browser open to localhost:8000?
echo.
echo If you DON'T see these:
echo   1. Check the new console window for errors
echo   2. Try running: QUICK_START.bat
echo   3. Or manually: python vm_deployment\\launcher.py
echo.
echo ========================================
pause

