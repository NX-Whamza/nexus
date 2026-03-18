@echo off
REM Quick Start - Prefer Docker (most consistent); fallback to local Python servers

title NOC Config Maker - Quick Start
color 0E

echo ========================================
echo  NOC Config Maker - Quick Start
echo ========================================
echo.

REM Ensure we run from the repo root even if launched from elsewhere
cd /d "%~dp0"

where docker >nul 2>nul
if %errorlevel%==0 (
  echo Starting via Docker Compose (recommended)...
  echo.
  docker compose up -d --build
  if errorlevel 1 goto :fallback

  echo.
  echo App:     http://localhost:8000/app
  echo Health:  http://localhost:8000/api/health
  echo.
  echo Opening browser...
  start http://localhost:8000/app
  echo.
  echo Tip: Stop everything with: docker compose down
  echo.
  pause
  exit /b 0
)

:fallback
echo.
echo Docker start failed or Docker not found.
echo Falling back to local Python servers (less consistent).
echo.
echo.

REM Start backend in new window
start "NOC Backend" /MIN cmd /c "python -m uvicorn --app-dir vm_deployment fastapi_server:app --host 0.0.0.0 --port 5000"

REM Wait for backend to start
timeout /t 3 /nobreak >nul

REM Start frontend in new window
start "NOC Frontend" cmd /c "python -m http.server 8000 --directory vm_deployment"

REM Wait for frontend to start
timeout /t 3 /nobreak >nul

echo Opening browser...
start http://localhost:8000/NOC-configMaker.html

echo.
echo ========================================
echo  Services Started (Fallback Mode)
echo ========================================
echo Backend:  http://localhost:5000
echo Frontend: http://localhost:8000/NOC-configMaker.html
echo.
echo KEEP THE SERVER WINDOWS OPEN!
echo.

pause

