@echo off
title NEXUS - Docker Local
color 0A

cd /d "%~dp0.."

where docker >nul 2>nul
if %errorlevel% neq 0 (
  echo Docker is not installed or not on PATH.
  echo Install Docker Desktop and try again.
  pause
  exit /b 1
)

echo Starting NEXUS via Docker Compose...
docker compose up -d --build
if errorlevel 1 (
  echo.
  echo ERROR: docker compose failed.
  echo Try: docker compose logs --tail=200
  pause
  exit /b 1
)

echo.
if %errorlevel% neq 0 (
)

echo.
echo App:    http://localhost:8000/app
echo Health: http://localhost:8000/api/health
echo.
start http://localhost:8000/app
pause

