@echo off
title NEXUS - Docker Stop
color 0C

cd /d "%~dp0.."

where docker >nul 2>nul
if %errorlevel% neq 0 (
  echo Docker is not installed or not on PATH.
  pause
  exit /b 1
)

echo Stopping NEXUS containers...
docker compose down
pause

