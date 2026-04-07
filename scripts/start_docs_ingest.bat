@echo off
REM ========================================
REM NEXUS - MikroTik Docs Ingest
REM ========================================
cd /d "%~dp0"

echo [INGEST] Using training dir: %ROS_TRAINING_DIR%
if "%ROS_TRAINING_DIR%"=="" (
  set "ROS_TRAINING_DIR=%CD%\ros-migration-trainer-v3"
  echo [INGEST] ROS_TRAINING_DIR not set, defaulting to %ROS_TRAINING_DIR%
)

echo [PY] Ensuring dependencies...
py -3.11 -m pip install -r requirements.txt --no-input --disable-pip-version-check

echo [INGEST] Fetching MikroTik docs into training dir...
set "ROS_TRAINING_DIR=%ROS_TRAINING_DIR%"
py -3.11 docs_ingest.py

echo [RELOAD] Asking backend to reload training (if running)...
curl -s -X POST http://127.0.0.1:5000/api/reload-training >nul 2>&1 && echo [RELOAD] Reload request sent || echo [RELOAD] Backend not responding, start it then run reload.

echo [DONE]
pause


