@echo off
REM ========================================
REM AI SERVER DEPLOYMENT SCRIPT
REM Deploy NOC Config Maker AI Server
REM ========================================
set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%..") do set "REPO_ROOT=%%~fI"
cd /d "%REPO_ROOT%"

echo ========================================
echo NOC AI SERVER DEPLOYMENT
echo ========================================
echo.
echo This will set up your PC as a dedicated AI server
echo accessible from anywhere on your network.
echo.
echo Features:
echo - Smart model selection (phi3:mini, qwen2.5-coder:7b)
echo - MikroTik documentation integration
echo - Nextlink standards training
echo - Network access from any device
echo - Auto-start on boot
echo ========================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [✓] Running as administrator
) else (
    echo [!] Please run as administrator for full setup
    echo     Right-click and "Run as administrator"
    pause
    exit /b 1
)

echo [1/8] Installing Python 3.11...
winget install Python.Python.3.11 --accept-package-agreements --accept-source-agreements
if %ERRORLEVEL% NEQ 0 (
    echo [!] Python installation failed. Please install manually from python.org
    pause
    exit /b 1
)

if %ERRORLEVEL% NEQ 0 (
    pause
    exit /b 1
)

timeout /t 5 /nobreak >nul

echo [4/8] Downloading AI models...

echo [5/8] Installing Python dependencies...
py -3.11 -m pip install --upgrade pip
py -3.11 -m pip install -r requirements.txt

echo [6/8] Setting up network access...
netsh advfirewall firewall add rule name="NOC AI Server" dir=in action=allow protocol=TCP localport=5000
netsh advfirewall firewall add rule name="NOC AI Server WebUI" dir=in action=allow protocol=TCP localport=3000

echo [7/8] Creating auto-start service...
echo @echo off > "%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\start_ai_server.bat"
echo cd /d "%REPO_ROOT%" >> "%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\start_ai_server.bat"
echo timeout /t 10 /nobreak ^>nul >> "%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\start_ai_server.bat"
echo set ROS_TRAINING_DIR=%CD%\ros-migration-trainer-v3 >> "%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\start_ai_server.bat"
echo py -3.11 -m uvicorn --app-dir vm_deployment fastapi_server:app --host 0.0.0.0 --port 5000 >> "%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\start_ai_server.bat"

echo [8/8] Starting AI server...
set ROS_TRAINING_DIR=%CD%\ros-migration-trainer-v3

echo [CHAT] Initializing chat history database...
py -3.11 -c "import sqlite3; conn = sqlite3.connect('chat_history.db'); conn.close(); print('Chat database ready')"

echo [MEMORY] Chat history and user preferences will be saved
echo [CONTEXT] AI will remember conversations across sessions
echo [EXPORT] Chat history can be exported via API

py -3.11 -m uvicorn --app-dir vm_deployment fastapi_server:app --host 0.0.0.0 --port 5000

echo ========================================
echo AI SERVER DEPLOYMENT COMPLETE!
echo ========================================
echo.
echo Your AI server is now running on:
echo   - AI API: http://YOUR_IP:5000/v1
echo   - Health: http://YOUR_IP:5000/api/health
echo.
echo To find your IP address, run: ipconfig
echo.
echo The server will auto-start on boot.
echo You can access it from any device on your network!
echo ========================================
pause
