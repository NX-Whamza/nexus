@echo off
REM ========================================
REM NEXUS - Network Access Setup
REM Adds Windows Firewall rules for network access
REM Run this as Administrator
REM ========================================
cd /d "%~dp0"

echo ========================================
echo NEXUS - Network Access Setup
echo ========================================
echo.
echo This script will add Windows Firewall rules to allow:
echo - Port 8000 (HTML frontend)
echo - Port 5000 (API backend)
echo.
echo [NOTE] This requires Administrator privileges
echo.

REM Check if running as admin
net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] This script must be run as Administrator
    echo [!] Right-click and select "Run as administrator"
    pause
    exit /b 1
)

echo [*] Adding firewall rules...

REM Add rule for HTML server (port 8000)
netsh advfirewall firewall delete rule name="NEXUS HTTP Server" >nul 2>&1
netsh advfirewall firewall add rule name="NEXUS HTTP Server" dir=in action=allow protocol=TCP localport=8000
if %ERRORLEVEL% EQU 0 (
    echo [OK] Port 8000 rule added
) else (
    echo [ERROR] Failed to add port 8000 rule
)

REM Add rule for API server (port 5000)
netsh advfirewall firewall delete rule name="NEXUS API Server" >nul 2>&1
netsh advfirewall firewall add rule name="NEXUS API Server" dir=in action=allow protocol=TCP localport=5000
if %ERRORLEVEL% EQU 0 (
    echo [OK] Port 5000 rule added
) else (
    echo [ERROR] Failed to add port 5000 rule
)

echo.
echo ========================================
echo Setup complete!
echo ========================================
echo.
echo Servers should now be accessible from network:
echo - Frontend: http://YOUR_IP:8000/nexus.html
echo - Backend API: http://YOUR_IP:5000
echo.
echo To find your IP address, run: ipconfig
echo.
pause

