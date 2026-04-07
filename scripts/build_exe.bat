@echo off
REM ========================================
REM NEXUS - Executable Builder
REM ========================================
setlocal enabledelayedexpansion
cd /d "%~dp0"
for %%I in ("%~dp0..") do set "REPO_ROOT=%%~fI"
cd /d "%REPO_ROOT%"

echo ========================================
echo NEXUS - Executable Builder
echo ========================================
echo.

REM Resolve Python runner
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

REM Check if requirements are installed
echo [1/3] Checking dependencies...
%PY_CMD% -c "import flask" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [1/3] Installing Python dependencies...
    %PY_CMD% -m pip install -r requirements.txt
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Failed to install dependencies
        pause
        exit /b 1
    )
)

REM Check PyInstaller
echo [2/3] Checking PyInstaller...
%PY_CMD% -c "import PyInstaller" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [2/3] Installing PyInstaller...
    %PY_CMD% -m pip install pyinstaller
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Failed to install PyInstaller
        pause
        exit /b 1
    )
)

REM Build executable
echo [3/3] Building executable...
echo This may take several minutes...
echo.

%PY_CMD% build_exe.py

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo Build Complete!
    echo ========================================
    echo.
    echo Executable location: dist\NEXUS.exe
    echo.
    echo You can now distribute this .exe file.
    echo Users can run it without installing Python.
    echo.
) else (
    echo.
    echo ========================================
    echo Build Failed!
    echo ========================================
    echo Check errors above.
    echo.
)

pause

