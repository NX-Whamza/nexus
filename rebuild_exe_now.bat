@echo off
echo ========================================
echo Rebuilding NEXUS.exe
echo ========================================
echo.

cd /d "%~dp0"

echo Cleaning old build files...
if exist dist\NEXUS.exe del /F /Q dist\NEXUS.exe
if exist build rmdir /s /q build
if exist __pycache__ rmdir /s /q __pycache__

echo.
echo Starting build...
echo.

python build_exe.py

echo.
echo ========================================
echo Build completed!
echo ========================================
echo.

if exist dist\NEXUS.exe (
    echo EXE file found at: dist\NEXUS.exe
    for %%F in (dist\NEXUS.exe) do (
        echo File size: %%~zF bytes
        echo Last modified: %%~tF
    )
) else (
    echo ERROR: EXE file not found!
)

pause
