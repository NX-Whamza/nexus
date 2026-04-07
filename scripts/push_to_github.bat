@echo off
REM ========================================
REM NEXUS - Push to GitHub
REM ========================================
cd /d "%~dp0"

echo ========================================
echo NEXUS - Push to GitHub
echo ========================================
echo.
echo Your project is ready to push to GitHub!
echo.
echo STEP 1: Create GitHub Repository
echo ========================================
echo 1. Go to https://github.com/new
echo 2. Repository name: nexus
echo 3. Description: AI-powered RouterOS configuration tool with chat memory system
echo 4. Make it PUBLIC
echo 5. DO NOT initialize with README (we already have one)
echo 6. Click "Create repository"
echo.
echo STEP 2: Copy the Repository URL
echo ========================================
echo After creating the repository, GitHub will show you a URL like:
echo https://github.com/YOUR_USERNAME/nexus.git
echo.
echo Copy that URL and paste it below:
echo.
set /p REPO_URL="https://github.com/Wally0517/nexus.git: "

if "%REPO_URL%"=="" (
    echo [ERROR] No URL provided. Please run this script again.
    pause
    exit /b 1
)

echo.
echo STEP 3: Adding Remote and Pushing
echo ========================================
echo Adding remote origin: %REPO_URL%
git remote add origin %REPO_URL%

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to add remote origin
    echo You might need to remove existing remote first:
    echo git remote remove origin
    echo Then run this script again.
    pause
    exit /b 1
)

echo Setting main branch...
git branch -M main

echo Pushing to GitHub...
git push -u origin main

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo SUCCESS! Your project is now on GitHub!
    echo ========================================
    echo.
    echo Your repository is available at:
    echo %REPO_URL%
    echo.
    echo To clone on another PC:
    echo git clone %REPO_URL%
    echo.
    echo To update from another PC:
    echo git pull origin main
    echo.
    echo Your NEXUS is now backed up on GitHub! 🚀
) else (
    echo.
    echo [ERROR] Failed to push to GitHub
    echo Please check:
    echo 1. Your GitHub credentials are correct
    echo 2. The repository URL is correct
    echo 3. You have write access to the repository
    echo.
    echo You can also try:
    echo git remote -v
    echo git push -u origin main --force
)

echo.
pause
