@echo off
REM ========================================
REM NEXUS - GitHub Setup
REM ========================================
cd /d "%~dp0"

echo ========================================
echo NEXUS - GitHub Repository Setup
echo ========================================
echo.
echo This script will help you create a GitHub repository
echo and push your NEXUS project to it.
echo.
echo Prerequisites:
echo 1. GitHub account (https://github.com)
echo 2. Git installed on your system
echo 3. GitHub CLI (gh) or manual repository creation
echo ========================================
echo.

REM Check if git is installed
git --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Git is not installed!
    echo Please install Git from: https://git-scm.com/download/win
    echo Then run this script again.
    pause
    exit /b 1
)

echo [1/6] Initializing Git repository...
git init
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to initialize Git repository
    pause
    exit /b 1
)

echo [2/6] Adding all files to Git...
git add .
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to add files to Git
    pause
    exit /b 1
)

echo [3/6] Creating initial commit...
git commit -m "Initial commit: NEXUS with AI chat memory system"
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to create initial commit
    pause
    exit /b 1
)

echo [4/6] Checking for GitHub CLI...
gh --version >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [GITHUB CLI] Found! Creating repository automatically...
    echo.
    echo Please enter your GitHub repository name:
    echo (e.g., nexus, routeros-ai-tool, etc.)
    set /p REPO_NAME="Repository name: "
    
    echo.
    echo Creating repository: %REPO_NAME%
    gh repo create %REPO_NAME% --public --description "AI-powered RouterOS configuration tool with chat memory system"
    
    if %ERRORLEVEL% EQU 0 (
        echo [SUCCESS] Repository created: https://github.com/%USERNAME%/%REPO_NAME%
        echo.
        echo [5/6] Adding remote origin...
        git remote add origin https://github.com/%USERNAME%/%REPO_NAME%.git
        
        echo [6/6] Pushing to GitHub...
        git branch -M main
        git push -u origin main
        
        if %ERRORLEVEL% EQU 0 (
            echo.
            echo ========================================
            echo SUCCESS! Repository created and pushed!
            echo ========================================
            echo.
            echo Your repository is now available at:
            echo https://github.com/%USERNAME%/%REPO_NAME%
            echo.
            echo To clone on another PC:
            echo git clone https://github.com/%USERNAME%/%REPO_NAME%.git
            echo.
        ) else (
            echo [ERROR] Failed to push to GitHub
            echo Please check your GitHub credentials
        )
    ) else (
        echo [ERROR] Failed to create repository
        echo Please create it manually on GitHub.com
    )
) else (
    echo [GITHUB CLI] Not found. Manual setup required.
    echo.
    echo ========================================
    echo MANUAL GITHUB SETUP
    echo ========================================
    echo.
    echo 1. Go to https://github.com/new
    echo 2. Create a new repository (e.g., 'nexus')
    echo 3. Copy the repository URL
    echo 4. Run these commands:
    echo.
    echo    git remote add origin YOUR_REPO_URL
    echo    git branch -M main
    echo    git push -u origin main
    echo.
    echo Example:
    echo    git remote add origin https://github.com/username/nexus.git
    echo    git branch -M main
    echo    git push -u origin main
    echo.
    echo 5. Your project will be available at:
    echo    https://github.com/username/nexus
    echo.
)

echo.
echo ========================================
echo NEXT STEPS
echo ========================================
echo.
echo 1. Copy the repository URL
echo 2. On your other PC, run:
echo    git clone YOUR_REPO_URL
echo 3. Install dependencies:
echo    pip install -r requirements.txt
echo 4. Start the server:
echo    start_backend.bat
echo.
echo Your NEXUS is now on GitHub! 🚀
echo.
pause
