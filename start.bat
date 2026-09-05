@echo off
setlocal EnableExtensions EnableDelayedExpansion

echo ================================================================
echo   Fake Site Detector - Windows Startup
echo ================================================================
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python was not found.
    echo         Install Python 3.10+ from: https://www.python.org/downloads/
    echo         During installation, enable "Add Python to PATH".
    pause
    exit /b 1
)

for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PYTHON_VER=%%v
echo [OK] Python %PYTHON_VER% detected

if not exist ".env" (
    if exist ".env.example" (
        echo.
        echo [WARNING] .env file not found.
        echo          Copying .env.example to .env...
        copy ".env.example" ".env" > nul
        echo.
        echo ================================================================
        echo  .env was created. Please open it and verify the API keys.
        echo ================================================================
        echo.
echo  1. URLSCAN_API_KEY
echo  2. GEMINI_API_KEY
echo  3. SUPABASE_URL / SUPABASE_ANON_KEY / SUPABASE_EMAIL / SUPABASE_PASSWORD
        echo.
        echo  After setting the keys, run start.bat again.
        echo ================================================================
        start notepad .env
        pause
        exit /b 0
    ) else (
        echo [ERROR] .env.example was not found.
        pause
        exit /b 1
    )
)

if not exist "venv\" (
    echo.
    echo [1/3] Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo [ERROR] Virtual environment creation failed.
        pause
        exit /b 1
    )
    echo [OK] Virtual environment created
) else (
    echo [OK] Virtual environment already exists
)

echo.
echo [2/3] Installing required libraries...
call venv\Scripts\activate.bat

python -m pip install --upgrade pip --quiet
pip install -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Dependency installation failed.
    echo         Check the internet connection and try again.
    pause
    exit /b 1
)
echo [OK] Dependencies installed

echo.
echo [3/3] Starting desktop GUI...
echo       Close the window to exit.
echo.

echo ================================================================
cd src
python gui.py
cd ..

echo.
echo ================================================================
echo  System finished.
echo  Detection reports are saved as Excel files.
echo ================================================================

call venv\Scripts\deactivate.bat
pause
