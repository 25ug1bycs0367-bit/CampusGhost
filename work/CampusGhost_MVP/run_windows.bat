@echo off
setlocal
cd /d "%~dp0"
echo ==========================================
echo   CampusGhost - AI Agent-led Launcher
echo ==========================================
where py >nul 2>nul
if errorlevel 1 (
  echo Python launcher not found. Install Python 3.11 or 3.12 and select Add Python to PATH.
  pause
  exit /b 1
)
py -3.12 --version >nul 2>nul
if errorlevel 1 (
  echo Python 3.12 was not found. Trying the default Python installation...
  py --version
  py -m venv .venv
) else (
  py -3.12 -m venv .venv
)
if not exist ".venv\Scripts\python.exe" (
  echo Could not create virtual environment. Check your Python installation.
  pause
  exit /b 1
)
call .venv\Scripts\activate.bat
set CAMPUSGHOST_ADMIN_USERNAME=admin
set CAMPUSGHOST_ADMIN_PASSWORD=zxcvbnm@123
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if errorlevel 1 (
  echo Dependency installation failed. Check internet connection and Python version.
  pause
  exit /b 1
)
echo Starting strict agent-led mode. If Ollama is unavailable, investigations are escalated.
call run_agent_windows.bat
pause
