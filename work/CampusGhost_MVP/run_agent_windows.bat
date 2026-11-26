@echo off
setlocal
cd /d "%~dp0"
echo ==========================================
echo   CampusGhost - AI agent-led investigation
echo ==========================================
set "PYTHON_EXE=.venv\Scripts\python.exe"
if not exist "%PYTHON_EXE%" set "PYTHON_EXE=..\..\.venv\Scripts\python.exe"
if not exist "%PYTHON_EXE%" (
  echo No virtual environment found. Run run_windows.bat once first to create it.
  pause
  exit /b 1
)
"%PYTHON_EXE%" -c "import langgraph" >nul 2>nul
if errorlevel 1 (
  echo Installing agent dependencies...
  "%PYTHON_EXE%" -m pip install -r requirements.txt -r requirements-ai.txt
  if errorlevel 1 (
    echo Dependency installation failed. Check your internet connection and retry.
    pause
    exit /b 1
  )
)
powershell -NoProfile -Command "try { Invoke-WebRequest -UseBasicParsing http://127.0.0.1:11434/api/tags | Out-Null; exit 0 } catch { exit 1 }"
if errorlevel 1 (
  echo.
  echo WARNING: Ollama does not seem to be running on 127.0.0.1:11434.
  echo Open the Ollama app and run:  ollama pull qwen3:4b
  echo With strict mode on, cases will be escalated to the administrator until Ollama is available.
  echo.
)
set CAMPUSGHOST_ADMIN_USERNAME=admin
set CAMPUSGHOST_ADMIN_PASSWORD=zxcvbnm@123
set CAMPUSGHOST_USE_OLLAMA=1
set CAMPUSGHOST_AGENT_MODE=led
set CAMPUSGHOST_AI_STRICT=1
set OLLAMA_MODEL=qwen3:4b
"%PYTHON_EXE%" app.py
pause
