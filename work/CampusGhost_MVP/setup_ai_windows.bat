@echo off
setlocal
cd /d "%~dp0"
set "PYTHON_EXE=.venv\Scripts\python.exe"
if not exist "%PYTHON_EXE%" set "PYTHON_EXE=..\..\.venv\Scripts\python.exe"
if not exist "%PYTHON_EXE%" (
  echo No project virtual environment was found.
  echo Run run_windows.bat in this folder, or create/activate the outer project .venv first.
  pause
  exit /b 1
)
"%PYTHON_EXE%" -m pip install -r requirements-ai.txt
if errorlevel 1 (
  echo LangGraph installation failed. Check your internet connection and retry.
  pause
  exit /b 1
)
echo.
echo LangGraph is installed.
echo Install Ollama for Windows separately from https://ollama.com/download
echo Then open Ollama and run in PowerShell:
echo ollama pull qwen3:4b
echo.
echo To enable the Qwen3 agent in the current PowerShell window:
echo $env:CAMPUSGHOST_USE_OLLAMA="1"
echo $env:OLLAMA_MODEL="qwen3:4b"
echo %PYTHON_EXE% app.py
echo.
echo Or simply double-click run_agent_windows.bat to start the agent-led investigation.
echo Qwen3 receives only pseudonymous categorical evidence and has no identity, database, decryption, or revoke tool.
pause
