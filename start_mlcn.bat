@echo off
rem MLCN single-PC demo: receiver pipeline (Npcap) + Streamlit attacker UI.
rem Usage: start_mlcn.bat [launcher options]   (see: start_mlcn.bat --help)
setlocal
cd /d "%~dp0"
set "MLCN_PY="
if exist "%~dp0.venv\Scripts\python.exe" set "MLCN_PY=%~dp0.venv\Scripts\python.exe"
if not defined MLCN_PY if exist "%~dp0venv\Scripts\python.exe" set "MLCN_PY=%~dp0venv\Scripts\python.exe"
if not defined MLCN_PY set "MLCN_PY=python"
"%MLCN_PY%" -m mlcn_launcher %*
set "MLCN_RC=%ERRORLEVEL%"
if not "%MLCN_RC%"=="0" pause
exit /b %MLCN_RC%
