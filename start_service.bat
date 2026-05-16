@echo off
:: NetMon — headless server start (used by Task Scheduler)
:: Runs as SYSTEM, no UAC prompt, no pause, no --reload

:: Add tool directories to PATH so nmap/tshark are found regardless of system PATH
set PATH=%PATH%;C:\Program Files (x86)\Nmap;C:\Program Files\Nmap;C:\Program Files\Wireshark

cd /d "%~dp0"

set "PORT=%APP_PORT%"
if "%PORT%"=="" set "PORT=8000"

if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -m uvicorn app.main:app --host 0.0.0.0 --port %PORT%
    exit /b %errorlevel%
)

py -3 -m uvicorn app.main:app --host 0.0.0.0 --port %PORT%
if %errorlevel% equ 0 exit /b 0

python -m uvicorn app.main:app --host 0.0.0.0 --port %PORT%
