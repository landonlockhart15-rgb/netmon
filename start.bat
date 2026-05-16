@echo off
:: NetMon — One-click launcher
:: Starts NetMon (tray icon), which also manages ntfy internally.
:: UAC prompt appears once for admin (needed for nmap/firewall/DNS).

net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

set "ROOT=%~dp0"

:: ── Start NetMon system tray icon (manages ntfy internally) ──────────────────
if exist "%ROOT%.venv\Scripts\pythonw.exe" (
    start "" /d "%ROOT%" "%ROOT%.venv\Scripts\pythonw.exe" "%ROOT%launch.py"
    exit /b
)

if exist "%ROOT%.venv\Scripts\python.exe" (
    start "" /d "%ROOT%" "%ROOT%.venv\Scripts\python.exe" "%ROOT%launch.py"
    exit /b
)

where pyw.exe >nul 2>&1
if %errorlevel% equ 0 (
    start "" /d "%ROOT%" pyw.exe -3 "%ROOT%launch.py"
    exit /b
)

where pythonw.exe >nul 2>&1
if %errorlevel% equ 0 (
    start "" /d "%ROOT%" pythonw.exe "%ROOT%launch.py"
    exit /b
)

where python.exe >nul 2>&1
if %errorlevel% equ 0 (
    start "" /d "%ROOT%" python.exe "%ROOT%launch.py"
    exit /b
)

echo Python 3 was not found. Install Python 3.10+ and run tools\setup.ps1.
pause

:: Launcher exits cleanly — NetMon lives in the system tray
exit
