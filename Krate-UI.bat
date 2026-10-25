@echo off
setlocal EnableDelayedExpansion

:: Change directory to the folder containing this batch script
cd /d "%~dp0"

set "PYTHONDONTWRITEBYTECODE=1"

:: Krate CLI lifecycle scripts require a POSIX/Bash environment (WSL2).
:: Prefer WSL2 Python 3.9+ first so backend subprocess calls to ./krate succeed.
where wsl.exe >nul 2>&1
if !errorlevel! equ 0 (
    wsl.exe python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>&1
    if !errorlevel! equ 0 (
        goto :launch_wsl
    )
)

echo ========================================================================
echo Error: WSL2 with Python 3.9+ is required on Windows to run Krate Studio
echo and execute Krate Bash CLI lifecycle operations.
echo Please install WSL2 (wsl --install) and Python 3.9+ inside your WSL2
echo distribution (e.g., sudo apt install python3 or sudo dnf install python3).
echo ========================================================================
pause
exit /b 1

:launch_wsl
echo Starting Krate Studio (WSL2)...
wsl.exe env PYTHONDONTWRITEBYTECODE=1 python3 -B ui/krate_ui.py %*
goto :eof
