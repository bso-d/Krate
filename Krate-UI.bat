@echo off
setlocal EnableDelayedExpansion

:: Change directory to the folder containing this batch script
cd /d "%~dp0"

set "PYTHONDONTWRITEBYTECODE=1"

:: Check for native Python 3 (3.9+)
set "PYTHON_CMD="

where py >nul 2>&1
if !errorlevel! equ 0 (
    py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>&1
    if !errorlevel! equ 0 (
        set "PYTHON_CMD=py -3"
        goto :launch_native
    )
)

where python >nul 2>&1
if !errorlevel! equ 0 (
    python -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>&1
    if !errorlevel! equ 0 (
        set "PYTHON_CMD=python"
        goto :launch_native
    )
)

where python3 >nul 2>&1
if !errorlevel! equ 0 (
    python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>&1
    if !errorlevel! equ 0 (
        set "PYTHON_CMD=python3"
        goto :launch_native
    )
)

:: If native Python was not found, check for WSL2
where wsl.exe >nul 2>&1
if !errorlevel! equ 0 (
    wsl.exe python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>&1
    if !errorlevel! equ 0 (
        goto :launch_wsl
    )
)

echo ========================================================================
echo Error: Python 3.9+ was not found natively or in WSL2.
echo Please install Python 3.9+ from https://www.python.org/ or install Python 3 inside WSL2.
echo ========================================================================
pause
exit /b 1

:launch_native
echo Starting Krate Studio (Native Windows)...
%PYTHON_CMD% -B ui\krate_ui.py %*
goto :eof

:launch_wsl
echo Starting Krate Studio (WSL2)...
wsl.exe python3 -B ui/krate_ui.py %*
goto :eof
