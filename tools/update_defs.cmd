@echo off
REM ------------------------------------------------------------------
REM  update_defs.cmd - refresh CarrotAV definitions.
REM  Run this on a MODERN Windows/Linux/Mac machine. XP's TLS stack is
REM  too old to talk to database.clamav.net, so the download happens
REM  here and you copy carrot.cdb across to the XP box.
REM  Requires Python 3.
REM ------------------------------------------------------------------
setlocal
cd /d "%~dp0"

echo.
echo  CarrotAV definition builder
echo  ---------------------------
echo.

python --version >nul 2>&1
if errorlevel 1 (
  echo  ERROR: Python 3 was not found on PATH.
  echo  Install it from python.org and run this again.
  pause
  exit /b 1
)

if not exist "..\defs" mkdir "..\defs"

python get_defs.py
if errorlevel 1 (
  echo.
  echo  Build failed.
  pause
  exit /b 1
)

echo.
echo  Done. Copy ..\defs\carrot.cdb to the CarrotAV\defs folder on the XP
echo  machine, then use Definitions -^> Reload in the program.
echo.
pause
