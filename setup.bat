@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\dev.ps1" -task setup
set "exitCode=%errorlevel%"
if not "%exitCode%"=="0" echo Setup failed with exit code %exitCode%. Review the error above.
if not defined EPP_NO_PAUSE if not defined CI pause
exit /b %exitCode%
