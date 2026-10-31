@echo off
setlocal
set "helper=%~dp0scripts\manage-service.ps1"
if exist "%~dp0service\manage-service.ps1" set "helper=%~dp0service\manage-service.ps1"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%helper%" -action install
set "exitCode=%errorlevel%"
if not defined EPP_NO_PAUSE if not defined CI pause
exit /b %exitCode%
