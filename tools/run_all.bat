@echo off
setlocal
if /i "%~1"=="/destructive" (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_all.ps1" -Destructive
) else (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_all.ps1" %*
)
exit /b %errorlevel%
