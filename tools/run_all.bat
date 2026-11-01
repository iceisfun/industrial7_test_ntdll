@echo off
setlocal
if /i "%~1"=="/destructive" (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_all.ps1" -Destructive %2 %3 %4 %5 %6 %7 %8 %9
) else (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_all.ps1" %*
)
exit /b %errorlevel%
