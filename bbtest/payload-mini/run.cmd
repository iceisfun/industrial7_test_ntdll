@echo off
mode COM1:115200,n,8,1 >nul
mkdir C:\i7 2>nul
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0runner.ps1" -Mode std >COM1 2>&1
exit /b 0
