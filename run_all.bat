@echo off
rem Runs every build\*.exe in turn, one result file per area under results\.
rem Usage: run_all.bat [name-filter]   (the filter is passed to each test executable)
setlocal EnableDelayedExpansion
if not exist results mkdir results
set FAILED=0
set INCOMPLETE=0
for %%E in (build\*.exe) do (
  set AREA=%%~nE
  echo == AREA !AREA!
  build\%%~nxE %1 > results\!AREA!.txt 2>&1
  set RC=!errorlevel!
  findstr /R /C:"^FAIL" /C:"^  FAIL" /C:"^SUMMARY" results\!AREA!.txt
  findstr /B /C:"SUMMARY" results\!AREA!.txt >nul || (echo !AREA!: no SUMMARY line, exit code !RC! & set INCOMPLETE=1)
  if not "!RC!"=="0" set FAILED=1
)
if "%FAILED%%INCOMPLETE%"=="00" (echo ALL AREAS PASSED & exit /b 0)
echo SOME AREAS FAILED OR WERE INCOMPLETE - see results\
exit /b 1
