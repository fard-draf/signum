@echo off
setlocal
set SIGNUM_PORTABLE=1
if "%SIGNUM_DATA_DIR%"=="" set SIGNUM_DATA_DIR=%~dp0signum-data
"%~dp0signum.exe" %*
endlocal
