@echo off
setlocal
set SIGNUM_PORTABLE=1
set ROOT_DIR=%~dp0..
if "%SIGNUM_SHARED_DIR%"=="" set SIGNUM_SHARED_DIR=%ROOT_DIR%\signum-data
if "%SIGNUM_CONFIG_PATH%"=="" set SIGNUM_CONFIG_PATH=%ROOT_DIR%\signum.conf
"%~dp0signum.exe" %*
endlocal
