@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

echo.
echo This project now uses email registration and login.
echo Static file mode cannot complete sign-in or registration.
echo.
echo Please use start-server.bat instead.
echo This page will open a short explanation screen.
echo.

start "" "%~dp0login.html"
