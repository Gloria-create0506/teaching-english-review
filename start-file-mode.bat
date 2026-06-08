@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

echo.
echo Opening the review lesson in file mode...
echo Password: monkey2026
echo.
echo If the page does not open automatically, open login.html in this folder.
echo.

start "" "%~dp0login.html"

