@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

where node >nul 2>nul
if errorlevel 1 (
  echo.
  echo Node.js was not found on this computer.
  echo.
  echo This project now requires server mode for email registration and login.
  echo Install Node.js first:
  echo https://nodejs.org/
  echo.
  pause
  exit /b 1
)

if "%PORT%"=="" set "PORT=8765"
if "%SESSION_HOURS%"=="" set "SESSION_HOURS=24"

echo.
echo Starting Journey Review account server...
echo.
echo Local computer:
echo   http://localhost:%PORT%/login
echo.
echo Other computers on the same Wi-Fi/LAN can try one of these addresses:
for /f "tokens=2 delims=:" %%A in ('ipconfig ^| findstr /R /C:"IPv4.*[0-9]"') do (
  for /f "tokens=* delims= " %%B in ("%%A") do echo   http://%%B:%PORT%/login
)
echo.
if not "%ALLOWED_EMAIL_DOMAINS%"=="" echo Allowed registration domains: %ALLOWED_EMAIL_DOMAINS%
echo.
echo Keep this window open while users access the site.
echo Press Ctrl+C to stop the server.
echo.

node server.js
