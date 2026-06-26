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
if "%VERIFY_TOKEN_HOURS%"=="" set "VERIFY_TOKEN_HOURS=24"
if "%RESET_TOKEN_MINUTES%"=="" set "RESET_TOKEN_MINUTES=30"

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
if "%RESEND_API_KEY%"=="" echo Warning: RESEND_API_KEY is not set. Registration emails will fail.
if "%EMAIL_FROM%"=="" echo Warning: EMAIL_FROM is not set. Registration emails will fail.
echo.
echo Keep this window open while users access the site.
echo Press Ctrl+C to stop the server.
echo.

node server.js
