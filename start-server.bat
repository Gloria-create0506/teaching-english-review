@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

where node >nul 2>nul
if errorlevel 1 (
  echo.
  echo Node.js was not found on this computer.
  echo.
  echo You can still open start-file-mode.bat for offline use.
  echo If you need IP/password limits, install Node.js first:
  echo https://nodejs.org/
  echo.
  pause
  exit /b 1
)

if "%ACCESS_PASSWORD%"=="" set "ACCESS_PASSWORD=monkey2026"
if "%MAX_IPS_PER_PASSWORD%"=="" set "MAX_IPS_PER_PASSWORD=2"
if "%PORT%"=="" set "PORT=8765"

echo.
echo Starting classroom review server...
echo Password: %ACCESS_PASSWORD%
echo Max IPs per password: %MAX_IPS_PER_PASSWORD%
echo.
echo Local computer:
echo   http://localhost:%PORT%/
echo.
echo Other computers on the same Wi-Fi/LAN can try one of these addresses:
for /f "tokens=2 delims=:" %%A in ('ipconfig ^| findstr /R /C:"IPv4.*[0-9]"') do (
  for /f "tokens=* delims= " %%B in ("%%A") do echo   http://%%B:%PORT%/
)
echo.
echo Keep this window open while students use the page.
echo Press Ctrl+C to stop the server.
echo.

node server.js

