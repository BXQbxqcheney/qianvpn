@echo off
title QianVPN Gateway
cd /d "%~dp0"
chcp 65001 >nul
set QGW_CONSOLE=1
where node >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Node.js not found. Please install it from https://nodejs.org/
  pause
  exit /b 1
)
if not exist "node_modules\node-forge" call npm install --no-audit --no-fund
node proxy.js
echo.
echo Gateway exited. You can close this window.
pause
