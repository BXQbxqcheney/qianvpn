@echo off
title QianVPN - Deploy Relay Server
cd /d "%~dp0"
chcp 65001 >nul
where node >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Node.js not found. Please install it from https://nodejs.org/
  pause
  exit /b 1
)
echo Starting deploy - a browser window will open for Netlify authorization.
node deploy\deploy-server.js
echo.
pause
