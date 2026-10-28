@echo off
title Install CA Cert
cd /d "%~dp0"
if not exist "certs\ca.crt" (
  echo [ERROR] certs\ca.crt not found. Run start-gateway.cmd first.
  pause
  exit /b 1
)
echo Importing local CA certificate into Current User - Trusted Root Stores.
echo Click YES if Windows shows a security warning.
pause
powershell -NoProfile -Command "try { Import-Certificate -FilePath '%~dp0certs\ca.crt' -CertStoreLocation Cert:\CurrentUser\Root | Out-Null; exit 0 } catch { exit 1 }"
if %errorlevel%==0 (
  echo [OK] CA certificate installed.
) else (
  echo [FAIL] Manual steps: double-click certs\ca.crt - Install Certificate - Current User
  echo        - Place all certificates in the following store - Trusted Root Certification Authorities.
)
pause
