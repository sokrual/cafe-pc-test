@echo off
rem Asks for admin, then runs install-admin.ps1 -Uninstall.
net session >nul 2>&1 || (powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath \"%~f0\"" & exit /b)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-admin.ps1" -Uninstall
