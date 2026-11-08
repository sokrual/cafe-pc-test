@echo off
rem Asks for admin, then stops the test, restores the PC and makes the report.
net session >nul 2>&1 || (powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath \"%~f0\"" & exit /b)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0finish.ps1"
pause
