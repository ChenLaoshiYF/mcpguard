@echo off
chcp 65001 >nul 2>&1 || chcp 936 >nul
title Mingleng MCPGuard - Demo Mode
cd /d "%~dp0"
echo ============================================================
echo   Mingleng MCPGuard DEMO - scanning bundled samples
echo   NOTE: samples include a deliberately malicious server
echo   to demonstrate detection. Your real system is fine.
echo ============================================================
echo.
"%~dp0dist\mcpguard.exe" --path "%~dp0samples"
echo.
echo ============================================================
echo   Demo finished. Press any key to close.
echo ============================================================
pause
