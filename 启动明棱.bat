@echo off
chcp 65001 >nul 2>&1 || chcp 936 >nul
title Mingleng MCPGuard - AI Agent Security Scanner
cd /d "%~dp0"
echo ============================================================
echo   Mingleng MCPGuard - scan your AI agent's security posture
echo ============================================================
echo.
echo Scanning MCP configs and skill directories...
echo.
"%~dp0dist\mcpguard.exe"
echo.
echo ============================================================
echo   Scan finished. Press any key to close.
echo ============================================================
pause
