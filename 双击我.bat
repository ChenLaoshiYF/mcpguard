@echo off
chcp 65001 >nul
title MCPGuard - AI Agent Security Scanner
cd /d "%~dp0"
echo ============================================================
echo   MCPGuard - Scan your AI agent's security posture
echo ============================================================
echo.
echo [1/2] Scanning MCP configs and skill directories...
echo.
"%~dp0dist\mcpguard.exe" --path "%~dp0samples"
echo.
echo ============================================================
echo   Scan finished. Press any key to close.
echo ============================================================
pause
