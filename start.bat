@echo off
pushd "%~dp0"

echo ============================================
echo   PentAGI
echo ============================================

if not exist "%~dp0frontend\dist\index.html" (
    echo [ERROR] Frontend not built yet!
    echo   Please run build.bat first.
    pause
    exit /b 1
)

echo Starting server ...
echo.
echo   Open http://localhost:8080
echo   Press Ctrl+C to stop
echo.

node "%~dp0server.js"

pause
