@echo off
pushd "%~dp0"

echo ============================================
echo   PentAGI - Build
echo ============================================
echo.

echo [1/2] Building frontend ...
pushd "%~dp0frontend"

if not exist "node_modules\" (
    echo   Installing npm dependencies ...
    call npm install
    if %errorlevel% neq 0 (
        echo [ERROR] npm install failed!
        popd
        pause
        exit /b 1
    )
)

echo   Running vite build ...
call npx vite build --outDir dist
if %errorlevel% neq 0 (
    echo [ERROR] Build failed!
    popd
    pause
    exit /b 1
)
popd
echo   Done.

echo.
echo [2/2] Build complete!
echo.
echo   The frontend is built in: frontend\dist\
echo   To start, run: start.bat
echo.

echo ============================================
echo   Build Success!
echo ============================================
pause
