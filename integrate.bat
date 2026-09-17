@echo off
chcp 65001 >nul
pushd "%~dp0"

echo ============================================
echo   Bee Full-Stack Integration
echo   Frontend: embedded in backend
echo   Backend:  port 8080
echo ============================================
echo.

echo [Check 1/5] Docker (for PostgreSQL) ...
where docker >nul 2>&1
if %errorlevel% neq 0 (
    echo   [ERROR] Docker not found!
    echo   Please install Docker Desktop first:
    echo   https://www.docker.com/products/docker-desktop/
    pause
    exit /b 1
)
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo   Docker not running. Starting Docker Desktop...
    if exist "C:\Program Files\Docker\Docker Desktop.exe" (
        start "" "C:\Program Files\Docker\Docker Desktop.exe"
    ) else if exist "C:\Program Files\Docker\Docker\Docker Desktop.exe" (
        start "" "C:\Program Files\Docker\Docker\Docker Desktop.exe"
    ) else (
        echo   [ERROR] Docker Desktop not found at default path.
        echo   Please start Docker Desktop manually.
        pause
        exit /b 1
    )
    echo   Waiting for Docker to start (this may take 30-60 seconds)...
    set _docker_wait=0
    :docker_wait_loop
    timeout /t 3 /nobreak >nul
    set /a _docker_wait+=3
    docker info >nul 2>&1
    if %errorlevel% equ 0 (
        echo   Docker is ready!
        goto docker_ready
    )
    if %_docker_wait% lss 90 (
        echo   Still waiting... (%_docker_wait%s)
        goto docker_wait_loop
    )
    echo   [ERROR] Docker failed to start within 90 seconds.
    echo   Please start Docker Desktop manually and try again.
    pause
    exit /b 1
    :docker_ready
    set _docker_wait=
)
echo   OK

echo.
echo [Check 2/5] Go ...
where go >nul 2>&1
if %errorlevel% neq 0 (
    if exist "C:\Program Files\Go\bin\go.exe" (
        set "PATH=C:\Program Files\Go\bin;%PATH%"
    )
)
where go >nul 2>&1
if %errorlevel% neq 0 (
    echo   [ERROR] Go not found!
    echo   Install from: https://go.dev/dl/
    echo   Or add C:\Program Files\Go\bin to system PATH
    pause
    exit /b 1
)
echo   OK

echo.
echo [Check 3/5] Node.js ...
where node >nul 2>&1
if %errorlevel% neq 0 (
    echo   [ERROR] Node.js not found!
    echo   Download: https://nodejs.org/
    pause
    exit /b 1
)
echo   OK

echo.
echo [Check 4/5] Frontend build ...
echo   Building frontend...
cd /d "%~dp0frontend"
call npm run build
if %errorlevel% neq 0 (
    echo   [ERROR] Frontend build failed!
    pause
    exit /b 1
)
echo   Copying to backend/fe/ ...
if exist "%~dp0backend\fe" (
    rd /s /q "%~dp0backend\fe"
)
md "%~dp0backend\fe"
xcopy /E /Y /Q "%~dp0frontend\dist\*" "%~dp0backend\fe\" >nul
echo   OK

echo.
echo [Check 5/5] PostgreSQL container ...
docker ps --format "{{.Names}}" | findstr /c:"pgvector" >nul
if %errorlevel% neq 0 (
    echo   Starting pgvector container...
    docker rm -f pgvector >nul 2>&1
    docker run -d --name pgvector ^
      -e POSTGRES_USER=postgres ^
      -e POSTGRES_PASSWORD=postgres ^
      -e POSTGRES_DB=beedb ^
      -p 5432:5432 ^
      vxcontrol/pgvector:latest
    if %errorlevel% neq 0 (
        echo   [ERROR] Failed to start PostgreSQL container!
        echo   Make sure port 5432 is not in use.
        echo   Try: netstat -ano ^| findstr :5432
        pause
        exit /b 1
    )
    echo   Waiting for PostgreSQL to be ready...
    timeout /t 8 /nobreak >nul
)
echo   OK

echo.
echo ============================================
echo   Starting backend server...
echo ============================================
echo.

set SERVER_PORT=8080
set SERVER_HOST=0.0.0.0
set CORS_ORIGINS=*
set DOCKER_INSIDE=false
set DATABASE_URL=postgres://postgres:postgres@localhost:5432/beedb?sslmode=disable
set DATA_DIR=%~dp0data
set STATIC_DIR=%~dp0backend\fe
set GOPROXY=https://goproxy.cn,direct
set GOSUMDB=sum.golang.google.cn

echo   Server:           http://localhost:%SERVER_PORT%
echo   GOPROXY:          %GOPROXY%
echo   First run may take 3-5 min downloading Go dependencies...
echo.
echo   DO NOT close this window while the server is running.
echo.

cd /d "%~dp0backend"
go run ./cmd/pentagi/

echo.
echo Server stopped.
if errorlevel 1 (
    echo.
    echo [ERROR] Backend failed to start.
    echo Common issues:
    echo   1. PostgreSQL not ready - wait 10s and try again
    echo   2. Port 8080 in use - change SERVER_PORT
    echo   3. Database connection error - check DATABASE_URL
)
echo.
pause
popd
