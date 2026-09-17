# Bee Portable Package Builder for Windows
# Usage: Right-click -> "Run with PowerShell" or run in terminal:
#        .\launcher\build-portable.ps1
#        .\launcher\build-portable.ps1 -PostgresZip C:\Downloads\postgresql-15.4-1-windows-x64-binaries.zip

param(
    [string]$OutputDir = ".\dist\Bee-Portable",
    [string]$PostgresZip = "",
    [switch]$SkipPostgresCheck
)

$ErrorActionPreference = "Stop"
$baseDir = Resolve-Path "."

function Test-Command($cmd) {
    return [bool](Get-Command $cmd -ErrorAction SilentlyContinue)
}

# Check prerequisites
Write-Host "============================================"
Write-Host "  Bee Portable Package Builder"
Write-Host "============================================"
Write-Host ""

if (!(Test-Command go)) {
    $env:PATH = "C:\Program Files\Go\bin;" + $env:PATH
}
if (!(Test-Command go)) {
    throw "Go not found. Please install Go from https://go.dev/dl/"
}

if (!(Test-Command node)) {
    throw "Node.js not found. Please install Node.js from https://nodejs.org/"
}

if (!(Test-Command wails)) {
    throw "Wails CLI not found. Please install with: go install github.com/wailsapp/wails/v2/cmd/wails@latest"
}

$goVersion = (go version) -replace 'go version go', '' -replace ' .*', ''
Write-Host "Go version: $goVersion"
Write-Host "Wails version: $(wails version)"

# Resolve output directory
$OutputDir = Join-Path $baseDir $OutputDir

# Preserve previous build logs so failures remain visible after rebuild.
$logFiles = @()
if (Test-Path $OutputDir) {
    $logFiles = Get-ChildItem -Path $OutputDir -Filter "build-*.log" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }
    if ($logFiles.Count -gt 0) {
        Write-Host "Preserving previous build logs..."
    }
}

# Clean output directory
if (Test-Path $OutputDir) {
    Remove-Item -Recurse -Force $OutputDir
}
New-Item -ItemType Directory -Path $OutputDir | Out-Null
$OutputDir = Resolve-Path $OutputDir

# Restore preserved logs
foreach ($logFile in $logFiles) {
    $dest = Join-Path $OutputDir (Split-Path $logFile -Leaf)
    Copy-Item -Path $logFile -Destination $dest -ErrorAction SilentlyContinue
}

# Build frontend
Write-Host ""
Write-Host "[1/5] Building frontend..."
Set-Location "$baseDir\frontend"
if (!(Test-Path node_modules)) {
    npm install
}
$buildLog = "$OutputDir\build-frontend.log"
$env:NPM_CONFIG_LOGLEVEL = "warn"
& cmd /c "npm run build > `"$buildLog`" 2>&1"
if ($LASTEXITCODE -ne 0 -or !(Test-Path "$baseDir\frontend\dist\index.html")) {
    if (Test-Path $buildLog) { Get-Content $buildLog -Tail 50 }
    throw "Frontend build failed"
}

# Build backend
Write-Host ""
Write-Host "[2/5] Building backend..."
Set-Location "$baseDir\backend"
$env:CGO_ENABLED = "0"
$env:GOPROXY = "https://goproxy.cn,direct"
$env:GOSUMDB = "sum.golang.google.cn"
$backendLog = "$OutputDir\build-backend.log"
& cmd /c "go build -ldflags `"-s -w`" -o `"$OutputDir\bee-server.exe`" ./cmd/pentagi/ > `"$backendLog`" 2>&1"
if ($LASTEXITCODE -ne 0 -or !(Test-Path "$OutputDir\bee-server.exe")) {
    if (Test-Path $backendLog) { Get-Content $backendLog -Tail 50 }
    throw "Backend build failed"
}

# Build Wails launcher
Write-Host ""
Write-Host "[3/5] Building Wails launcher..."
Set-Location "$baseDir\launcher-wails"
$launcherLog = "$OutputDir\build-launcher.log"
& cmd /c "wails build -clean -o Bee.exe > `"$launcherLog`" 2>&1"
if ($LASTEXITCODE -ne 0 -or !(Test-Path "$baseDir\launcher-wails\build\bin\Bee.exe")) {
    if (Test-Path $launcherLog) { Get-Content $launcherLog -Tail 80 }
    throw "Wails launcher build failed"
}
Copy-Item -Path "$baseDir\launcher-wails\build\bin\Bee.exe" -Destination "$OutputDir\Bee.exe" -Force

# Copy frontend
Write-Host ""
Write-Host "[4/5] Copying frontend..."
Copy-Item -Recurse -Force "$baseDir\frontend\dist" "$OutputDir\fe"

# Handle PostgreSQL
Write-Host ""
Write-Host "[5/5] Setting up PostgreSQL..."
$postgresDir = Join-Path $OutputDir "postgres"

if ($PostgresZip -and (Test-Path $PostgresZip)) {
    Write-Host "Extracting PostgreSQL from $PostgresZip..."
    Expand-Archive -Path $PostgresZip -DestinationPath $OutputDir -Force
    # If extracted to a subfolder, move it to postgres/
    $extracted = Get-ChildItem $OutputDir | Where-Object { $_.PSIsContainer -and $_.Name -ne "fe" -and $_.Name -ne "postgres" }
    if ($extracted) {
        Rename-Item $extracted.FullName $postgresDir
    }
}

if (!(Test-Path $postgresDir)) {
    New-Item -ItemType Directory -Path $postgresDir | Out-Null
}

$pgBinDir = Join-Path $postgresDir "bin"
$pgCtl = Join-Path $pgBinDir "pg_ctl.exe"

if (!(Test-Path $pgCtl)) {
    if (!$SkipPostgresCheck) {
        Write-Host ""
        Write-Host "============================================"
        Write-Host "  MANUAL STEP REQUIRED"
        Write-Host "============================================"
        Write-Host "PostgreSQL binaries not found in the package."
        Write-Host ""
        Write-Host "Please download PostgreSQL 15+ Windows x64 portable binaries"
        Write-Host "and place them in:"
        Write-Host "  $postgresDir"
        Write-Host ""
        Write-Host "Recommended sources:"
        Write-Host "  - https://www.enterprisedb.com/downloads/postgres-postgresql-downloads"
        Write-Host "  - https://github.com/zaxx81/postgresql-lite"
        Write-Host "  - https://github.com/garethflowers/postgresql-portable"
        Write-Host ""
        Write-Host "Directory structure should be:"
        Write-Host "  $postgresDir\bin\pg_ctl.exe"
        Write-Host "  $postgresDir\bin\initdb.exe"
        Write-Host "  $postgresDir\bin\psql.exe"
        Write-Host "  $postgresDir\lib\..."
        Write-Host "  $postgresDir\share\..."
        Write-Host ""
        Write-Host "Note: pgvector extension is required for knowledge base features."
        Write-Host "If using plain PostgreSQL, knowledge base will not work."
        Write-Host "============================================"
        Write-Host ""
    }
}

# Create README
$readme = @"
# Bee Portable

One-click portable version of Bee for Windows.

## Quick Start

1. Double-click Bee.exe
2. Wait for Docker, PostgreSQL and backend to start in the splash screen
3. The main application will open automatically
4. Login with:
   - Username: admin@bee.com
   - Password: password

## Files

- Bee.exe - Wails launcher (splash screen + starts PostgreSQL + backend)
- bee-server.exe - Bee backend server
- fe/ - Frontend static files
- postgres/ - PostgreSQL portable binaries
- data/ - Runtime data (created automatically)
  - pgdata/ - PostgreSQL database files
  - logs/ - Application logs

## Stop

Close the Bee.exe window.

## Notes

- Docker Desktop is required because Bee runs tools inside containers.
  The launcher will try to start Docker Desktop automatically.
- First startup may take 1-2 minutes as PostgreSQL initializes.
- Make sure port 8080 and 5432 are not in use.
- Data is stored in the data/ folder next to Bee.exe.
"@

$readme | Out-File -FilePath "$OutputDir\README.txt" -Encoding UTF8

Write-Host ""
Write-Host "============================================"
Write-Host "  Build complete!"
Write-Host "============================================"
Write-Host "Output directory: $OutputDir"
Write-Host ""
Write-Host "To run: $OutputDir\Bee.exe"
Write-Host ""

if (!(Test-Path $pgCtl)) {
    Write-Host "WARNING: PostgreSQL binaries are missing. See README.txt for manual setup."
    Write-Host ""
}
