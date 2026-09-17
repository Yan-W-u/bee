package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

const (
	pgHost      = "127.0.0.1"
	pgPortStart = 5432
	pgPortEnd   = 5452
	pgUser      = "postgres"
	pgPassword  = "postgres"
	pgDatabase  = "beedb"
	serverPort  = "8080"

	CREATE_NO_WINDOW = 0x08000000

	// disableDocker disables Docker checks and runs the backend in local
	// execution mode. This matches the portable/no-Docker build.
	disableDocker = true
)

// Status describes the current launch phase shown in the splash screen.
type Status struct {
	Step     string `json:"step"`     // idle | docker | postgres | backend | ready | error
	Message  string `json:"message"`  // human-readable description
	Progress int    `json:"progress"` // 0-100
	Error    string `json:"error"`    // empty unless step == error
	CanRetry bool   `json:"canRetry"` // whether the user can retry
}

// App is the Wails application struct that manages the splash screen and the
// background services (Docker check, PostgreSQL, Bee backend).
type App struct {
	ctx    context.Context
	mu     sync.RWMutex
	status Status

	baseDir   string
	dataDir   string
	pgDir     string
	pgDataDir string
	logDir    string
	feDir     string

	pgPort       string
	actualPgPort string

	logFile   *os.File
	logger    *log.Logger
	serverCmd *exec.Cmd
}

// NewApp creates a new App application struct.
func NewApp() *App {
	return &App{
		status: Status{Step: "idle", Message: "准备启动...", Progress: 0},
	}
}

// startup is called at application start. It initialises paths, logging, and
// starts the background service launcher.
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	exePath, err := os.Executable()
	if err != nil {
		a.setError("无法获取程序路径", err, false)
		return
	}
	a.baseDir = filepath.Dir(exePath)

	a.pgDir = choosePostgresDir(a.baseDir)
	a.dataDir = chooseDataDir(a.baseDir)
	a.pgDataDir = filepath.Join(a.dataDir, "pgdata")
	a.logDir = filepath.Join(a.dataDir, "logs")
	a.feDir = filepath.Join(a.baseDir, "fe")

	if err := os.MkdirAll(a.logDir, 0755); err != nil {
		a.setError("无法创建日志目录", err, false)
		return
	}

	logFilePath := filepath.Join(a.logDir, "launcher.log")
	f, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		a.setError("无法打开日志文件", err, false)
		return
	}
	a.logFile = f
	a.logger = log.New(f, "", log.LstdFlags)
	a.logger.Println("============================================")
	a.logger.Println("Bee Wails Launcher started")
	a.logger.Printf("Base directory: %s\n", a.baseDir)

	// Start services in a goroutine so the UI window appears immediately.
	go a.launchServices()
}

// shutdown stops all background services when the user closes the window.
func (a *App) shutdown(ctx context.Context) {
	if a.serverCmd != nil && a.serverCmd.Process != nil {
		a.logger.Println("Stopping Bee backend")
		_ = a.serverCmd.Process.Kill()
		_, _ = a.serverCmd.Process.Wait()
	}

	if a.pgDataDir != "" {
		a.stopPostgres()
	}

	if a.logFile != nil {
		a.logFile.Close()
	}
}

// stopPostgres stops the PostgreSQL instance launched by the launcher.
func (a *App) stopPostgres() {
	if a.pgDir == "" || a.pgDataDir == "" {
		return
	}
	pgCtl := filepath.Join(a.pgDir, "bin", "pg_ctl.exe")
	if _, err := os.Stat(pgCtl); os.IsNotExist(err) {
		a.logger.Printf("pg_ctl.exe not found, cannot stop PostgreSQL: %s\n", pgCtl)
		return
	}
	a.logger.Println("Stopping PostgreSQL")
	cmd := exec.Command(pgCtl,
		"stop",
		"--pgdata", a.pgDataDir,
		"--wait",
		"-m", "fast",
	)
	a.setupPostgresCmd(cmd)
	cmd.Stdout = a.logFile
	cmd.Stderr = a.logFile
	if err := cmd.Run(); err != nil {
		a.logger.Printf("PostgreSQL stop failed (may already be stopped): %v\n", err)
	} else {
		a.logger.Println("PostgreSQL stopped")
	}
}

// domReady applies native window styling once the window exists.
func (a *App) domReady(ctx context.Context) {
	hwnd := findMainWindow("Bee - 蜜罐渗透测试平台")
	if hwnd == 0 {
		// Fallback: try a shorter prefix match in case the title is truncated.
		hwnd = findMainWindow("Bee")
	}
	makeWindowModern(hwnd)
}

// GetStatus returns the current launcher status to the frontend.
func (a *App) GetStatus() Status {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.status
}

// Retry tells the launcher to retry the whole launch sequence. Used from the
// frontend when Docker was not running.
func (a *App) Retry() {
	a.mu.Lock()
	if a.status.Step != "error" {
		a.mu.Unlock()
		return
	}
	a.status = Status{Step: "idle", Message: "准备启动...", Progress: 0}
	a.mu.Unlock()
	a.emitStatus()
	go a.launchServices()
}

// Quit exits the application from the frontend.
func (a *App) Quit() {
	wailsRuntime.Quit(a.ctx)
}

// OpenLogDir opens the launcher log directory in Windows Explorer.
func (a *App) OpenLogDir() {
	if a.logDir == "" {
		return
	}
	cmd := exec.Command("explorer", a.logDir)
	runHidden(cmd)
	_ = cmd.Start()
}

func (a *App) launchServices() {
	if !disableDocker {
		a.setStatus("docker", "检查 Docker 环境...", 5)

		dockerErr := a.ensureDocker()
		if dockerErr != nil {
			a.setError("Docker 未运行，自动启动失败", dockerErr, true)
			return
		}
		a.setStatus("docker", "Docker 已就绪", 20)
	} else {
		a.logger.Println("Docker disabled, using local execution mode")
		a.setStatus("docker", "本地执行模式，跳过 Docker", 20)
	}

	if err := a.startPostgres(); err != nil {
		a.setError("PostgreSQL 启动失败", err, false)
		return
	}
	a.setStatus("postgres", "PostgreSQL 已就绪", 50)

	if err := a.startBackend(); err != nil {
		a.setError("Bee 后端启动失败", err, false)
		return
	}
	a.setStatus("backend", "Bee 后端已就绪", 80)

	// Give the backend a moment to finish initialising, then navigate.
	a.setStatus("ready", "正在打开应用...", 100)
	time.Sleep(500 * time.Millisecond)
	wailsRuntime.WindowExecJS(a.ctx, fmt.Sprintf(`window.location.href = "http://localhost:%s/";`, serverPort))
}

func (a *App) ensureDocker() error {
	a.logger.Println("Checking Docker availability")

	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("未在系统 PATH 中找到 docker 命令。请先安装 Docker Desktop：https://www.docker.com/products/docker-desktop/")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if a.isDockerReady(ctx) {
		a.logger.Println("Docker is ready")
		return nil
	}

	a.logger.Println("Docker daemon not reachable, trying to start it silently")
	a.setStatus("docker", "正在尝试静默启动 Docker...", 8)

	// If we are elevated, start the Windows service directly (fully silent).
	if a.startDockerService() {
		if a.waitForDocker(60 * time.Second) {
			a.logger.Println("Docker is ready (via service)")
			return nil
		}
		a.logger.Println("Docker service started but daemon is still not ready")
	}

	// Try the official Docker Desktop CLI plugin. This works when the service
	// is already running or when Docker Desktop can start without elevation.
	a.logger.Println("Trying docker desktop start")
	if a.startDockerDesktopCLI() {
		return nil
	}

	// Last resort: request elevation to start Docker Desktop. This shows the
	// Windows UAC prompt, but if the user allows it, Docker Desktop starts
	// with the privileges it needs to start its service.
	a.logger.Println("Trying elevated Docker Desktop executable")
	a.setStatus("docker", "需要管理员权限启动 Docker，请在系统提示中点击允许...", 10)
	if a.startDockerDesktopElevated() {
		return nil
	}

	return fmt.Errorf("Docker Desktop 未运行，自动启动失败。\n\n请手动启动 Docker Desktop，然后点击“重试”。\n如果尚未安装，可前往：https://www.docker.com/products/docker-desktop/")
}

func (a *App) startDockerService() bool {
	a.logger.Println("Trying to start Docker Desktop Windows service")
	cmd := exec.Command("sc", "start", "com.docker.service")
	runHidden(cmd)
	if err := cmd.Run(); err != nil {
		a.logger.Printf("sc start com.docker.service failed or service not installed: %v\n", err)
		return false
	}
	a.logger.Println("Issued sc start com.docker.service")
	return true
}

func (a *App) startDockerDesktopCLI() bool {
	cmd := exec.Command("docker", "desktop", "start", "-d")
	runHidden(cmd)
	if err := cmd.Start(); err != nil {
		a.logger.Printf("docker desktop start failed: %v\n", err)
		return false
	}
	if a.waitForDocker(90 * time.Second) {
		a.logger.Println("Docker is ready (via docker desktop start)")
		return true
	}
	a.logger.Println("docker desktop start timed out")
	return false
}

func (a *App) startDockerDesktopElevated() bool {
	exe := findDockerDesktopExe()
	if exe == "" {
		a.logger.Println("Docker Desktop executable not found")
		return false
	}
	a.logger.Printf("Requesting elevation for %s\n", exe)
	// SW_SHOWMINNOACTIVE asks Windows to show the elevated window minimized and
	// inactive. The UAC prompt itself is unavoidable, but the main Docker
	// Desktop window will at least start minimized.
	if err := runElevated(exe, "", SW_SHOWMINNOACTIVE); err != nil {
		a.logger.Printf("runElevated failed: %v\n", err)
		return false
	}
	if a.waitForDocker(120 * time.Second) {
		a.logger.Println("Docker is ready (via elevated Docker Desktop)")
		return true
	}
	a.logger.Println("elevated Docker Desktop start timed out")
	return false
}

func findDockerDesktopExe() string {
	candidates := []string{
		`C:\Program Files\Docker\Docker\Docker Desktop.exe`,
		`C:\Program Files\Docker\Docker Desktop.exe`,
		`C:\Program Files (x86)\Docker\Docker Desktop.exe`,
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

func (a *App) waitForDocker(timeout time.Duration) bool {
	a.logger.Println("Waiting for Docker to start")
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if a.isDockerReady(ctx) {
			cancel()
			return true
		}
		cancel()
		time.Sleep(3 * time.Second)
	}
	return false
}

func (a *App) isDockerReady(ctx context.Context) bool {
	cmd := exec.CommandContext(ctx, "docker", "info")
	runHidden(cmd)
	return cmd.Run() == nil
}

func (a *App) startPostgres() error {
	if _, err := os.Stat(a.pgDir); os.IsNotExist(err) {
		return fmt.Errorf("PostgreSQL 未找到：%s", a.pgDir)
	}

	binDir := filepath.Join(a.pgDir, "bin")
	pgCtl := filepath.Join(binDir, "pg_ctl.exe")
	initDb := filepath.Join(binDir, "initdb.exe")
	psql := filepath.Join(binDir, "psql.exe")
	postgresExe := filepath.Join(binDir, "postgres.exe")

	for _, exe := range []string{pgCtl, initDb, psql, postgresExe} {
		if _, err := os.Stat(exe); os.IsNotExist(err) {
			return fmt.Errorf("缺少 PostgreSQL 二进制文件：%s", exe)
		}
	}

	a.pgPort = findAvailablePort(pgHost, pgPortStart, pgPortEnd)
	if a.pgPort == "" {
		return fmt.Errorf("未找到可用 PostgreSQL 端口（%d-%d）", pgPortStart, pgPortEnd)
	}

	if err := os.MkdirAll(a.pgDataDir, 0755); err != nil {
		return fmt.Errorf("无法创建 PostgreSQL 数据目录：%v", err)
	}

	if _, err := os.Stat(filepath.Join(a.pgDataDir, "PG_VERSION")); os.IsNotExist(err) {
		a.setStatus("postgres", "正在初始化 PostgreSQL 数据库...", 25)
		a.logger.Println("Initializing PostgreSQL database")
		cmd := exec.Command(initDb,
			"--pgdata", a.pgDataDir,
			"--username", pgUser,
			"--encoding", "UTF8",
			"--no-locale",
			"--pwfile", a.createPasswordFile(),
		)
		a.setupPostgresCmd(cmd)
		cmd.Stdout = a.logFile
		cmd.Stderr = a.logFile
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("initdb 失败：%v", err)
		}
		a.logger.Println("Database initialized")
	}

	cleanStalePostmasterPid(a.pgDataDir, a.logger)

	a.setStatus("postgres", "正在启动 PostgreSQL...", 30)
	a.logger.Println("Starting PostgreSQL")
	startCmd := exec.Command(pgCtl,
		"start",
		"--pgdata", a.pgDataDir,
		"--wait",
		"-o", fmt.Sprintf("-p %s", a.pgPort),
	)
	a.setupPostgresCmd(startCmd)
	startCmd.Stdout = a.logFile
	startCmd.Stderr = a.logFile
	if err := startCmd.Run(); err != nil {
		return fmt.Errorf("启动 PostgreSQL 失败：%v", err)
	}
	a.logger.Println("PostgreSQL started")

	a.actualPgPort = readPostmasterPort(a.pgDataDir)
	if a.actualPgPort == "" {
		a.actualPgPort = a.pgPort
	} else if a.actualPgPort != a.pgPort {
		a.logger.Printf("PostgreSQL bound to port %s (requested %s)\n", a.actualPgPort, a.pgPort)
	}

	a.setStatus("postgres", "正在等待 PostgreSQL 就绪...", 40)
	a.logger.Println("Waiting for PostgreSQL to be ready")
	for i := 0; i < 30; i++ {
		cmd := exec.Command(psql,
			"-h", pgHost,
			"-p", a.actualPgPort,
			"-U", pgUser,
			"-d", "postgres",
			"-c", "SELECT 1",
		)
		a.setupPostgresCmd(cmd)
		cmd.Env = append(cmd.Env, "PGPASSWORD="+pgPassword)
		if err := cmd.Run(); err == nil {
			break
		}
		time.Sleep(1 * time.Second)
	}
	a.logger.Println("PostgreSQL is ready")

	createDb := exec.Command(psql,
		"-h", pgHost,
		"-p", a.actualPgPort,
		"-U", pgUser,
		"-d", "postgres",
		"-t", "-A",
		"-c", fmt.Sprintf("SELECT 1 FROM pg_database WHERE datname='%s'", pgDatabase),
	)
	a.setupPostgresCmd(createDb)
	createDb.Env = append(createDb.Env, "PGPASSWORD="+pgPassword)
	output, _ := createDb.CombinedOutput()
	if strings.TrimSpace(string(output)) != "1" {
		a.logger.Printf("Creating database %s\n", pgDatabase)
		cmd := exec.Command(psql,
			"-h", pgHost,
			"-p", a.actualPgPort,
			"-U", pgUser,
			"-d", "postgres",
			"-c", fmt.Sprintf("CREATE DATABASE %s", pgDatabase),
		)
		a.setupPostgresCmd(cmd)
		cmd.Env = append(cmd.Env, "PGPASSWORD="+pgPassword)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("创建数据库失败：%v\n%s", err, string(output))
		}
	}

	return nil
}

func (a *App) startBackend() error {
	backendExe := filepath.Join(a.baseDir, "bee-server.exe")
	if _, err := os.Stat(backendExe); os.IsNotExist(err) {
		return fmt.Errorf("后端程序未找到：%s", backendExe)
	}
	if _, err := os.Stat(a.feDir); os.IsNotExist(err) {
		return fmt.Errorf("前端目录未找到：%s", a.feDir)
	}

	a.setStatus("backend", "正在启动 Bee 后端...", 55)
	a.logger.Println("Starting Bee backend")

	a.serverCmd = exec.Command(backendExe)
	a.serverCmd.Dir = a.baseDir
	runHidden(a.serverCmd)
	env := []string{
		"SERVER_PORT=" + serverPort,
		"SERVER_HOST=0.0.0.0",
		"DATABASE_URL=postgres://" + pgUser + ":" + pgPassword + "@" + pgHost + ":" + a.actualPgPort + "/" + pgDatabase + "?sslmode=disable",
		"DATA_DIR=" + a.dataDir,
		"STATIC_DIR=" + a.feDir,
		"CORS_ORIGINS=*",
		"DOCKER_INSIDE=false",
	}
	if disableDocker {
		env = append(env, "DISABLE_DOCKER=true")
	}
	a.serverCmd.Env = append(os.Environ(), env...)
	a.serverCmd.Stdout = a.logFile
	a.serverCmd.Stderr = a.logFile

	if err := a.serverCmd.Start(); err != nil {
		return fmt.Errorf("启动后端失败：%v", err)
	}
	a.logger.Printf("Backend started with PID %d\n", a.serverCmd.Process.Pid)

	a.setStatus("backend", "正在等待后端就绪...", 65)
	a.logger.Println("Waiting for backend to be ready")
	for i := 0; i < 30; i++ {
		if conn, err := net.DialTimeout("tcp", net.JoinHostPort(pgHost, serverPort), 1*time.Second); err == nil {
			conn.Close()
			break
		}
		time.Sleep(1 * time.Second)
	}

	if a.serverCmd.Process != nil {
		// Quick health check: if the process died, the port will never open.
		if a.serverCmd.ProcessState != nil && a.serverCmd.ProcessState.Exited() {
			return fmt.Errorf("后端进程已退出")
		}
	}

	a.logger.Println("Backend is ready")
	return nil
}

func (a *App) setupPostgresCmd(cmd *exec.Cmd) {
	runHidden(cmd)

	cmd.Dir = filepath.Dir(a.pgDataDir)
	pgBinDir := filepath.Dir(cmd.Path)
	minimalPath := "C:\\Windows\\system32;C:\\Windows;C:\\Windows\\System32\\Wbem;" + pgBinDir

	cmd.Env = []string{
		"PGDATA=" + a.pgDataDir,
		"PATH=" + minimalPath,
		"SystemRoot=C:\\Windows",
		"windir=C:\\Windows",
		"COMSPEC=C:\\Windows\\system32\\cmd.exe",
		"TEMP=" + os.TempDir(),
		"TMP=" + os.TempDir(),
		"LC_ALL=C",
		"LC_MESSAGES=C",
		"PGCLIENTENCODING=UTF8",
	}
}

func (a *App) createPasswordFile() string {
	pwFile := filepath.Join(a.logDir, "pgpassword.txt")
	_ = os.WriteFile(pwFile, []byte(pgPassword+"\n"), 0600)
	return pwFile
}

func (a *App) setStatus(step, message string, progress int) {
	a.mu.Lock()
	a.status = Status{Step: step, Message: message, Progress: progress}
	a.mu.Unlock()
	a.emitStatus()
}

func (a *App) setError(message string, err error, canRetry bool) {
	errText := ""
	if err != nil {
		errText = err.Error()
	}
	a.mu.Lock()
	a.status = Status{Step: "error", Message: message, Error: errText, CanRetry: canRetry}
	a.mu.Unlock()
	a.emitStatus()
	a.logError("%s: %v", message, err)
}

func (a *App) emitStatus() {
	if a.ctx == nil {
		return
	}
	a.mu.RLock()
	s := a.status
	a.mu.RUnlock()
	wailsRuntime.EventsEmit(a.ctx, "status", s)
}

func (a *App) logError(format string, v ...interface{}) {
	if a.logger != nil {
		a.logger.Printf(format+"\n", v...)
	}
}

// Helpers kept close to the original launcher behaviour.

func runHidden(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
	cmd.SysProcAttr.CreationFlags = syscall.CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW
}

func choosePostgresDir(baseDir string) string {
	srcDir := filepath.Join(baseDir, "postgres")
	if !isASCIIPath(srcDir) {
		panic(fmt.Sprintf(
			"安装路径包含非 ASCII 字符：%s\n\nPostgreSQL 无法在该路径下初始化，请将 Bee-Portable 文件夹移动到纯英文路径，例如：C:\\Bee-Portable",
			baseDir,
		))
	}
	return srcDir
}

func chooseDataDir(baseDir string) string {
	if isASCIIPath(baseDir) {
		return filepath.Join(baseDir, "data")
	}
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		localAppData = os.Getenv("APPDATA")
	}
	if localAppData == "" {
		localAppData = os.TempDir()
	}
	return filepath.Join(localAppData, "Bee", "data")
}

func findAvailablePort(host string, start, end int) string {
	for port := start; port <= end; port++ {
		addr := fmt.Sprintf("%s:%d", host, port)
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			ln.Close()
			return strconv.Itoa(port)
		}
	}
	return ""
}

func readPostmasterPort(pgDataDir string) string {
	pidFile := filepath.Join(pgDataDir, "postmaster.pid")
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) < 4 {
		return ""
	}
	port := strings.TrimSpace(lines[3])
	if port == "" {
		return ""
	}
	if _, err := strconv.Atoi(port); err != nil {
		return ""
	}
	return port
}

func cleanStalePostmasterPid(pgDataDir string, logger *log.Logger) {
	pidFile := filepath.Join(pgDataDir, "postmaster.pid")
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return
	}
	pidStr := strings.TrimSpace(lines[0])
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return
	}
	proc, err := os.FindProcess(pid)
	if err != nil || proc == nil {
		logger.Printf("Removing stale postmaster.pid (PID %d not running)\n", pid)
		_ = os.Remove(pidFile)
	}
}

func isASCIIPath(s string) bool {
	for _, r := range s {
		if r > 127 {
			return false
		}
	}
	return true
}
