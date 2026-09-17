//go:build windows || linux || darwin

package docker

import (
	"archive/tar"
	"bufio"
	"context"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"pentagi/pkg/config"
	"pentagi/pkg/database"
	"pentagi/pkg/queue"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/sirupsen/logrus"
)

const localContainerIDTemplate = "local-%d"
const localContainerDirTemplate = "flow-%d"

type localContainer struct {
	name    string
	workDir string
	dbID    int64
	status  database.ContainerStatus
	mu      sync.RWMutex
}

type localExec struct {
	id        string
	container string
	cmd       []string
	workDir   string
	env       []string
	user      string
	tty       bool

	mu       sync.Mutex
	done     chan struct{}
	err      error
	exitCode int
	started  bool
}

type localClient struct {
	db       database.Querier
	dataDir  string
	defImage string
	logger   *logrus.Logger

	cntMu        sync.RWMutex
	containers   map[string]*localContainer
	containersID map[string]*localContainer

	execMu    sync.Mutex
	execIDSeq int64
	execs     map[string]*localExec
}

func NewLocalClient(db database.Querier, cfg *config.Config) (DockerClient, error) {
	dataDir, err := filepath.Abs(cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute data dir: %w", err)
	}
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data dir: %w", err)
	}

	defImage := strings.ToLower(cfg.DockerDefaultImage)
	if defImage == "" {
		defImage = defaultImage
	}

	logger := logrus.StandardLogger()
	logger.Info("Using local execution mode (Docker disabled)")

	return &localClient{
		db:           db,
		dataDir:      dataDir,
		defImage:     defImage,
		logger:       logger,
		containers:   make(map[string]*localContainer),
		containersID: make(map[string]*localContainer),
		execs:        make(map[string]*localExec),
	}, nil
}

func (lc *localClient) RunContainer(
	ctx context.Context,
	containerName string,
	containerType database.ContainerType,
	flowID int64,
	config *container.Config,
	hostConfig *container.HostConfig,
) (database.Container, error) {
	if config == nil {
		return database.Container{}, fmt.Errorf("no config found for container %s", containerName)
	}

	workDir := filepath.Join(lc.dataDir, fmt.Sprintf(localContainerDirTemplate, flowID))
	if err := os.MkdirAll(workDir, 0755); err != nil {
		return database.Container{}, fmt.Errorf("failed to create work directory: %w", err)
	}

	localID := fmt.Sprintf(localContainerIDTemplate, flowID)

	logger := lc.logger.WithContext(ctx).WithFields(logrus.Fields{
		"image":    config.Image,
		"name":     containerName,
		"type":     containerType,
		"flow_id":  flowID,
		"work_dir": workDir,
	})
	logger.Info("running local container")

	dbContainer, err := lc.db.CreateContainer(ctx, database.CreateContainerParams{
		Type:     containerType,
		Name:     containerName,
		Image:    config.Image,
		Status:   database.ContainerStatusStarting,
		FlowID:   flowID,
		LocalID:  database.StringToNullString(localID),
		LocalDir: database.StringToNullString(workDir),
	})
	if err != nil {
		return database.Container{}, fmt.Errorf("failed to create container in database: %w", err)
	}

	lc.cntMu.Lock()
	cnt := &localContainer{
		name:    containerName,
		workDir: workDir,
		dbID:    dbContainer.ID,
		status:  database.ContainerStatusRunning,
	}
	lc.containers[containerName] = cnt
	lc.containersID[localID] = cnt
	lc.cntMu.Unlock()

	dbContainer, err = lc.db.UpdateContainerStatusLocalID(ctx, database.UpdateContainerStatusLocalIDParams{
		Status:  database.ContainerStatusRunning,
		LocalID: database.StringToNullString(localID),
		ID:      dbContainer.ID,
	})
	if err != nil {
		logger.WithError(err).Error("failed to update container info in database")
	}

	return dbContainer, nil
}

func (lc *localClient) StopContainer(ctx context.Context, containerID string, dbID int64) error {
	logger := lc.logger.WithContext(ctx).WithField("local_id", containerID)
	logger.Info("initiating local container shutdown sequence")

	lc.cntMu.Lock()
	if cnt, ok := lc.containersID[containerID]; ok {
		cnt.mu.Lock()
		cnt.status = database.ContainerStatusStopped
		cnt.mu.Unlock()
	}
	lc.cntMu.Unlock()

	_, err := lc.db.UpdateContainerStatus(ctx, database.UpdateContainerStatusParams{
		Status: database.ContainerStatusStopped,
		ID:     dbID,
	})
	if err != nil {
		return fmt.Errorf("database status update failed during container stop: %w", err)
	}

	logger.Info("local container shutdown completed successfully")
	return nil
}

func (lc *localClient) RemoveContainer(ctx context.Context, containerID string, dbID int64) error {
	logger := lc.logger.WithContext(ctx).WithField("local_id", containerID)
	logger.Info("removing local container and associated resources")

	if err := lc.StopContainer(ctx, containerID, dbID); err != nil {
		return fmt.Errorf("failed to stop local container: %w", err)
	}

	lc.cntMu.Lock()
	if cnt, ok := lc.containersID[containerID]; ok {
		delete(lc.containers, cnt.name)
		delete(lc.containersID, containerID)
		_ = os.RemoveAll(cnt.workDir)
	}
	lc.cntMu.Unlock()

	_, err := lc.db.UpdateContainerStatus(ctx, database.UpdateContainerStatusParams{
		Status: database.ContainerStatusDeleted,
		ID:     dbID,
	})
	if err != nil {
		return fmt.Errorf("failed to update container status to deleted: %w", err)
	}

	logger.Info("local container removed")
	return nil
}

func (lc *localClient) Cleanup(ctx context.Context) error {
	logger := lc.logger.WithContext(ctx).WithField("local", "cleanup")
	logger.Info("cleaning up local containers and making all flows finished...")

	flows, err := lc.db.GetFlows(ctx)
	if err != nil {
		return fmt.Errorf("failed to get all flows: %w", err)
	}

	containers, err := lc.db.GetContainers(ctx)
	if err != nil {
		return fmt.Errorf("failed to get all containers: %w", err)
	}

	flowsStatusMap := make(map[int64]database.FlowStatus)
	for _, flow := range flows {
		flowsStatusMap[flow.ID] = flow.Status
	}
	flowContainersMap := make(map[int64][]database.Container)
	for _, container := range containers {
		flowContainersMap[container.FlowID] = append(flowContainersMap[container.FlowID], container)
	}

	var wg sync.WaitGroup
	removeContainer := func(containerID string, dbID int64) {
		defer wg.Done()
		logger := logger.WithField("local_id", containerID)

		if err := lc.RemoveContainer(ctx, containerID, dbID); err != nil {
			logger.WithError(err).Errorf("failed to remove local container")
		}

		_, err := lc.db.UpdateContainerStatus(ctx, database.UpdateContainerStatusParams{
			Status: database.ContainerStatusDeleted,
			ID:     dbID,
		})
		if err != nil {
			logger.WithError(err).Errorf("failed to update container status to deleted")
		}
	}
	isAllContainersRunning := func(flowID int64) bool {
		containers, ok := flowContainersMap[flowID]
		if !ok || len(containers) == 0 {
			return false
		}
		for _, container := range containers {
			switch container.Status {
			case database.ContainerStatusStarting, database.ContainerStatusRunning:
				return false
			}
		}
		return true
	}
	markFlowAsFailed := func(flowID int64) {
		logger := logger.WithField("flow_id", flowID)
		_, err := lc.db.UpdateFlowStatus(ctx, database.UpdateFlowStatusParams{
			Status: database.FlowStatusFailed,
			ID:     flowID,
		})
		if err != nil {
			logger.WithError(err).Errorf("failed to update flow status to failed")
		}
	}

	for _, flow := range flows {
		switch flowsStatusMap[flow.ID] {
		case database.FlowStatusRunning, database.FlowStatusWaiting:
			if isAllContainersRunning(flow.ID) {
				continue
			}
			fallthrough
		case database.FlowStatusCreated:
			markFlowAsFailed(flow.ID)
			fallthrough
		default: // FlowStatusFinished, FlowStatusFailed
			for _, container := range flowContainersMap[flow.ID] {
				switch container.Status {
				case database.ContainerStatusStarting, database.ContainerStatusRunning:
					wg.Add(1)
					go removeContainer(container.LocalID.String, container.ID)
				}
			}
		}
	}

	wg.Wait()
	logger.Info("cleanup finished")

	return nil
}

func (lc *localClient) IsContainerRunning(ctx context.Context, containerID string) (bool, error) {
	lc.cntMu.RLock()
	cnt, ok := lc.containersID[containerID]
	lc.cntMu.RUnlock()
	if !ok {
		return false, nil
	}
	cnt.mu.RLock()
	status := cnt.status
	cnt.mu.RUnlock()
	return status == database.ContainerStatusRunning, nil
}

func (lc *localClient) GetDefaultImage() string {
	return lc.defImage
}

func (lc *localClient) ContainerExecCreate(
	ctx context.Context,
	containerName string,
	opts container.ExecOptions,
) (container.ExecCreateResponse, error) {
	lc.cntMu.RLock()
	cnt, ok := lc.containers[containerName]
	lc.cntMu.RUnlock()
	if !ok {
		return container.ExecCreateResponse{}, fmt.Errorf("container %s not found", containerName)
	}

	workDir := cnt.workDir
	if opts.WorkingDir != "" {
		workDir = lc.resolveContainerPath(cnt, opts.WorkingDir)
	}

	lc.execMu.Lock()
	defer lc.execMu.Unlock()
	lc.execIDSeq++
	execID := fmt.Sprintf("exec-%d", lc.execIDSeq)

	lc.execs[execID] = &localExec{
		id:        execID,
		container: containerName,
		cmd:       opts.Cmd,
		workDir:   workDir,
		env:       opts.Env,
		user:      opts.User,
		tty:       opts.Tty,
		done:      make(chan struct{}),
	}

	return container.ExecCreateResponse{ID: execID}, nil
}

func (lc *localClient) ContainerExecAttach(
	ctx context.Context,
	execID string,
	config container.ExecAttachOptions,
) (types.HijackedResponse, error) {
	lc.execMu.Lock()
	exec, ok := lc.execs[execID]
	if !ok {
		lc.execMu.Unlock()
		return types.HijackedResponse{}, fmt.Errorf("exec %s not found", execID)
	}
	if exec.started {
		lc.execMu.Unlock()
		return types.HijackedResponse{}, fmt.Errorf("exec %s already started", execID)
	}
	exec.started = true
	lc.execMu.Unlock()

	pr, pw := io.Pipe()

	go func() {
		defer close(exec.done)
		defer pw.Close()

		if len(exec.cmd) == 0 {
			return
		}

		cmd := lc.buildCommand(ctx, exec)
		cmd.Dir = exec.workDir
		cmd.Env = append(os.Environ(), exec.env...)
		if attr := windowsSysProcAttr(); attr != nil {
			cmd.SysProcAttr = attr
		}

		if exec.tty {
			cmd.Stdout = pw
			cmd.Stderr = pw
		} else {
			cmd.Stdout = pw
			cmd.Stderr = pw
		}

		err := cmd.Run()
		exec.mu.Lock()
		exec.err = err
		if cmd.ProcessState != nil {
			exec.exitCode = cmd.ProcessState.ExitCode()
		} else if err != nil {
			exec.exitCode = 127
		}
		exec.mu.Unlock()
	}()

	return types.HijackedResponse{
		Reader: bufio.NewReader(pr),
		Conn:   &nopConn{},
	}, nil
}

func (lc *localClient) buildCommand(ctx context.Context, le *localExec) *exec.Cmd {
	if runtime.GOOS == "windows" {
		// Prefer bash (Git Bash / MSYS2 / WSL) for POSIX commands used by tools.
		if bashPath, err := exec.LookPath("bash"); err == nil {
			return exec.CommandContext(ctx, bashPath, "-c", strings.Join(le.cmd, " "))
		}
	}

	if len(le.cmd) == 1 {
		return exec.CommandContext(ctx, le.cmd[0])
	}
	return exec.CommandContext(ctx, le.cmd[0], le.cmd[1:]...)
}

func (lc *localClient) ContainerExecInspect(
	ctx context.Context,
	execID string,
) (container.ExecInspect, error) {
	lc.execMu.Lock()
	exec, ok := lc.execs[execID]
	lc.execMu.Unlock()
	if !ok {
		return container.ExecInspect{}, fmt.Errorf("exec %s not found", execID)
	}

	select {
	case <-exec.done:
	case <-ctx.Done():
		return container.ExecInspect{}, ctx.Err()
	}

	exec.mu.Lock()
	exitCode := exec.exitCode
	exec.mu.Unlock()

	return container.ExecInspect{
		ExecID:   execID,
		ExitCode: exitCode,
	}, nil
}

func (lc *localClient) ContainerStatPath(
	ctx context.Context,
	containerID string,
	p string,
) (container.PathStat, error) {
	cnt, err := lc.getContainerByID(containerID)
	if err != nil {
		return container.PathStat{}, err
	}
	localPath := lc.resolveContainerPath(cnt, p)
	info, err := os.Stat(localPath)
	if err != nil {
		return container.PathStat{}, err
	}
	return container.PathStat{
		Name:  filepath.Base(localPath),
		Size:  info.Size(),
		Mode:  info.Mode(),
		Mtime: info.ModTime(),
	}, nil
}

func (lc *localClient) ListContainerDir(
	ctx context.Context,
	containerID string,
	dirPath string,
) ([]container.PathStat, error) {
	if strings.TrimSpace(dirPath) == "" {
		dirPath = WorkFolderPathInContainer
	}

	cnt, err := lc.getContainerByID(containerID)
	if err != nil {
		return nil, err
	}

	localDir := lc.resolveContainerPath(cnt, dirPath)
	info, err := os.Stat(localDir)
	if err != nil {
		return nil, fmt.Errorf("failed to stat container path '%s': %w", dirPath, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("container path '%s' is not a directory", dirPath)
	}

	entries, err := os.ReadDir(localDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory '%s': %w", dirPath, err)
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if name == "" {
			continue
		}
		names = append(names, name)
	}

	input := make(chan containerPathStatRequest, len(names))
	outputStats := make(chan containerPathStatResult)
	for _, name := range names {
		input <- containerPathStatRequest{
			name: name,
			path: path.Join(dirPath, name),
		}
	}
	close(input)

	statQueue := queue.NewQueue(input, outputStats, containerListWorkers, func(req containerPathStatRequest) (containerPathStatResult, error) {
		stat, err := lc.ContainerStatPath(ctx, containerID, req.path)
		return containerPathStatResult{
			name: req.name,
			stat: stat,
			err:  err,
		}, nil
	})
	if err := statQueue.Start(); err != nil {
		return nil, fmt.Errorf("failed to start container stat queue: %w", err)
	}

	stats := make([]container.PathStat, 0, len(names))
	for range names {
		result := <-outputStats
		if result.err != nil {
			_ = statQueue.Stop()
			return nil, fmt.Errorf("failed to stat container entry '%s': %w", result.name, result.err)
		}
		stats = append(stats, result.stat)
	}
	_ = statQueue.Stop()

	return stats, nil
}

func (lc *localClient) CopyToContainer(
	ctx context.Context,
	containerID string,
	dstPath string,
	content io.Reader,
	options container.CopyToContainerOptions,
) error {
	cnt, err := lc.getContainerByID(containerID)
	if err != nil {
		return err
	}
	localDst := lc.resolveContainerPath(cnt, dstPath)

	if err := os.MkdirAll(localDst, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory '%s': %w", localDst, err)
	}

	tr := tar.NewReader(content)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		target := filepath.Join(localDst, filepath.Clean(header.Name))
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(localDst)) {
			return fmt.Errorf("invalid tar entry: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to create directory '%s': %w", target, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("failed to create parent directory for '%s': %w", target, err)
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("failed to create file '%s': %w", target, err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fmt.Errorf("failed to write file '%s': %w", target, err)
			}
			f.Close()
		}
	}

	return nil
}

func (lc *localClient) CopyFromContainer(
	ctx context.Context,
	containerID string,
	srcPath string,
) (io.ReadCloser, container.PathStat, error) {
	cnt, err := lc.getContainerByID(containerID)
	if err != nil {
		return nil, container.PathStat{}, err
	}
	localSrc := lc.resolveContainerPath(cnt, srcPath)

	info, err := os.Stat(localSrc)
	if err != nil {
		return nil, container.PathStat{}, err
	}
	stat := container.PathStat{
		Name:  filepath.Base(localSrc),
		Size:  info.Size(),
		Mode:  info.Mode(),
		Mtime: info.ModTime(),
	}

	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		tw := tar.NewWriter(pw)
		defer tw.Close()

		if info.IsDir() {
			_ = filepath.WalkDir(localSrc, func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				rel, _ := filepath.Rel(localSrc, p)
				if rel == "." {
					return nil
				}
				fileInfo, infoErr := d.Info()
				if infoErr != nil {
					return infoErr
				}
				header, headerErr := tar.FileInfoHeader(fileInfo, "")
				if headerErr != nil {
					return headerErr
				}
				header.Name = filepath.ToSlash(rel)
				if err := tw.WriteHeader(header); err != nil {
					return err
				}
				if !d.IsDir() {
					f, ferr := os.Open(p)
					if ferr != nil {
						return ferr
					}
					_, _ = io.Copy(tw, f)
					f.Close()
				}
				return nil
			})
		} else {
			header, _ := tar.FileInfoHeader(info, "")
			header.Name = filepath.Base(localSrc)
			_ = tw.WriteHeader(header)
			f, _ := os.Open(localSrc)
			_, _ = io.Copy(tw, f)
			f.Close()
		}
	}()

	return pr, stat, nil
}

func (lc *localClient) getContainerByID(containerID string) (*localContainer, error) {
	lc.cntMu.RLock()
	cnt, ok := lc.containersID[containerID]
	lc.cntMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("container %s not found", containerID)
	}
	return cnt, nil
}

func (lc *localClient) resolveContainerPath(cnt *localContainer, containerPath string) string {
	if containerPath == "" || containerPath == WorkFolderPathInContainer {
		return cnt.workDir
	}
	if strings.HasPrefix(containerPath, WorkFolderPathInContainer+"/") {
		rel := strings.TrimPrefix(containerPath, WorkFolderPathInContainer+"/")
		return filepath.Join(cnt.workDir, filepath.FromSlash(rel))
	}
	if path.IsAbs(containerPath) {
		// Absolute paths outside /work are mapped relative to the work dir.
		return filepath.Join(cnt.workDir, filepath.FromSlash(path.Base(containerPath)))
	}
	return filepath.Join(cnt.workDir, filepath.FromSlash(containerPath))
}

// parseFlowID extracts the flow ID from a local container ID such as "local-123".
func parseFlowID(containerID string) (int64, error) {
	parts := strings.Split(containerID, "-")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid local container id: %s", containerID)
	}
	return strconv.ParseInt(parts[1], 10, 64)
}

// nopConn is a minimal net.Conn implementation used for local exec output streams.
type nopConn struct {
	closed bool
	mu     sync.Mutex
}

func (c *nopConn) Read(_ []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, io.EOF
	}
	return 0, nil
}

func (c *nopConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *nopConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}
func (c *nopConn) LocalAddr() net.Addr                { return nil }
func (c *nopConn) RemoteAddr() net.Addr               { return nil }
func (c *nopConn) SetDeadline(_ time.Time) error      { return nil }
func (c *nopConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *nopConn) SetWriteDeadline(_ time.Time) error { return nil }