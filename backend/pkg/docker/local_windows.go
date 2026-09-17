//go:build windows

package docker

import "syscall"

func windowsSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{HideWindow: true}
}
