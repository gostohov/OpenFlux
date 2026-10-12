//go:build !windows

package main

import (
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func lockManaged(file *os.File) error { return unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB) }
func startOwnedPlatform(cmd *exec.Cmd) (func(), error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	pid := cmd.Process.Pid
	return func() {
		_ = syscall.Kill(-pid, syscall.SIGTERM)
		time.Sleep(200 * time.Millisecond)
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	}, nil
}

func foregroundManaged(cmd *exec.Cmd) func() {
	file, ok := cmd.Stdin.(*os.File)
	if !ok {
		return func() {}
	}
	fd := int(file.Fd())
	previous, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
	if err != nil {
		return func() {}
	}
	signal.Ignore(syscall.SIGTTOU)
	if unix.IoctlSetPointerInt(fd, unix.TIOCSPGRP, cmd.Process.Pid) != nil {
		signal.Reset(syscall.SIGTTOU)
		return func() {}
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGCONT)
	return func() { _ = unix.IoctlSetPointerInt(fd, unix.TIOCSPGRP, previous); signal.Reset(syscall.SIGTTOU) }
}
