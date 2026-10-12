package main

import (
	"os/exec"
	"sync"
	"time"
)

type ownedChild struct {
	cmd       *exec.Cmd
	done      chan struct{}
	err       error
	terminate func()
	once      sync.Once
}

func startOwned(cmd *exec.Cmd) (*ownedChild, error) {
	kill, err := startOwnedPlatform(cmd)
	if err != nil {
		return nil, err
	}
	child := &ownedChild{cmd: cmd, done: make(chan struct{}), terminate: kill}
	go func() { child.err = cmd.Wait(); close(child.done) }()
	return child, nil
}
func (c *ownedChild) stop() {
	c.once.Do(func() {
		c.terminate()
		select {
		case <-c.done:
		case <-time.After(3 * time.Second):
			_ = c.cmd.Process.Kill()
		}
	})
}
func (c *ownedChild) exitCode() int {
	<-c.done
	if c.err == nil {
		return 0
	}
	if code := c.cmd.ProcessState.ExitCode(); code > 0 {
		return code
	}
	return 1
}
