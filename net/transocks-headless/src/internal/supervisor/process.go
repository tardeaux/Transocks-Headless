package supervisor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

const (
	coreCheckTimeout   = 30 * time.Second
	maxCoreCheckOutput = 64 << 10
	coreStopTimeout    = 5 * time.Second
)

type coreProcess struct {
	binary string
	config string
	mu     sync.Mutex
	cmd    *exec.Cmd
	done   chan error
}

func newCoreProcess(binary, config string) *coreProcess {
	return &coreProcess{binary: binary, config: config}
}

func (p *coreProcess) Check(ctx context.Context) error {
	return p.CheckFile(ctx, p.config)
}

func (p *coreProcess) CheckFile(ctx context.Context, path string) error {
	checkCtx, cancel := context.WithTimeout(ctx, coreCheckTimeout)
	defer cancel()
	cmd := exec.CommandContext(checkCtx, p.binary, "check", "-c", path)
	output := &boundedBuffer{limit: maxCoreCheckOutput}
	cmd.Stdout = output
	cmd.Stderr = output
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("sing-box config check failed: %w: %s", err, truncate(output.String(), 512))
	}
	return nil
}

func (p *coreProcess) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd != nil {
		return errors.New("sing-box already running")
	}
	cmd := exec.Command(p.binary, "run", "-c", p.config)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = nil
	configureManagedProcess(cmd)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start sing-box: %w", err)
	}
	done := make(chan error, 1)
	p.cmd = cmd
	p.done = done
	go func() {
		err := cmd.Wait()
		p.mu.Lock()
		if p.cmd == cmd {
			p.cmd = nil
		}
		p.mu.Unlock()
		done <- err
		close(done)
	}()
	return nil
}

func (p *coreProcess) Done() <-chan error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done == nil {
		closed := make(chan error)
		close(closed)
		return closed
	}
	return p.done
}

func (p *coreProcess) Running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cmd != nil
}

func (p *coreProcess) Stop() {
	p.mu.Lock()
	cmd := p.cmd
	done := p.done
	p.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = interruptManagedProcess(cmd)
	timer := time.NewTimer(coreStopTimeout)
	defer timer.Stop()
	select {
	case <-done:
		return
	case <-timer.C:
		_ = killManagedProcess(cmd)
	}
	timer.Reset(coreStopTimeout)
	select {
	case <-done:
	case <-timer.C:
	}
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".transocks-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return syncParentDirectory(filepath.Dir(path))
}

type boundedBuffer struct {
	data  []byte
	limit int
}

func (b *boundedBuffer) Write(data []byte) (int, error) {
	accepted := len(data)
	remaining := b.limit - len(b.data)
	if remaining > 0 {
		if len(data) > remaining {
			data = data[:remaining]
		}
		b.data = append(b.data, data...)
	}
	return accepted, nil
}

func (b *boundedBuffer) String() string {
	return string(b.data)
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}
