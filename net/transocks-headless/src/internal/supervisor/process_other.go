//go:build !linux

package supervisor

import (
	"os"
	"os/exec"
)

func configureManagedProcess(_ *exec.Cmd) {}

func interruptManagedProcess(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return cmd.Process.Signal(os.Interrupt)
}

func killManagedProcess(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}

func syncParentDirectory(string) error {
	return nil
}
