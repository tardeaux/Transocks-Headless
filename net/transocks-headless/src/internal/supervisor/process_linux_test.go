//go:build linux

package supervisor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCoreCheckOutputIsBounded(t *testing.T) {
	script := filepath.Join(t.TempDir(), "fake-core")
	body := "#!/bin/sh\nhead -c 131072 /dev/zero >&2\nexit 1\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	process := newCoreProcess(script, "/unused")
	err := process.Check(context.Background())
	if err == nil {
		t.Fatal("expected check failure")
	}
	if len(err.Error()) > 1024 {
		t.Fatalf("diagnostic was not bounded: %d bytes", len(err.Error()))
	}
}

func TestCoreStopTerminatesProcessGroup(t *testing.T) {
	script := filepath.Join(t.TempDir(), "fake-core")
	body := `#!/bin/sh
if [ "$1" = "run" ]; then
  sleep 300 &
  child=$!
  trap 'kill "$child" 2>/dev/null; wait "$child" 2>/dev/null; exit 0' TERM
  wait "$child"
fi
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	process := newCoreProcess(script, "/unused")
	for index := 0; index < 5; index++ {
		if err := process.Start(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
		process.Stop()
		if process.Running() {
			t.Fatalf("process still running after stop iteration %d", index)
		}
		done := process.Done()
		deadline := time.After(time.Second)
		for {
			select {
			case _, open := <-done:
				if !open {
					goto stopped
				}
			case <-deadline:
				t.Fatalf("done channel still open after stop iteration %d", index)
			}
		}
	stopped:
	}
}

func TestWriteAtomicReplacesWithoutPartialData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	if err := writeAtomic(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(path, []byte(strings.Repeat("new", 1024)), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != strings.Repeat("new", 1024) {
		t.Fatal("atomic replacement content mismatch")
	}
}
