package singbox

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/transocks-headless/transocks-headless/internal/config"
	"github.com/transocks-headless/transocks-headless/internal/provider"
)

func TestGenerateAndRedact(t *testing.T) {
	cfg := config.Defaults()
	candidates := []provider.Candidate{{
		Tag: "ss-01", Type: "shadowsocks", Server: "server.example",
		Port: 443, Password: "top-secret", Method: "aes-256-gcm",
	}}
	data, err := Generate(cfg, candidates)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"urltest"`) || !strings.Contains(string(data), `"geoip-cn"`) {
		t.Fatalf("missing selection or compatibility route: %s", data)
	}
	if strings.Contains(string(Redacted(data)), "top-secret") {
		t.Fatal("redaction failed")
	}
}

func TestGenerateDeterministicAndResilientSelection(t *testing.T) {
	cfg := config.Defaults()
	first := provider.Candidate{
		Tag: "ss-a", Type: "shadowsocks", Server: "a.example",
		Port: 443, Password: "a", Method: "aes-256-gcm",
	}
	second := provider.Candidate{
		Tag: "ss-b", Type: "shadowsocks", Server: "b.example",
		Port: 443, Password: "b", Method: "aes-256-gcm",
	}
	one, err := Generate(cfg, []provider.Candidate{first, second})
	if err != nil {
		t.Fatal(err)
	}
	two, err := Generate(cfg, []provider.Candidate{second, first})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(one, two) {
		t.Fatal("candidate order changed generated configuration")
	}
	text := string(one)
	if !strings.Contains(text, `"process_name"`) ||
		!strings.Contains(text, `"interrupt_exist_connections": true`) {
		t.Fatal("missing controller bypass or connection interruption")
	}
}

func TestGenerateRejectsDuplicateTags(t *testing.T) {
	cfg := config.Defaults()
	candidate := provider.Candidate{
		Tag: "duplicate", Type: "shadowsocks", Server: "a.example",
		Port: 443, Password: "a", Method: "aes-256-gcm",
	}
	if _, err := Generate(cfg, []provider.Candidate{candidate, candidate}); err == nil {
		t.Fatal("expected duplicate tag failure")
	}
}

func TestGeneratedConfigAcceptedBySingBox(t *testing.T) {
	binary := os.Getenv("SING_BOX_BINARY")
	if binary == "" {
		t.Skip("SING_BOX_BINARY not set")
	}
	cfg := config.Defaults()
	cfg.Transparent = false
	for _, routeMode := range []string{"compatibility", "full"} {
		t.Run(routeMode, func(t *testing.T) {
			cfg.RouteMode = routeMode
			data, err := Generate(cfg, []provider.Candidate{{
				Tag: "ss-01", Type: "shadowsocks", Server: "127.0.0.1",
				Port: 8388, Password: "test-only", Method: "aes-256-gcm",
			}})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			output, err := exec.Command(binary, "check", "-c", path).CombinedOutput()
			if err != nil {
				t.Fatalf("sing-box rejected generated config: %v\n%s\nconfig:\n%s", err, output, Redacted(data))
			}
		})
	}
}
