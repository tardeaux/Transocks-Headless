package singbox

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestRuleSetSurvivesOfflineCoreRestart(t *testing.T) {
	binary := os.Getenv("SING_BOX_BINARY")
	if binary == "" {
		t.Skip("SING_BOX_BINARY not set")
	}
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(rulePath, []byte(`{"version":3,"rules":[{"ip_cidr":["192.0.2.0/24"]}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	srsPath := filepath.Join(dir, "rules.srs")
	if output, err := exec.Command(binary, "rule-set", "compile", "--output", srsPath, rulePath).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v %s", err, output)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, srsPath) }))
	defer server.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	cfg := config.Defaults()
	cfg.Transparent = false
	cfg.MixedListen = ""
	cfg.APIControllerListen = address
	cfg.RunDir = dir
	cfg.CacheFile = filepath.Join(dir, "last-known-good.json")
	cfg.GeoIPCNRuleSetURL = server.URL + "/rules.srs"
	data, err := Generate(cfg, []provider.Candidate{{Tag: "test", Type: "shadowsocks", Server: "127.0.0.1", Port: 8388, Password: "test", Method: "aes-256-gcm"}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	startAndStop := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, "run", "-c", path)
		var output bytes.Buffer
		cmd.Stdout = &output
		cmd.Stderr = &output
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		ready := false
		client := &http.Client{Timeout: 100 * time.Millisecond}
		for ctx.Err() == nil {
			response, err := client.Get("http://" + address + "/proxies/auto")
			if err == nil {
				_ = response.Body.Close()
				if response.StatusCode == 200 {
					ready = true
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
		_ = cmd.Process.Signal(os.Interrupt)
		_ = cmd.Wait()
		if !ready {
			t.Fatalf("core did not start: %s", output.String())
		}
	}
	startAndStop()
	if _, err := os.Stat(filepath.Join(dir, "sing-box-cache.db")); err != nil {
		t.Fatal(err)
	}
	server.Close()
	startAndStop()
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
