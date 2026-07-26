package supervisor

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/transocks-headless/transocks-headless/internal/config"
)

func TestMain(m *testing.M) {
	if os.Getenv("TRANSOCKS_TEST_CORE") == "1" {
		listener, err := net.Listen("tcp", os.Getenv("TRANSOCKS_TEST_CORE_LISTEN"))
		if err != nil {
			os.Exit(2)
		}
		server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"now":"test-proxy","history":[]}`))
		})}
		_ = server.Serve(listener)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestBoundedBuffer(t *testing.T) {
	buffer := &boundedBuffer{limit: 4}
	if count, err := buffer.Write([]byte("123456")); err != nil || count != 6 {
		t.Fatalf("write = %d, %v", count, err)
	}
	if got := buffer.String(); got != "1234" {
		t.Fatalf("buffer = %q", got)
	}
}

func TestInputBounds(t *testing.T) {
	if data, err := readHTTPBody(strings.NewReader("1234"), 4); err != nil || string(data) != "1234" {
		t.Fatalf("exact limit failed: %q, %v", data, err)
	}
	if _, err := readHTTPBody(strings.NewReader("12345"), 4); err == nil {
		t.Fatal("expected oversized input error")
	}
}

func TestBackoffSaturates(t *testing.T) {
	if got := nextBackoff(8*time.Second, 10*time.Second); got != 10*time.Second {
		t.Fatalf("backoff = %s", got)
	}
	if got := nextBackoff(10*time.Second, 10*time.Second); got != 10*time.Second {
		t.Fatalf("maximum backoff = %s", got)
	}
	for i := 0; i < 128; i++ {
		got := jitterDuration(time.Second)
		if got < 800*time.Millisecond || got > 1200*time.Millisecond {
			t.Fatalf("jitter out of range: %s", got)
		}
	}
}

func TestWaitContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	if err := waitContext(ctx, time.Hour); err == nil {
		t.Fatal("expected cancellation")
	}
	if time.Since(started) > 100*time.Millisecond {
		t.Fatal("cancellation was not prompt")
	}
}

func TestReadCoreHealthRejectsStaleSample(t *testing.T) {
	server := &http.Server{}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"now":"ss-a","history":[{"time":"2000-01-01T00:00:00Z","delay":20}]}`))
	})
	go func() { _ = server.Serve(listener) }()
	defer server.Close()

	cfg := config.Defaults()
	cfg.APIControllerListen = listener.Addr().String()
	manager := New(cfg, nil, config.Credentials{}, "test")
	defer manager.healthTransport.CloseIdleConnections()
	if _, _, err := manager.readCoreHealth(context.Background()); err == nil {
		t.Fatal("expected stale sample error")
	}
}

func TestSecureCachePermissionsAndBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")
	if err := os.WriteFile(path, []byte("1234"), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := readSecureFile(path, 4); err != nil || string(data) != "1234" {
		t.Fatalf("secure read failed: %q, %v", data, err)
	}
	if _, err := readSecureFile(path, 3); err == nil {
		t.Fatal("expected cache size error")
	}
}

func TestStartCoreWaitsForControllerReadiness(t *testing.T) {
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.Addr().String()
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TRANSOCKS_TEST_CORE", "1")
	t.Setenv("TRANSOCKS_TEST_CORE_LISTEN", address)
	cfg := config.Defaults()
	cfg.CoreBinary = os.Args[0]
	cfg.APIControllerListen = address
	cfg.RunDir = t.TempDir()
	manager := New(cfg, nil, config.Credentials{}, "test")
	defer manager.core.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := manager.startCore(ctx); err != nil {
		t.Fatal(err)
	}
}
