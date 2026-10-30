package supervisor

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/transocks-headless/transocks-headless/internal/config"
	"github.com/transocks-headless/transocks-headless/internal/provider"
)

func TestMain(m *testing.M) {
	if os.Getenv("TRANSOCKS_TEST_CORE") == "1" {
		if delay, err := time.ParseDuration(os.Getenv("TRANSOCKS_TEST_CORE_DELAY")); err == nil {
			time.Sleep(delay)
		}
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

type sessionTestProvider struct {
	authenticate func(context.Context, config.Credentials) (provider.Session, error)
	candidates   func(context.Context, provider.Session) ([]provider.Candidate, error)
}

func (p sessionTestProvider) Authenticate(ctx context.Context, credentials config.Credentials) (provider.Session, error) {
	return p.authenticate(ctx, credentials)
}

func (p sessionTestProvider) Candidates(ctx context.Context, session provider.Session) ([]provider.Candidate, error) {
	return p.candidates(ctx, session)
}

func TestCandidateRefreshReusesSession(t *testing.T) {
	for _, expiry := range []int64{0, time.Now().Add(time.Hour).Unix()} {
		logins := 0
		manager := New(config.Defaults(), sessionTestProvider{
			authenticate: func(context.Context, config.Credentials) (provider.Session, error) {
				logins++
				return provider.Session{Token: "bearer", TokenExp: expiry}, nil
			},
			candidates: func(_ context.Context, session provider.Session) ([]provider.Candidate, error) {
				if session.Token != "bearer" {
					t.Fatalf("unexpected session: %+v", session)
				}
				return []provider.Candidate{{Tag: "test"}}, nil
			},
		}, config.Credentials{}, "test")
		for index := 0; index < 3; index++ {
			if _, err := manager.fetchCandidates(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		if logins != 1 {
			t.Fatalf("expiry=%d caused %d logins, want 1", expiry, logins)
		}
	}
}

func TestCandidateRefreshRenewsExpiringSession(t *testing.T) {
	logins := 0
	manager := New(config.Defaults(), sessionTestProvider{
		authenticate: func(context.Context, config.Credentials) (provider.Session, error) {
			logins++
			return provider.Session{Token: "renewed", TokenExp: time.Now().Add(time.Hour).Unix()}, nil
		},
		candidates: func(_ context.Context, session provider.Session) ([]provider.Candidate, error) {
			if session.Token != "renewed" {
				t.Fatal("expiring token was used")
			}
			return nil, nil
		},
	}, config.Credentials{}, "test")
	manager.session = provider.Session{Token: "expiring", TokenExp: time.Now().Add(30 * time.Second).Unix()}
	if _, err := manager.fetchCandidates(context.Background()); err != nil {
		t.Fatal(err)
	}
	if logins != 1 {
		t.Fatalf("got %d renewal logins", logins)
	}
}

func TestCandidateNetworkFailurePreservesSession(t *testing.T) {
	logins := 0
	networkErr := errors.New("temporary network failure")
	manager := New(config.Defaults(), sessionTestProvider{
		authenticate: func(context.Context, config.Credentials) (provider.Session, error) {
			logins++
			return provider.Session{Token: "bearer"}, nil
		},
		candidates: func(context.Context, provider.Session) ([]provider.Candidate, error) {
			return nil, networkErr
		},
	}, config.Credentials{}, "test")
	for index := 0; index < 3; index++ {
		if _, err := manager.fetchCandidates(context.Background()); !errors.Is(err, networkErr) {
			t.Fatalf("unexpected error %v", err)
		}
	}
	if logins != 1 || manager.session.Token != "bearer" {
		t.Fatalf("network failure invalidated session: logins=%d", logins)
	}
}

func TestAuthenticationRejectionRetriesOnce(t *testing.T) {
	for _, rejectRenewed := range []bool{false, true} {
		logins, attempts := 0, 0
		manager := New(config.Defaults(), sessionTestProvider{
			authenticate: func(context.Context, config.Credentials) (provider.Session, error) {
				logins++
				return provider.Session{Token: "renewed"}, nil
			},
			candidates: func(context.Context, provider.Session) ([]provider.Candidate, error) {
				attempts++
				if attempts == 1 || rejectRenewed {
					return nil, &provider.APIError{Code: 40015}
				}
				return []provider.Candidate{{Tag: "test"}}, nil
			},
		}, config.Credentials{}, "test")
		manager.session = provider.Session{Token: "rejected"}
		_, err := manager.fetchCandidates(context.Background())
		if (err != nil) != rejectRenewed || logins != 1 || attempts != 2 {
			t.Fatalf("rejectRenewed=%v: error=%v logins=%d attempts=%d", rejectRenewed, err, logins, attempts)
		}
		if rejectRenewed && manager.session.Token != "" {
			t.Fatal("rejected renewed session retained")
		}
	}
}

func TestRefreshTriggersShareFailureDeadline(t *testing.T) {
	logins := 0
	cfg := config.Defaults()
	cfg.StateFile = filepath.Join(t.TempDir(), "status.json")
	manager := New(cfg, sessionTestProvider{
		authenticate: func(context.Context, config.Credentials) (provider.Session, error) {
			logins++
			return provider.Session{}, errors.New("provider unavailable")
		},
	}, config.Credentials{}, "test")
	backoff := time.Minute
	if delay := manager.runScheduledRefresh(context.Background(), &backoff); delay <= 0 {
		t.Fatalf("invalid first retry delay %s", delay)
	}
	for index := 0; index < 10; index++ {
		if delay := manager.runScheduledRefresh(context.Background(), &backoff); delay <= 0 {
			t.Fatalf("invalid gated retry delay %s", delay)
		}
	}
	if logins != 1 || manager.state.RefreshFailures != 1 || backoff != 2*time.Minute {
		t.Fatalf("early triggers bypassed deadline: logins=%d failures=%d backoff=%s", logins, manager.state.RefreshFailures, backoff)
	}
	manager.nextRefreshRetry = time.Now().Add(-time.Second)
	manager.runScheduledRefresh(context.Background(), &backoff)
	if logins != 2 {
		t.Fatalf("due retry did not run: logins=%d", logins)
	}
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

func TestHealthActivelyTestsTunnelBeforeReadingHistory(t *testing.T) {
	probed := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/proxies/auto/delay" {
			if r.URL.Query().Get("url") == "" || r.URL.Query().Get("timeout") == "" {
				t.Error("missing delay test parameters")
			}
			probed = true
			_, _ = w.Write([]byte(`{"delay":12}`))
			return
		}
		if !probed {
			t.Error("history read before live probe")
		}
		_, _ = w.Write([]byte(`{"now":"ss-a","history":[{"time":"` + time.Now().UTC().Format(time.RFC3339Nano) + `","delay":12}]}`))
	}))
	defer server.Close()
	cfg := config.Defaults()
	cfg.APIControllerListen = strings.TrimPrefix(server.URL, "http://")
	manager := New(cfg, nil, config.Credentials{}, "test")
	defer manager.healthTransport.CloseIdleConnections()
	if selected, delay, err := manager.readCoreHealth(context.Background()); err != nil || selected != "ss-a" || delay != 12 {
		t.Fatalf("health: %s %d %v", selected, delay, err)
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
	t.Setenv("TRANSOCKS_TEST_CORE_DELAY", "2100ms")
	t.Setenv("TRANSOCKS_TEST_CORE_LISTEN", address)
	cfg := config.Defaults()
	cfg.CoreBinary = os.Args[0]
	cfg.APIControllerListen = address
	cfg.RunDir = t.TempDir()
	manager := New(cfg, nil, config.Credentials{}, "test")
	defer manager.core.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := manager.startCore(ctx); err != nil {
		t.Fatal(err)
	}
}
