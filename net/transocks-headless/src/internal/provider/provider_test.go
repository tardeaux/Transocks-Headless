package provider

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/transocks-headless/transocks-headless/internal/config"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestExtractCandidates(t *testing.T) {
	configs := []remoteConfig{
		{SS: &remoteProxy{Server: "ss.example", Port: 443, Password: "secret", Method: "aes-256-gcm"}},
		{Trojan: &remoteProxy{Server: "tr.example", Port: 443, Password: "secret"}},
	}
	got := extractCandidates(configs)
	if len(got) != 2 {
		t.Fatalf("got %d candidates", len(got))
	}
	if got[0].Type != "shadowsocks" || got[1].Type != "trojan" {
		t.Fatalf("unexpected candidates: %#v", got)
	}
	if !got[1].TLS.Enabled || got[1].TLS.ServerName != "tr.example" {
		t.Fatalf("unexpected Trojan TLS: %#v", got[1].TLS)
	}
}

func TestCandidateCountIsBounded(t *testing.T) {
	configs := make([]remoteConfig, maxCandidateCount*4)
	for index := range configs {
		configs[index].SS = &remoteProxy{
			Server: "server-" + string(rune('a'+index%26)) + strings.Repeat("x", index/26),
			Port:   443, Password: "secret", Method: "aes-256-gcm",
		}
	}
	got := extractCandidates(configs)
	if len(got) != maxCandidateCount {
		t.Fatalf("got %d candidates, want %d", len(got), maxCandidateCount)
	}
}

func TestStableTagIncludesRenderedSecuritySettings(t *testing.T) {
	base := Candidate{Type: "trojan", Server: "proxy.example", Port: 443, Password: "x"}
	changed := base
	changed.TLS.Insecure = true
	if stableTag(base) == stableTag(changed) {
		t.Fatal("TLS security change did not change stable tag")
	}
	changed = base
	changed.Transport.Enabled = true
	if stableTag(base) == stableTag(changed) {
		t.Fatal("transport enablement change did not change stable tag")
	}
}

func TestDistinctTransportVariantsAreNotDeduplicated(t *testing.T) {
	plain := &remoteProxy{Server: "proxy.example", Port: 443, Password: "x"}
	websocket := &remoteProxy{Server: "proxy.example", Port: 443, Password: "x"}
	websocket.Websocket = &struct {
		Enabled bool   `json:"enabled"`
		Host    string `json:"host"`
		Path    string `json:"path"`
	}{Enabled: true, Host: "edge.example", Path: "/ws"}
	got := extractCandidates([]remoteConfig{{Trojan: plain}, {Trojan: websocket}})
	if len(got) != 2 {
		t.Fatalf("got %d transport variants, want 2", len(got))
	}
}

func TestReadBounded(t *testing.T) {
	if data, err := readBounded(strings.NewReader("1234"), 4); err != nil || string(data) != "1234" {
		t.Fatalf("exact limit failed: %q, %v", data, err)
	}
	if _, err := readBounded(strings.NewReader("12345"), 4); err == nil {
		t.Fatal("expected oversized response error")
	}
}

func TestRaceDomainsReturnsFastAndCancelsSlowProbe(t *testing.T) {
	slowStarted := make(chan struct{})
	slowCanceled := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(slowStarted)
		<-r.Context().Done()
		close(slowCanceled)
	}))
	defer slow.Close()
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-slowStarted
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0}`))
	}))
	defer fast.Close()

	cfg := config.Defaults()
	cfg.APIDomains = []string{slow.URL, fast.URL}
	cfg.RequestTimeout = time.Second
	client := New(cfg)
	defer client.Close()
	started := time.Now()
	got, err := client.raceDomains(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got != fast.URL {
		t.Fatalf("got %q, want %q", got, fast.URL)
	}
	if time.Since(started) > 500*time.Millisecond {
		t.Fatal("slow provider delayed successful race")
	}
	select {
	case <-slowCanceled:
	case <-time.After(time.Second):
		t.Fatal("slow provider request was not canceled")
	}
}

func TestRaceDomainsRejectsNonJSONSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>captive portal</html>"))
	}))
	defer server.Close()
	cfg := config.Defaults()
	cfg.APIDomains = []string{server.URL}
	client := New(cfg)
	defer client.Close()
	if _, err := client.raceDomains(context.Background()); err == nil {
		t.Fatal("expected invalid provider probe failure")
	}
}

func TestRepeatedDomainRacesLeaveNoActiveRequests(t *testing.T) {
	cfg := config.Defaults()
	cfg.APIDomains = []string{"https://slow.example", "https://fast.example"}
	var active atomic.Int64
	client := &Client{
		cfg: cfg,
		http: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.URL.Host == "slow.example" {
				active.Add(1)
				defer active.Add(-1)
				<-request.Context().Done()
				return nil, request.Context().Err()
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"code":0}`)),
				Header:     make(http.Header),
			}, nil
		})},
	}
	for index := 0; index < 100; index++ {
		if _, err := client.raceDomains(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(time.Second)
	for active.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := active.Load(); got != 0 {
		t.Fatalf("%d provider requests remained active", got)
	}
}

func TestCandidateProbesCloseConnections(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		for index := 0; index < 3; index++ {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			_ = connection.SetReadDeadline(time.Now().Add(time.Second))
			_, _ = io.Copy(io.Discard, connection)
			_ = connection.Close()
		}
	}()
	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	candidates := []Candidate{{Server: host, Port: port}}
	probeCandidates(context.Background(), candidates, time.Second)
	if candidates[0].LatencyMS < 1 {
		t.Fatalf("successful probe recorded invalid latency %d", candidates[0].LatencyMS)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("candidate probe connections were not closed")
	}
}

func TestAuthenticateFallsBackAfterSelectedDomainFailsLogin(t *testing.T) {
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/1/ip" {
			_, _ = w.Write([]byte(`{"code":0}`))
			return
		}
		http.Error(w, "temporary failure", http.StatusServiceUnavailable)
	}))
	defer primary.Close()
	backup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/1/ip" {
			time.Sleep(20 * time.Millisecond)
			_, _ = w.Write([]byte(`{"code":0}`))
			return
		}
		_, _ = w.Write([]byte(`{"code":0,"token":{"access_token":"test","token_type":"Bearer","exp":1}}`))
	}))
	defer backup.Close()
	cfg := config.Defaults()
	cfg.APIDomains = []string{primary.URL, backup.URL}
	client := New(cfg)
	defer client.Close()
	session, err := client.Authenticate(context.Background(), config.Credentials{
		AuthBy: "username", Username: "test", Password: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.BaseURL != backup.URL || session.Token != "Bearer test" {
		t.Fatalf("unexpected fallback session: %+v", session)
	}
}

func TestCandidatesFallBackToAlternateDomain(t *testing.T) {
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "temporary failure", http.StatusServiceUnavailable)
	}))
	defer primary.Close()
	backup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, portText, err := net.SplitHostPort(r.Host)
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = w.Write([]byte(`{"code":0,"configs":[{"SSConf":{"server":"` +
			host + `","port":` + portText + `,"password":"test","method":"aes-256-gcm"}}]}`))
	}))
	defer backup.Close()
	cfg := config.Defaults()
	cfg.RequestTimeout = time.Second
	client := New(cfg)
	defer client.Close()
	candidates, err := client.Candidates(context.Background(), Session{
		BaseURL: primary.URL, AlternateBases: []string{backup.URL}, Token: "Bearer test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0].LatencyMS < 1 {
		t.Fatalf("unexpected fallback candidates: %+v", candidates)
	}
}

func TestAPIResultValidation(t *testing.T) {
	if err := (apiResult{Code: 0}).validate(); err != nil {
		t.Fatal(err)
	}
	if err := (apiResult{Code: 40101, Error: "invalid"}).validate(); err == nil {
		t.Fatal("expected error")
	}
}

func TestTrojanAPKTLSShape(t *testing.T) {
	for _, verify := range []string{``, `,"verify":true`, `,"verify":false`} {
		var remote remoteConfig
		data := `{"trojanConf":{"server":"proxy.example","port":443,"password":"test","ssl":{"sni":"tls.example"` + verify + `}}}`
		if err := json.Unmarshal([]byte(data), &remote); err != nil {
			t.Fatal(err)
		}
		got := extractCandidates([]remoteConfig{remote})
		if len(got) != 1 || !got[0].TLS.Enabled || got[0].TLS.ServerName != "tls.example" || got[0].TLS.Insecure != strings.Contains(verify, "false") {
			t.Fatalf("incorrect TLS translation for %s: %+v", verify, got)
		}
	}
}

func TestAuthenticationCodes(t *testing.T) {
	for _, code := range []int{20001, 20006, 20010, 40015} {
		if !IsAuthenticationError((apiResult{Code: code}).validate()) {
			t.Fatalf("missing auth code %d", code)
		}
	}
	if IsAuthenticationError(&APIError{Code: 40021}) {
		t.Fatal("membership expiry must not cause login retry")
	}
	if (apiResult{Code: 20000}).validate() == nil {
		t.Fatal("APK treats 20000 as an error")
	}
}

func TestLoginSurvivesUnavailableDiscovery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/1/ip" {
			http.Error(w, "unavailable", 503)
			return
		}
		_, _ = w.Write([]byte(`{"token":{"access_token":"test"}}`))
	}))
	defer server.Close()
	cfg := config.Defaults()
	cfg.APIDomains = []string{server.URL}
	client := New(cfg)
	defer client.Close()
	if _, err := client.Authenticate(context.Background(), config.Credentials{AuthBy: "username", Username: "test", Password: "test"}); err != nil {
		t.Fatal(err)
	}
}
