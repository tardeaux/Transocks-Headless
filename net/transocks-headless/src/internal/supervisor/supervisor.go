package supervisor

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/transocks-headless/transocks-headless/internal/config"
	"github.com/transocks-headless/transocks-headless/internal/provider"
	"github.com/transocks-headless/transocks-headless/internal/singbox"
)

const (
	maxRuntimeConfigBytes = 4 << 20
	maxHealthBytes        = 64 << 10
	stableCoreUptime      = 10 * time.Minute
	coreStartupGrace      = 30 * time.Second
)

type providerClient interface {
	Authenticate(context.Context, config.Credentials) (provider.Session, error)
	Candidates(context.Context, provider.Session) ([]provider.Candidate, error)
}

type Manager struct {
	cfg              config.Config
	client           providerClient
	credentials      config.Credentials
	version          string
	core             *coreProcess
	health           *healthTracker
	healthClient     *http.Client
	healthTransport  *http.Transport
	state            State
	configHash       string
	coreStartedAt    time.Time
	stateWriteFailed bool
	session          provider.Session
	nextRefreshRetry time.Time
}

type State struct {
	Status           string           `json:"status"`
	Version          string           `json:"version"`
	UpdatedAt        time.Time        `json:"updated_at"`
	APIDomain        string           `json:"api_domain,omitempty"`
	Selected         string           `json:"selected,omitempty"`
	DelayMS          int              `json:"delay_ms,omitempty"`
	BadRounds        int              `json:"bad_rounds"`
	Switches         int              `json:"switches"`
	Restarts         int              `json:"restarts"`
	UsingCache       bool             `json:"using_cache"`
	RefreshFailures  int              `json:"refresh_failures"`
	NextRefreshRetry string           `json:"next_refresh_retry,omitempty"`
	NextCoreRetry    string           `json:"next_core_retry,omitempty"`
	LastRefresh      time.Time        `json:"last_refresh,omitempty"`
	LastRefreshError string           `json:"last_refresh_error,omitempty"`
	LastHealthError  string           `json:"last_health_error,omitempty"`
	LastCoreError    string           `json:"last_core_error,omitempty"`
	LastCacheError   string           `json:"last_cache_error,omitempty"`
	CandidateCount   int              `json:"candidate_count"`
	Candidates       []CandidateState `json:"candidates,omitempty"`
}

type CandidateState struct {
	Tag       string `json:"tag"`
	Type      string `json:"type"`
	Server    string `json:"server"`
	Port      int    `json:"port"`
	LatencyMS int64  `json:"tcp_latency_ms,omitempty"`
}

func New(cfg config.Config, client providerClient, credentials config.Credentials, version string) *Manager {
	configPath := filepath.Join(cfg.RunDir, "sing-box.json")
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: cfg.RequestTimeout}).DialContext,
		IdleConnTimeout:        2 * cfg.TestInterval,
		MaxIdleConns:           1,
		MaxIdleConnsPerHost:    1,
		MaxConnsPerHost:        1,
		MaxResponseHeaderBytes: 16 << 10,
	}
	return &Manager{
		cfg:             cfg,
		client:          client,
		credentials:     credentials,
		version:         version,
		core:            newCoreProcess(cfg.CoreBinary, configPath),
		health:          newHealthTracker(cfg.BadThresholdMS, cfg.FailureRounds),
		healthTransport: transport,
		healthClient:    &http.Client{Transport: transport, Timeout: cfg.RequestTimeout},
		state:           State{Status: "starting", Version: version},
	}
}

func (m *Manager) Run(ctx context.Context) error {
	defer m.core.Stop()
	defer m.healthTransport.CloseIdleConnections()

	refreshBackoff := m.cfg.RetryInitial
	coreBackoff := m.cfg.CoreRestartInitial
	refreshDelay := m.cfg.CandidateRefresh

	if err := m.refreshWithTimeout(ctx); err != nil {
		m.recordRefreshFailure(err)
		cacheErr := m.startCached(ctx)
		if cacheErr != nil {
			log.Printf("last-known-good cache unavailable: %v", cacheErr)
			if err := m.waitForInitialRefresh(ctx, &refreshBackoff); err != nil {
				return err
			}
		} else {
			refreshDelay = jitterDuration(refreshBackoff)
			refreshBackoff = nextBackoff(refreshBackoff, m.cfg.RetryMax)
			m.setNextRefreshRetry(refreshDelay)
		}
	}

	monitorTicker := time.NewTicker(m.cfg.TestInterval)
	refreshTimer := time.NewTimer(refreshDelay)
	defer monitorTicker.Stop()
	defer refreshTimer.Stop()

	for {
		done := m.core.Done()
		select {
		case <-ctx.Done():
			m.state.Status = "stopping"
			m.state.UpdatedAt = time.Now().UTC()
			m.persistState()
			return ctx.Err()

		case err := <-done:
			if !m.coreStartedAt.IsZero() && time.Since(m.coreStartedAt) >= stableCoreUptime {
				coreBackoff = m.cfg.CoreRestartInitial
			}
			if err == nil {
				err = errors.New("sing-box exited unexpectedly")
			}
			m.recordCoreFailure(err)
			delay := jitterDuration(coreBackoff)
			coreBackoff = nextBackoff(coreBackoff, m.cfg.CoreRestartMax)
			if err := m.restartCoreUntilReady(ctx, delay, &coreBackoff); err != nil {
				return err
			}

		case <-monitorTicker.C:
			degraded := m.observeHealth(ctx)
			if !m.coreStartedAt.IsZero() && time.Since(m.coreStartedAt) >= stableCoreUptime {
				coreBackoff = m.cfg.CoreRestartInitial
			}
			if degraded {
				log.Printf("performance degradation persisted for %d rounds; refreshing candidates", m.cfg.FailureRounds)
				delay := m.runScheduledRefresh(ctx, &refreshBackoff)
				resetTimer(refreshTimer, delay)
			}

		case <-refreshTimer.C:
			delay := m.runScheduledRefresh(ctx, &refreshBackoff)
			resetTimer(refreshTimer, delay)
		}
	}
}

func (m *Manager) waitForInitialRefresh(ctx context.Context, backoff *time.Duration) error {
	for {
		delay := jitterDuration(*backoff)
		*backoff = nextBackoff(*backoff, m.cfg.RetryMax)
		m.setNextRefreshRetry(delay)
		if err := waitContext(ctx, delay); err != nil {
			return err
		}
		if err := m.refreshWithTimeout(ctx); err != nil {
			m.recordRefreshFailure(err)
			continue
		}
		*backoff = m.cfg.RetryInitial
		return nil
	}
}

func (m *Manager) runScheduledRefresh(ctx context.Context, backoff *time.Duration) time.Duration {
	if remaining := time.Until(m.nextRefreshRetry); remaining > 0 {
		return remaining
	}
	if err := m.refreshWithTimeout(ctx); err != nil {
		m.recordRefreshFailure(err)
		delay := jitterDuration(*backoff)
		*backoff = nextBackoff(*backoff, m.cfg.RetryMax)
		m.setNextRefreshRetry(delay)
		return delay
	}
	*backoff = m.cfg.RetryInitial
	return m.cfg.CandidateRefresh
}

func (m *Manager) refreshWithTimeout(ctx context.Context) error {
	refreshCtx, cancel := context.WithTimeout(ctx, m.cfg.RefreshTimeout)
	defer cancel()
	return m.refresh(refreshCtx)
}

func (m *Manager) refresh(ctx context.Context) error {
	candidates, err := m.fetchCandidates(ctx)
	if err != nil {
		return err
	}
	if !hasReachableCandidate(candidates) {
		return errors.New("refusing an entirely unresponsive candidate set")
	}
	data, err := singbox.Generate(m.cfg, candidates)
	if err != nil {
		return err
	}
	hash := hashData(data)
	changed := hash != m.configHash || !m.core.Running()
	if changed {
		if err := m.installConfig(ctx, data, hash); err != nil {
			return err
		}
	}

	now := time.Now().UTC()
	m.state.Status = "running"
	m.state.UsingCache = false
	m.state.APIDomain = m.session.BaseURL
	m.state.LastRefresh = now
	m.state.UpdatedAt = now
	m.state.LastRefreshError = ""
	m.state.RefreshFailures = 0
	m.state.NextRefreshRetry = ""
	m.nextRefreshRetry = time.Time{}
	m.state.CandidateCount = len(candidates)
	m.state.Candidates = make([]CandidateState, 0, len(candidates))
	for _, candidate := range candidates {
		m.state.Candidates = append(m.state.Candidates, CandidateState{
			Tag: candidate.Tag, Type: candidate.Type, Server: candidate.Server,
			Port: candidate.Port, LatencyMS: candidate.LatencyMS,
		})
	}
	m.persistState()
	return nil
}

// Keep the bearer token in memory across candidate refreshes. Unknown expiry is
// usable until the provider explicitly rejects it; network failures do not imply
// that credentials need to be submitted again.
func (m *Manager) fetchCandidates(ctx context.Context) ([]provider.Candidate, error) {
	if m.session.Token == "" || (m.session.TokenExp > 0 &&
		!time.Unix(m.session.TokenExp, 0).After(time.Now().Add(time.Minute))) {
		m.session = provider.Session{}
		session, err := m.client.Authenticate(ctx, m.credentials)
		if err != nil {
			return nil, err
		}
		m.session = session
	}
	candidates, err := m.client.Candidates(ctx, m.session)
	if !provider.IsAuthenticationError(err) {
		return candidates, err
	}
	m.session = provider.Session{}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	session, err := m.client.Authenticate(ctx, m.credentials)
	if err != nil {
		return nil, err
	}
	m.session = session
	candidates, err = m.client.Candidates(ctx, m.session)
	if provider.IsAuthenticationError(err) {
		m.session = provider.Session{}
	}
	return candidates, err
}

func (m *Manager) installConfig(ctx context.Context, data []byte, hash string) error {
	if m.cfg.RouteMode == "compatibility" && m.cfg.CacheFile != "" {
		if err := os.MkdirAll(filepath.Dir(m.cfg.CacheFile), 0o700); err != nil {
			return err
		}
	}
	configPath := filepath.Join(m.cfg.RunDir, "sing-box.json")
	candidatePath := configPath + ".candidate"
	_ = os.Remove(candidatePath)
	defer os.Remove(candidatePath)

	if err := writeAtomic(candidatePath, data, 0o600); err != nil {
		return fmt.Errorf("write candidate sing-box config: %w", err)
	}
	if err := m.core.CheckFile(ctx, candidatePath); err != nil {
		return err
	}

	wasRunning := m.core.Running()
	var previous []byte
	if wasRunning {
		var err error
		previous, err = readSecureFile(configPath, maxRuntimeConfigBytes)
		if err != nil {
			return fmt.Errorf("preserve active sing-box config before update: %w", err)
		}
		m.core.Stop()
	}
	if err := os.Rename(candidatePath, configPath); err != nil {
		if wasRunning {
			_ = m.startCore(ctx)
		}
		return fmt.Errorf("activate sing-box config: %w", err)
	}
	if err := m.startCore(ctx); err != nil {
		startErr := err
		if len(previous) > 0 {
			if rollbackErr := writeAtomic(configPath, previous, 0o600); rollbackErr == nil {
				if rollbackErr = m.startCore(ctx); rollbackErr == nil {
					m.configHash = hashData(previous)
					return fmt.Errorf("start new sing-box config: %w; previous config restored", startErr)
				}
			}
		}
		return fmt.Errorf("start sing-box: %w", startErr)
	}
	if wasRunning {
		m.state.Restarts++
	}
	m.configHash = hash
	m.state.LastCoreError = ""
	m.state.NextCoreRetry = ""

	if err := m.writeCache(data); err != nil {
		m.state.LastCacheError = sanitizeError(err)
		log.Printf("last-known-good cache update failed: %v", err)
	} else {
		m.state.LastCacheError = ""
	}
	return nil
}

func (m *Manager) startCached(ctx context.Context) error {
	if m.cfg.CacheFile == "" {
		return errors.New("cache disabled")
	}
	data, err := readSecureFile(m.cfg.CacheFile, maxRuntimeConfigBytes)
	if err != nil {
		return err
	}
	if err := m.core.CheckFile(ctx, m.cfg.CacheFile); err != nil {
		return fmt.Errorf("cached config invalid: %w", err)
	}
	configPath := filepath.Join(m.cfg.RunDir, "sing-box.json")
	if err := writeAtomic(configPath, data, 0o600); err != nil {
		return fmt.Errorf("restore cached config: %w", err)
	}
	if err := m.startCore(ctx); err != nil {
		return fmt.Errorf("start cached config: %w", err)
	}
	m.configHash = hashData(data)
	m.state.Status = "running-cached"
	m.state.UsingCache = true
	m.state.LastCacheError = ""
	m.state.UpdatedAt = time.Now().UTC()
	m.state.LastCoreError = ""
	m.state.NextCoreRetry = ""
	m.persistState()
	return nil
}

func (m *Manager) writeCache(data []byte) error {
	if m.cfg.CacheFile == "" {
		return nil
	}
	dir := filepath.Dir(m.cfg.CacheFile)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	return writeAtomic(m.cfg.CacheFile, data, 0o600)
}

func (m *Manager) startCore(ctx context.Context) error {
	if err := m.core.Start(); err != nil {
		return err
	}
	timer := time.NewTimer(coreStartupGrace)
	defer timer.Stop()
	probeTicker := time.NewTicker(50 * time.Millisecond)
	defer probeTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			m.core.Stop()
			return ctx.Err()
		case err, ok := <-m.core.Done():
			if !ok || err == nil {
				err = errors.New("sing-box exited during startup")
			}
			return fmt.Errorf("sing-box failed startup grace period: %w", err)
		case <-probeTicker.C:
			probeCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
			ready := m.coreControllerReady(probeCtx)
			cancel()
			if ready {
				m.coreStartedAt = time.Now()
				return nil
			}
		case <-timer.C:
			m.core.Stop()
			return errors.New("sing-box controller API did not become ready during startup")
		}
	}
}

func (m *Manager) coreControllerReady(ctx context.Context) bool {
	endpoint := "http://" + m.cfg.APIControllerListen + "/proxies/auto"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false
	}
	response, err := m.healthClient.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
		return false
	}
	data, err := readHTTPBody(response.Body, maxHealthBytes)
	if err != nil {
		return false
	}
	var result struct {
		Now string `json:"now"`
	}
	return json.Unmarshal(data, &result) == nil && result.Now != ""
}

func (m *Manager) restartCoreUntilReady(ctx context.Context, delay time.Duration, backoff *time.Duration) error {
	failures := 0
	for {
		m.state.Status = "restarting"
		m.state.NextCoreRetry = time.Now().Add(delay).UTC().Format(time.RFC3339)
		m.state.UpdatedAt = time.Now().UTC()
		m.persistState()
		if err := waitContext(ctx, delay); err != nil {
			return err
		}
		if err := m.startCore(ctx); err == nil {
			m.state.Status = "running"
			m.state.LastCoreError = ""
			m.state.NextCoreRetry = ""
			m.state.UpdatedAt = time.Now().UTC()
			m.persistState()
			return nil
		} else {
			m.recordCoreFailure(err)
			failures++
		}
		if failures > 0 && failures%3 == 0 {
			if err := m.startCached(ctx); err == nil {
				return nil
			} else {
				m.state.LastCacheError = sanitizeError(err)
			}
			if err := m.refreshWithTimeout(ctx); err == nil {
				return nil
			} else {
				m.recordRefreshFailure(err)
			}
		}
		delay = jitterDuration(*backoff)
		*backoff = nextBackoff(*backoff, m.cfg.CoreRestartMax)
	}
}

func (m *Manager) observeHealth(ctx context.Context) bool {
	selected, delay, err := m.readCoreHealth(ctx)
	degraded, switched := m.health.Observe(selected, delay, err == nil)
	if switched {
		log.Printf("selected host changed: %s", selected)
	}
	m.state.Selected = m.health.selected
	m.state.DelayMS = delay
	m.state.BadRounds = m.health.bad
	m.state.Switches = m.health.switches
	m.state.UpdatedAt = time.Now().UTC()
	if err != nil {
		m.state.LastHealthError = sanitizeError(err)
	} else {
		m.state.LastHealthError = ""
	}
	m.persistState()
	return degraded
}

func (m *Manager) readCoreHealth(ctx context.Context) (string, int, error) {
	// A live test touches URLTest so its idle timeout cannot turn an unused
	// SSID into a false degradation/relogin loop. It also measures the tunnel,
	// rather than relying solely on an old cached delay.
	probeTimeout := min(m.cfg.RequestTimeout.Milliseconds(), int64(30000))
	probeURL := "http://" + m.cfg.APIControllerListen + "/proxies/auto/delay?timeout=" + fmt.Sprint(probeTimeout) + "&url=" + url.QueryEscape(m.cfg.ProbeURL)
	probeRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return "", 0, err
	}
	probeResponse, err := m.healthClient.Do(probeRequest)
	if err != nil {
		return "", 0, err
	}
	_, readErr := readHTTPBody(probeResponse.Body, maxHealthBytes)
	_ = probeResponse.Body.Close()
	if readErr != nil {
		return "", 0, readErr
	}
	if probeResponse.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("core delay API HTTP %d", probeResponse.StatusCode)
	}
	endpoint := "http://" + m.cfg.APIControllerListen + "/proxies/auto"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", 0, err
	}
	response, err := m.healthClient.Do(request)
	if err != nil {
		return "", 0, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
		return "", 0, fmt.Errorf("core API HTTP %d", response.StatusCode)
	}
	data, err := readHTTPBody(response.Body, maxHealthBytes)
	if err != nil {
		return "", 0, err
	}
	var result struct {
		Now     string `json:"now"`
		History []struct {
			Time  string `json:"time"`
			Delay int    `json:"delay"`
		} `json:"history"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return "", 0, err
	}
	if result.Now == "" {
		return "", 0, errors.New("core API returned no selected host")
	}
	if len(result.History) == 0 {
		return result.Now, 0, errors.New("core API has no successful latency sample")
	}
	sample := result.History[len(result.History)-1]
	if sample.Delay <= 0 {
		return result.Now, sample.Delay, errors.New("core API has no successful latency sample")
	}
	if sample.Time != "" {
		sampleTime, err := time.Parse(time.RFC3339Nano, sample.Time)
		if err != nil {
			return result.Now, sample.Delay, fmt.Errorf("core API returned invalid sample time: %w", err)
		}
		maxAge := 3*m.cfg.TestInterval + m.cfg.RequestTimeout
		age := time.Since(sampleTime)
		if age > maxAge || age < -m.cfg.RequestTimeout {
			return result.Now, sample.Delay, fmt.Errorf("core API latency sample is stale or future-dated")
		}
	}
	return result.Now, sample.Delay, nil
}

func (m *Manager) recordRefreshFailure(err error) {
	m.state.RefreshFailures++
	m.state.LastRefreshError = sanitizeError(err)
	if !m.core.Running() {
		m.state.Status = "waiting-for-provider"
	}
	m.state.UpdatedAt = time.Now().UTC()
	m.persistState()
	log.Printf("provider refresh failed: %v", err)
}

func (m *Manager) setNextRefreshRetry(delay time.Duration) {
	m.nextRefreshRetry = time.Now().Add(delay)
	m.state.NextRefreshRetry = m.nextRefreshRetry.UTC().Format(time.RFC3339)
	m.state.UpdatedAt = time.Now().UTC()
	m.persistState()
}

func (m *Manager) recordCoreFailure(err error) {
	m.state.Restarts++
	m.state.Status = "restarting"
	m.state.LastCoreError = sanitizeError(err)
	m.state.UpdatedAt = time.Now().UTC()
	m.persistState()
	log.Printf("sing-box failure: %v", err)
}

func (m *Manager) writeState() error {
	data, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(m.cfg.StateFile, append(data, '\n'), 0o600)
}

func (m *Manager) persistState() {
	err := m.writeState()
	if err != nil {
		if !m.stateWriteFailed {
			log.Printf("state persistence failed: %v", err)
		}
		m.stateWriteFailed = true
		return
	}
	if m.stateWriteFailed {
		log.Printf("state persistence recovered")
	}
	m.stateWriteFailed = false
}

func hasReachableCandidate(candidates []provider.Candidate) bool {
	for _, candidate := range candidates {
		if candidate.LatencyMS > 0 {
			return true
		}
	}
	return false
}

func hashData(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func readSecureFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s must not be group/world accessible", path)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, limit)
	}
	return readHTTPBody(file, limit)
}

func readHTTPBody(reader io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("input exceeds %d bytes", limit)
	}
	return data, nil
}

func waitContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func resetTimer(timer *time.Timer, delay time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(delay)
}

func nextBackoff(current, maximum time.Duration) time.Duration {
	if current >= maximum || current > maximum/2 {
		return maximum
	}
	return current * 2
}

func jitterDuration(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	var value [1]byte
	if _, err := rand.Read(value[:]); err != nil {
		return base
	}
	percent := 80 + int(value[0])%41
	return base * time.Duration(percent) / 100
}

func sanitizeError(err error) string {
	if err == nil {
		return ""
	}
	value := strings.ReplaceAll(err.Error(), "\n", " ")
	if len(value) > 256 {
		value = value[:256]
	}
	return value
}
