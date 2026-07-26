package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/transocks-headless/transocks-headless/internal/config"
)

const (
	maxResponseBytes  = 4 << 20
	maxCandidateCount = 16
)

type Client struct {
	cfg       config.Config
	http      *http.Client
	transport *http.Transport
}

func New(cfg config.Config) *Client {
	dialer := &net.Dialer{Timeout: cfg.RequestTimeout, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                  http.ProxyFromEnvironment,
		DialContext:            dialer.DialContext,
		TLSHandshakeTimeout:    cfg.RequestTimeout,
		ResponseHeaderTimeout:  cfg.RequestTimeout,
		IdleConnTimeout:        30 * time.Second,
		MaxIdleConns:           8,
		MaxIdleConnsPerHost:    2,
		MaxConnsPerHost:        4,
		MaxResponseHeaderBytes: 64 << 10,
		ForceAttemptHTTP2:      true,
	}
	return &Client{
		cfg:       cfg,
		transport: transport,
		http:      &http.Client{Transport: transport, Timeout: cfg.RequestTimeout},
	}
}

func (c *Client) Close() {
	if c.transport != nil {
		c.transport.CloseIdleConnections()
	}
}

type Session struct {
	BaseURL        string
	AlternateBases []string
	Token          string
	TokenExp       int64
	UserID         int
	ExpiresAt      string
}

type Candidate struct {
	Tag       string
	Type      string
	Server    string
	Port      int
	Password  string
	Method    string
	TLS       TLSConfig
	Transport TransportConfig
	LatencyMS int64
}

type TLSConfig struct {
	Enabled    bool
	ServerName string
	Insecure   bool
}

type TransportConfig struct {
	Enabled bool
	Type    string
	Host    string
	Path    string
}

type apiResult struct {
	Code   int      `json:"code"`
	Status string   `json:"status"`
	Error  string   `json:"error"`
	Errors []string `json:"errors"`
}

func (r apiResult) validate() error {
	if r.Code != 0 && r.Code != 20000 && r.Code != 200 {
		message := r.Error
		if message == "" {
			message = strings.Join(r.Errors, "; ")
		}
		if message == "" {
			message = r.Status
		}
		return fmt.Errorf("provider code %d: %s", r.Code, message)
	}
	return nil
}

func (c *Client) Authenticate(ctx context.Context, credentials config.Credentials) (Session, error) {
	baseURL, err := c.raceDomains(ctx)
	if err != nil {
		return Session{}, err
	}
	body := c.baseRequest()
	body["auth_by"] = credentials.AuthBy
	body["password"] = credentials.Password
	body["auth_type"] = "jwt"
	body["autokick"] = 1
	switch credentials.AuthBy {
	case "username":
		body["username"] = credentials.Username
	case "email":
		body["email"] = credentials.Email
	case "mobile":
		body["cc"] = credentials.CC
		body["phone"] = credentials.Phone
	}
	var lastErr error
	for _, loginBase := range c.orderedDomains(baseURL) {
		var response struct {
			apiResult
			Token struct {
				AccessToken string `json:"access_token"`
				TokenType   string `json:"token_type"`
				Exp         int64  `json:"exp"`
			} `json:"token"`
			UserID   int    `json:"user_id"`
			ExpireAt string `json:"expire_at"`
		}
		if err := c.requestJSON(ctx, http.MethodPost, loginBase+"/api/1/login", "", body, &response); err != nil {
			lastErr = err
			continue
		}
		if err := response.validate(); err != nil {
			return Session{}, err
		}
		if response.Token.AccessToken == "" {
			lastErr = errors.New("login response did not contain an access token")
			continue
		}
		tokenType := response.Token.TokenType
		if tokenType == "" {
			tokenType = "Bearer"
		}
		domains := c.orderedDomains(loginBase)
		return Session{
			BaseURL:        loginBase,
			AlternateBases: append([]string(nil), domains[1:]...),
			Token:          tokenType + " " + response.Token.AccessToken,
			TokenExp:       response.Token.Exp,
			UserID:         response.UserID,
			ExpiresAt:      response.ExpireAt,
		}, nil
	}
	return Session{}, fmt.Errorf("login failed on every provider domain: %w", lastErr)
}

func (c *Client) Candidates(ctx context.Context, session Session) ([]Candidate, error) {
	body := c.baseRequest()
	proto := c.cfg.Protocol
	if proto == "auto" {
		proto = "ss"
	}
	body["proto"] = proto
	body["recommendLine"] = true
	body["methods"] = []string{"chacha20-ietf-poly1305", "aes-256-gcm", "aes-128-gcm"}
	if c.cfg.Protocol == "ss" {
		body["available_proto"] = []string{"ss"}
	} else if c.cfg.Protocol == "trojan" {
		body["available_proto"] = []string{"trojan"}
	} else {
		body["available_proto"] = []string{"ss", "trojan"}
	}
	body["lineCount"] = c.cfg.LineCount

	var response connectResponse
	var lastErr error
	bases := append([]string{session.BaseURL}, session.AlternateBases...)
	for _, base := range bases {
		response = connectResponse{}
		if err := c.requestJSON(ctx, http.MethodPost, base+"/api/2/line/connectmultiple", session.Token, body, &response); err != nil {
			lastErr = err
			continue
		}
		if err := response.validate(); err != nil {
			return nil, err
		}
		lastErr = nil
		break
	}
	if lastErr != nil {
		return nil, fmt.Errorf("connectmultiple failed on every provider domain: %w", lastErr)
	}
	remote := response.Configs
	if response.Config != nil {
		remote = append([]remoteConfig{*response.Config}, remote...)
	}
	candidates := extractCandidates(remote)
	if len(candidates) == 0 {
		return nil, errors.New("provider returned no supported Shadowsocks or Trojan candidates")
	}
	probeCandidates(ctx, candidates, c.cfg.RequestTimeout)
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].LatencyMS == 0 {
			return false
		}
		if candidates[j].LatencyMS == 0 {
			return true
		}
		return candidates[i].LatencyMS < candidates[j].LatencyMS
	})
	for i := range candidates {
		candidates[i].Tag = stableTag(candidates[i])
	}
	return candidates, nil
}

func stableTag(candidate Candidate) string {
	identity := strings.Join([]string{
		candidate.Type,
		strings.ToLower(candidate.Server),
		strconv.Itoa(candidate.Port),
		candidate.Method,
		strconv.FormatBool(candidate.TLS.Enabled),
		candidate.TLS.ServerName,
		strconv.FormatBool(candidate.TLS.Insecure),
		strconv.FormatBool(candidate.Transport.Enabled),
		candidate.Transport.Type,
		candidate.Transport.Host,
		candidate.Transport.Path,
	}, "\x00")
	sum := sha256.Sum256([]byte(identity))
	prefix := "proxy"
	if candidate.Type == "shadowsocks" {
		prefix = "ss"
	} else if candidate.Type == "trojan" {
		prefix = "trojan"
	}
	return fmt.Sprintf("%s-%x", prefix, sum[:6])
}

type connectResponse struct {
	apiResult
	BoostSession string         `json:"boostSession"`
	Config       *remoteConfig  `json:"config"`
	Configs      []remoteConfig `json:"configs"`
	LineID       *int           `json:"lineID"`
	LineName     string         `json:"lineName"`
}

type remoteConfig struct {
	Host        string       `json:"host"`
	ProxyIP     string       `json:"proxyIP"`
	SS          *remoteProxy `json:"SSConf"`
	Trojan      *remoteProxy `json:"trojanConf"`
	LowerSS     *remoteProxy `json:"ssConf"`
	LowerTrojan *remoteProxy `json:"TrojanConf"`
}

type remoteProxy struct {
	Proto    string `json:"proto"`
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Password string `json:"password"`
	Method   string `json:"method"`
	Host     string `json:"host"`
	SSL      *struct {
		Enabled bool   `json:"enabled"`
		SNI     string `json:"sni"`
		Verify  bool   `json:"verify"`
	} `json:"ssl"`
	Websocket *struct {
		Enabled bool   `json:"enabled"`
		Host    string `json:"host"`
		Path    string `json:"path"`
	} `json:"websocket"`
}

func extractCandidates(configs []remoteConfig) []Candidate {
	out := make([]Candidate, 0, min(len(configs)*2, maxCandidateCount))
	seen := map[string]bool{}
	add := func(candidate Candidate) {
		if len(out) >= maxCandidateCount {
			return
		}
		key := stableTag(candidate)
		if candidate.Server == "" || candidate.Port < 1 || candidate.Port > 65535 || candidate.Password == "" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, candidate)
	}
	for _, item := range configs {
		if len(out) >= maxCandidateCount {
			break
		}
		ss := item.SS
		if ss == nil {
			ss = item.LowerSS
		}
		if ss != nil {
			method := ss.Method
			if method == "" {
				method = "chacha20-ietf-poly1305"
			}
			add(Candidate{Type: "shadowsocks", Server: ss.Server, Port: ss.Port, Password: ss.Password, Method: method})
		}
		trojan := item.Trojan
		if trojan == nil {
			trojan = item.LowerTrojan
		}
		if trojan != nil {
			candidate := Candidate{Type: "trojan", Server: trojan.Server, Port: trojan.Port, Password: trojan.Password}
			candidate.TLS.Enabled = true
			candidate.TLS.ServerName = trojan.Host
			if trojan.SSL != nil {
				candidate.TLS.Enabled = trojan.SSL.Enabled
				candidate.TLS.ServerName = trojan.SSL.SNI
				candidate.TLS.Insecure = !trojan.SSL.Verify
			}
			if candidate.TLS.ServerName == "" {
				candidate.TLS.ServerName = candidate.Server
			}
			if trojan.Websocket != nil && trojan.Websocket.Enabled {
				candidate.Transport = TransportConfig{
					Enabled: true,
					Type:    "ws",
					Host:    trojan.Websocket.Host,
					Path:    trojan.Websocket.Path,
				}
			}
			add(candidate)
		}
	}
	return out
}

func probeCandidates(ctx context.Context, candidates []Candidate, timeout time.Duration) {
	var wg sync.WaitGroup
	for index := range candidates {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var results []int64
			address := net.JoinHostPort(candidates[i].Server, strconv.Itoa(candidates[i].Port))
			for attempt := 0; attempt < 3; attempt++ {
				start := time.Now()
				dialer := net.Dialer{Timeout: timeout}
				conn, err := dialer.DialContext(ctx, "tcp", address)
				if err == nil {
					elapsed := time.Since(start).Milliseconds()
					if elapsed < 1 {
						elapsed = 1
					}
					results = append(results, elapsed)
					_ = conn.Close()
				}
			}
			if len(results) > 0 {
				sort.Slice(results, func(a, b int) bool { return results[a] < results[b] })
				candidates[i].LatencyMS = results[len(results)/2]
			}
		}(index)
	}
	wg.Wait()
}

func (c *Client) raceDomains(ctx context.Context) (string, error) {
	type result struct {
		domain string
		err    error
	}
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan result, len(c.cfg.APIDomains))
	for _, domain := range c.cfg.APIDomains {
		domain := strings.TrimRight(domain, "/")
		go func() {
			query := url.Values{}
			for key, value := range c.baseRequest() {
				query.Set(key, fmt.Sprint(value))
			}
			request, err := http.NewRequestWithContext(raceCtx, http.MethodGet, domain+"/api/1/ip?"+query.Encode(), nil)
			if err == nil {
				var response *http.Response
				response, err = c.http.Do(request)
				if err == nil {
					defer response.Body.Close()
					if response.StatusCode < 200 || response.StatusCode >= 300 {
						err = fmt.Errorf("HTTP %d", response.StatusCode)
					} else {
						var data []byte
						data, err = readBounded(response.Body, 64<<10)
						if err == nil && !json.Valid(data) {
							err = errors.New("provider probe returned invalid JSON")
						}
					}
				}
			}
			results <- result{domain: domain, err: err}
		}()
	}
	var lastErr error
	for range c.cfg.APIDomains {
		var item result
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case item = <-results:
		}
		if item.err == nil {
			cancel()
			return item.domain, nil
		}
		lastErr = item.err
	}
	if lastErr != nil {
		return "", fmt.Errorf("all provider API domains failed: %w", lastErr)
	}
	return "", errors.New("all provider API domains failed")
}

func (c *Client) requestJSON(ctx context.Context, method, endpoint, token string, body any, output any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "TransocksHeadless/1 OpenWrt")
	if token != "" {
		request.Header.Set("Authorization", token)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, err := readBounded(response.Body, maxResponseBytes)
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", response.StatusCode, truncate(string(data), 256))
	}
	if err := json.Unmarshal(data, output); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func readBounded(reader io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response exceeds %d bytes", limit)
	}
	return data, nil
}

func (c *Client) baseRequest() map[string]any {
	deviceID := c.cfg.DeviceID
	if deviceID == "" {
		deviceID = machineID()
	}
	return map[string]any{
		"device":       "phone",
		"mac":          "02:00:00:00:00:00",
		"uuid":         deviceID,
		"langue":       "en-US",
		"package_name": "com.fobwifi.transocks",
		"app_version":  "4.4.4",
		"org":          "transocks_mix",
		"channel":      "official",
		"width_height": "0x0",
		"realname":     true,
		"sys_version":  "OpenWrt",
		"model":        "OpenWrt Router",
	}
}

func (c *Client) orderedDomains(first string) []string {
	first = strings.TrimRight(first, "/")
	domains := make([]string, 0, len(c.cfg.APIDomains))
	seen := make(map[string]struct{}, len(c.cfg.APIDomains))
	add := func(domain string) {
		domain = strings.TrimRight(domain, "/")
		if domain == "" {
			return
		}
		if _, exists := seen[domain]; exists {
			return
		}
		seen[domain] = struct{}{}
		domains = append(domains, domain)
	}
	add(first)
	for _, domain := range c.cfg.APIDomains {
		add(domain)
	}
	return domains
}

func machineID() string {
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if data, err := osReadFile(path); err == nil {
			if value := strings.TrimSpace(string(data)); value != "" {
				return value
			}
		}
	}
	return "transocks-openwrt"
}

var osReadFile = func(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readBounded(file, 4<<10)
}

func truncate(value string, max int) string {
	value = strings.TrimSpace(value)
	if len(value) <= max {
		return value
	}
	return value[:max]
}
