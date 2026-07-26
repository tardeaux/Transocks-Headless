package config

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const maxCredentialBytes = 64 << 10

var defaultDomains = []string{
	"https://abscf2.fobwifi.com",
	"https://b.kolavpn.xyz",
	"https://b.kolavpn.win",
	"https://b.transmoon.xyz",
}

type Config struct {
	Enabled              bool
	CredentialFile       string
	DeviceID             string
	APIDomains           []string
	Protocol             string
	RouteMode            string
	GeoIPCNRuleSetURL    string
	CoreBinary           string
	RunDir               string
	StateFile            string
	CacheFile            string
	Transparent          bool
	InterruptConnections bool
	MixedListen          string
	TUNAddress           string
	ProbeURL             string
	TestInterval         time.Duration
	CandidateRefresh     time.Duration
	RefreshTimeout       time.Duration
	RequestTimeout       time.Duration
	RetryInitial         time.Duration
	RetryMax             time.Duration
	CoreRestartInitial   time.Duration
	CoreRestartMax       time.Duration
	BadThresholdMS       int
	FailureRounds        int
	LineCount            int
	SwitchToleranceMS    int
	LogLevel             string
	DirectPrivate        bool
	APIControllerListen  string
}

func Defaults() Config {
	return Config{
		CredentialFile:       "/etc/transocks/credentials.json",
		APIDomains:           append([]string(nil), defaultDomains...),
		Protocol:             "auto",
		RouteMode:            "compatibility",
		GeoIPCNRuleSetURL:    "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
		CoreBinary:           "/usr/bin/sing-box",
		RunDir:               "/var/run/transocks",
		StateFile:            "/var/run/transocks/status.json",
		CacheFile:            "/etc/transocks/last-known-good.json",
		Transparent:          true,
		InterruptConnections: true,
		MixedListen:          "127.0.0.1:7890",
		TUNAddress:           "172.19.0.1/30",
		ProbeURL:             "https://connect.rom.miui.com/generate_204",
		TestInterval:         60 * time.Second,
		CandidateRefresh:     30 * time.Minute,
		RefreshTimeout:       90 * time.Second,
		RequestTimeout:       10 * time.Second,
		RetryInitial:         5 * time.Second,
		RetryMax:             15 * time.Minute,
		CoreRestartInitial:   2 * time.Second,
		CoreRestartMax:       2 * time.Minute,
		BadThresholdMS:       1500,
		FailureRounds:        3,
		LineCount:            4,
		SwitchToleranceMS:    120,
		LogLevel:             "info",
		DirectPrivate:        true,
		APIControllerListen:  "127.0.0.1:9090",
	}
}

func Load(path string) (Config, error) {
	cfg := Defaults()
	f, err := os.Open(path)
	if err != nil {
		return cfg, fmt.Errorf("open configuration %s: %w", path, err)
	}
	defer f.Close()

	values := map[string][]string{}
	inMain := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(stripComment(scanner.Text()))
		if line == "" {
			continue
		}
		kind, key, value, ok := parseLine(line)
		if !ok {
			continue
		}
		if kind == "config" {
			inMain = key == "transocks" && (value == "" || value == "main")
			continue
		}
		if inMain {
			values[key] = append(values[key], value)
		}
	}
	if err := scanner.Err(); err != nil {
		return cfg, fmt.Errorf("read configuration: %w", err)
	}

	setString(values, "credential_file", &cfg.CredentialFile)
	setString(values, "device_id", &cfg.DeviceID)
	setString(values, "protocol", &cfg.Protocol)
	setString(values, "route_mode", &cfg.RouteMode)
	setString(values, "geoip_cn_rule_set_url", &cfg.GeoIPCNRuleSetURL)
	setString(values, "core_binary", &cfg.CoreBinary)
	setString(values, "run_dir", &cfg.RunDir)
	setString(values, "state_file", &cfg.StateFile)
	setString(values, "cache_file", &cfg.CacheFile)
	setString(values, "mixed_listen", &cfg.MixedListen)
	setString(values, "tun_address", &cfg.TUNAddress)
	setString(values, "probe_url", &cfg.ProbeURL)
	setString(values, "log_level", &cfg.LogLevel)
	setString(values, "api_controller_listen", &cfg.APIControllerListen)
	setBool(values, "enabled", &cfg.Enabled)
	setBool(values, "transparent", &cfg.Transparent)
	setBool(values, "interrupt_connections", &cfg.InterruptConnections)
	setBool(values, "direct_private", &cfg.DirectPrivate)
	setInt(values, "bad_threshold_ms", &cfg.BadThresholdMS)
	setInt(values, "failure_rounds", &cfg.FailureRounds)
	setInt(values, "line_count", &cfg.LineCount)
	setInt(values, "switch_tolerance_ms", &cfg.SwitchToleranceMS)
	setDuration(values, "test_interval", &cfg.TestInterval)
	setDuration(values, "candidate_refresh", &cfg.CandidateRefresh)
	setDuration(values, "refresh_timeout", &cfg.RefreshTimeout)
	setDuration(values, "request_timeout", &cfg.RequestTimeout)
	setDuration(values, "retry_initial", &cfg.RetryInitial)
	setDuration(values, "retry_max", &cfg.RetryMax)
	setDuration(values, "core_restart_initial", &cfg.CoreRestartInitial)
	setDuration(values, "core_restart_max", &cfg.CoreRestartMax)
	if domains := values["api_domain"]; len(domains) > 0 {
		cfg.APIDomains = append([]string(nil), domains...)
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if len(c.APIDomains) == 0 {
		return errors.New("at least one api_domain is required")
	}
	if len(c.APIDomains) > 16 {
		return errors.New("no more than 16 api_domain entries are allowed")
	}
	for _, domain := range c.APIDomains {
		parsed, err := url.Parse(domain)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
			return fmt.Errorf("api_domain must use HTTPS: %s", domain)
		}
	}
	if c.Protocol != "auto" && c.Protocol != "ss" && c.Protocol != "trojan" {
		return fmt.Errorf("unsupported protocol %q", c.Protocol)
	}
	if c.RouteMode != "compatibility" && c.RouteMode != "full" {
		return fmt.Errorf("unsupported route_mode %q", c.RouteMode)
	}
	if c.RouteMode == "compatibility" && !strings.HasPrefix(c.GeoIPCNRuleSetURL, "https://") {
		return errors.New("compatibility route_mode requires an HTTPS geoip_cn_rule_set_url")
	}
	if parsed, err := url.Parse(c.ProbeURL); err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return errors.New("probe_url must be a valid HTTPS URL")
	}
	controllerHost, controllerPort, err := net.SplitHostPort(c.APIControllerListen)
	if err != nil {
		return fmt.Errorf("api_controller_listen must be host:port: %w", err)
	}
	controllerIP := net.ParseIP(controllerHost)
	if controllerHost != "localhost" && (controllerIP == nil || !controllerIP.IsLoopback()) {
		return errors.New("api_controller_listen must use a loopback address")
	}
	if port, err := strconv.Atoi(controllerPort); err != nil || port < 1 || port > 65535 {
		return errors.New("api_controller_listen has an invalid port")
	}
	for name, path := range map[string]string{
		"credential_file": c.CredentialFile,
		"core_binary":     c.CoreBinary,
		"run_dir":         c.RunDir,
		"state_file":      c.StateFile,
	} {
		if !filepath.IsAbs(path) {
			return fmt.Errorf("%s must be an absolute path", name)
		}
	}
	if c.CacheFile != "" && !filepath.IsAbs(c.CacheFile) {
		return errors.New("cache_file must be empty or an absolute path")
	}
	if c.TestInterval < 10*time.Second {
		return errors.New("test_interval must be at least 10 seconds")
	}
	if c.CandidateRefresh < c.TestInterval {
		return errors.New("candidate_refresh must not be shorter than test_interval")
	}
	if c.RequestTimeout < time.Second || c.RequestTimeout > 2*time.Minute {
		return errors.New("request_timeout must be between 1 second and 2 minutes")
	}
	if c.RefreshTimeout < c.RequestTimeout || c.RefreshTimeout > 10*time.Minute {
		return errors.New("refresh_timeout must be at least request_timeout and no more than 10 minutes")
	}
	if c.RetryInitial < time.Second || c.RetryMax < c.RetryInitial {
		return errors.New("retry timing is invalid")
	}
	if c.CoreRestartInitial < time.Second || c.CoreRestartMax < c.CoreRestartInitial {
		return errors.New("core restart timing is invalid")
	}
	if c.LineCount < 2 || c.LineCount > 16 {
		return errors.New("line_count must be between 2 and 16")
	}
	if c.FailureRounds < 1 {
		return errors.New("failure_rounds must be positive")
	}
	if c.BadThresholdMS < 1 || c.SwitchToleranceMS < 0 {
		return errors.New("latency thresholds are invalid")
	}
	return nil
}

type Credentials struct {
	AuthBy   string `json:"auth_by"`
	Username string `json:"username,omitempty"`
	Email    string `json:"email,omitempty"`
	Password string `json:"password"`
	CC       string `json:"cc,omitempty"`
	Phone    string `json:"phone,omitempty"`
}

func LoadCredentials(path string) (Credentials, error) {
	var credentials Credentials
	file, err := os.Open(path)
	if err != nil {
		return credentials, fmt.Errorf("read credentials: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return credentials, fmt.Errorf("stat credentials %s: %w", path, err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return credentials, fmt.Errorf("credentials %s must not be group/world accessible (use chmod 600)", path)
	}
	if !info.Mode().IsRegular() {
		return credentials, fmt.Errorf("credentials %s must be a regular file", path)
	}
	if info.Size() > maxCredentialBytes {
		return credentials, fmt.Errorf("credentials %s exceeds %d bytes", path, maxCredentialBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxCredentialBytes+1))
	if err != nil {
		return credentials, fmt.Errorf("read credentials: %w", err)
	}
	if len(data) > maxCredentialBytes {
		return credentials, fmt.Errorf("credentials %s exceeds %d bytes", path, maxCredentialBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&credentials); err != nil {
		return credentials, fmt.Errorf("parse credentials: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return credentials, errors.New("parse credentials: multiple JSON values")
		}
		return credentials, fmt.Errorf("parse credentials trailing data: %w", err)
	}
	return credentials, nil
}

func (c Credentials) Validate() error {
	if c.Password == "" {
		return errors.New("credentials password is empty")
	}
	switch c.AuthBy {
	case "username":
		if c.Username == "" {
			return errors.New("username authentication requires username")
		}
	case "email":
		if c.Email == "" {
			return errors.New("email authentication requires email")
		}
	case "mobile":
		if c.CC == "" || c.Phone == "" {
			return errors.New("mobile authentication requires cc and phone")
		}
	default:
		return fmt.Errorf("unsupported credential auth_by %q", c.AuthBy)
	}
	return nil
}

func parseLine(line string) (kind, key, value string, ok bool) {
	fields := splitFields(line)
	if len(fields) < 2 {
		return "", "", "", false
	}
	switch fields[0] {
	case "config":
		if len(fields) > 2 {
			return "config", fields[1], fields[2], true
		}
		return "config", fields[1], "", true
	case "option", "list":
		if len(fields) < 3 {
			return "", "", "", false
		}
		return fields[0], fields[1], fields[2], true
	default:
		return "", "", "", false
	}
}

func splitFields(line string) []string {
	var out []string
	var b strings.Builder
	var quote rune
	escaped := false
	tokenStarted := false
	flush := func() {
		if tokenStarted {
			out = append(out, b.String())
			b.Reset()
			tokenStarted = false
		}
	}
	for _, r := range line {
		if escaped {
			b.WriteRune(r)
			tokenStarted = true
			escaped = false
			continue
		}
		if r == '\\' {
			tokenStarted = true
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				b.WriteRune(r)
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			tokenStarted = true
		} else if r == ' ' || r == '\t' {
			flush()
		} else {
			b.WriteRune(r)
			tokenStarted = true
		}
	}
	flush()
	return out
}

func stripComment(line string) string {
	var quote rune
	for i, r := range line {
		if quote == 0 && (r == '\'' || r == '"') {
			quote = r
		} else if quote != 0 && r == quote {
			quote = 0
		} else if quote == 0 && r == '#' {
			return line[:i]
		}
	}
	return line
}

func last(values map[string][]string, key string) (string, bool) {
	items := values[key]
	if len(items) == 0 {
		return "", false
	}
	return items[len(items)-1], true
}

func setString(values map[string][]string, key string, dst *string) {
	if value, ok := last(values, key); ok {
		*dst = value
	}
}

func setBool(values map[string][]string, key string, dst *bool) {
	if value, ok := last(values, key); ok {
		*dst = value == "1" || strings.EqualFold(value, "true") || strings.EqualFold(value, "yes")
	}
}

func setInt(values map[string][]string, key string, dst *int) {
	if value, ok := last(values, key); ok {
		if parsed, err := strconv.Atoi(value); err == nil {
			*dst = parsed
		}
	}
}

func setDuration(values map[string][]string, key string, dst *time.Duration) {
	if value, ok := last(values, key); ok {
		if seconds, err := strconv.Atoi(value); err == nil {
			*dst = time.Duration(seconds) * time.Second
		} else if parsed, err := time.ParseDuration(value); err == nil {
			*dst = parsed
		}
	}
}
