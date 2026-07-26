package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadUCI(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "transocks")
	content := `config transocks 'main'
	option enabled '1'
	option credential_file '/secret/credentials.json'
	option test_interval '75'
	option candidate_refresh '900'
	option transparent '0'
	option cache_file ''
	option mixed_listen ''
	list api_domain 'https://one.example'
	list api_domain "https://two.example"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Enabled || cfg.Transparent {
		t.Fatalf("unexpected booleans: %+v", cfg)
	}
	if cfg.TestInterval != 75*time.Second || cfg.CandidateRefresh != 15*time.Minute {
		t.Fatalf("unexpected intervals: %+v", cfg)
	}
	if len(cfg.APIDomains) != 2 || cfg.APIDomains[1] != "https://two.example" {
		t.Fatalf("unexpected domains: %#v", cfg.APIDomains)
	}
	if cfg.CacheFile != "" || cfg.MixedListen != "" {
		t.Fatalf("quoted empty values were not preserved: %+v", cfg)
	}
}

func TestCredentialsRejectTrailingJSONAndUnknownFields(t *testing.T) {
	for name, content := range map[string]string{
		"trailing": `{"auth_by":"username","username":"a","password":"x"} {}`,
		"unknown":  `{"auth_by":"username","username":"a","password":"x","token":"secret"}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "credentials.json")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadCredentials(path); err == nil {
				t.Fatal("expected credentials parse failure")
			}
		})
	}
}

func TestCredentialsSizeBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxCredentialBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredentials(path); err == nil {
		t.Fatal("expected oversized credentials failure")
	}
}

func TestValidateRejectsUnsafeEndpointsAndTiming(t *testing.T) {
	tests := []func(*Config){
		func(cfg *Config) { cfg.APIDomains = []string{"http://provider.example"} },
		func(cfg *Config) { cfg.StateFile = "relative/status.json" },
		func(cfg *Config) { cfg.RefreshTimeout = cfg.RequestTimeout - time.Second },
		func(cfg *Config) { cfg.RetryMax = cfg.RetryInitial - time.Second },
		func(cfg *Config) { cfg.APIControllerListen = "0.0.0.0:9090" },
	}
	for index, mutate := range tests {
		cfg := Defaults()
		mutate(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Fatalf("case %d unexpectedly valid", index)
		}
	}
}

func TestCredentialsValidation(t *testing.T) {
	if err := (Credentials{AuthBy: "email", Email: "a@example.test", Password: "x"}).Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (Credentials{AuthBy: "mobile", CC: "1", Phone: "", Password: "x"}).Validate(); err == nil {
		t.Fatal("expected mobile validation error")
	}
}
