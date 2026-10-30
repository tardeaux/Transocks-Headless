package singbox

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/transocks-headless/transocks-headless/internal/config"
	"github.com/transocks-headless/transocks-headless/internal/provider"
)

func Generate(cfg config.Config, candidates []provider.Candidate) ([]byte, error) {
	if len(candidates) == 0 {
		return nil, fmt.Errorf("cannot generate sing-box configuration without candidates")
	}
	candidates = append([]provider.Candidate(nil), candidates...)
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Tag < candidates[j].Tag
	})
	outbounds := make([]any, 0, len(candidates)+2)
	tags := make([]string, 0, len(candidates))
	seenTags := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		if candidate.Tag == "" {
			return nil, fmt.Errorf("candidate tag is empty")
		}
		if _, exists := seenTags[candidate.Tag]; exists {
			return nil, fmt.Errorf("duplicate candidate tag %q", candidate.Tag)
		}
		seenTags[candidate.Tag] = struct{}{}
		tags = append(tags, candidate.Tag)
		switch candidate.Type {
		case "shadowsocks":
			outbounds = append(outbounds, map[string]any{
				"type":        "shadowsocks",
				"tag":         candidate.Tag,
				"server":      candidate.Server,
				"server_port": candidate.Port,
				"method":      candidate.Method,
				"password":    candidate.Password,
			})
		case "trojan":
			outbound := map[string]any{
				"type":        "trojan",
				"tag":         candidate.Tag,
				"server":      candidate.Server,
				"server_port": candidate.Port,
				"password":    candidate.Password,
				"tls": map[string]any{
					"enabled":     candidate.TLS.Enabled,
					"server_name": candidate.TLS.ServerName,
					"insecure":    candidate.TLS.Insecure,
				},
			}
			if candidate.Transport.Enabled {
				transport := map[string]any{
					"type": candidate.Transport.Type,
					"path": candidate.Transport.Path,
				}
				if candidate.Transport.Host != "" {
					transport["headers"] = map[string]any{"Host": candidate.Transport.Host}
				}
				outbound["transport"] = transport
			}
			outbounds = append(outbounds, outbound)
		default:
			return nil, fmt.Errorf("unsupported candidate type %q", candidate.Type)
		}
	}
	outbounds = append(outbounds,
		map[string]any{
			"type":                        "urltest",
			"tag":                         "auto",
			"outbounds":                   tags,
			"url":                         cfg.ProbeURL,
			"interval":                    durationSeconds(cfg.TestInterval),
			"tolerance":                   cfg.SwitchToleranceMS,
			"interrupt_exist_connections": cfg.InterruptConnections,
		},
		map[string]any{"type": "direct", "tag": "direct"},
	)

	var inbounds []any
	if cfg.Transparent {
		inbounds = append(inbounds, map[string]any{
			"type":           "tun",
			"tag":            "tun-in",
			"interface_name": "transocks0",
			"address":        []string{cfg.TUNAddress},
			"auto_route":     true,
			"auto_redirect":  true,
			"strict_route":   false,
			"stack":          "system",
		})
	}
	if cfg.MixedListen != "" {
		host, portString, err := net.SplitHostPort(cfg.MixedListen)
		if err != nil {
			return nil, fmt.Errorf("mixed_listen: %w", err)
		}
		port, err := strconv.Atoi(portString)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("mixed_listen has invalid port")
		}
		inbounds = append(inbounds, map[string]any{
			"type":        "mixed",
			"tag":         "mixed-in",
			"listen":      host,
			"listen_port": port,
		})
	}

	routeRules := make([]any, 0, 4)
	routeRules = append(routeRules, map[string]any{
		"process_name": []string{"transocks-headless"},
		"outbound":     "direct",
	})
	if cfg.DirectPrivate {
		routeRules = append(routeRules, map[string]any{"ip_is_private": true, "outbound": "direct"})
	}
	route := map[string]any{
		"auto_detect_interface": true,
		"rules":                 routeRules,
		"final":                 "auto",
	}
	document := map[string]any{
		"log":       map[string]any{"level": cfg.LogLevel, "timestamp": true},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route":     route,
		"experimental": map[string]any{
			"clash_api": map[string]any{"external_controller": cfg.APIControllerListen},
		},
	}

	if cfg.RouteMode == "compatibility" {
		cachePath := filepath.Join(cfg.RunDir, "sing-box-cache.db")
		if cfg.CacheFile != "" {
			cachePath = filepath.Join(filepath.Dir(cfg.CacheFile), "sing-box-cache.db")
		}
		document["experimental"].(map[string]any)["cache_file"] = map[string]any{
			"enabled": true, "path": cachePath,
		}
		routeRules = append(routeRules, map[string]any{"rule_set": []string{"geoip-cn"}, "outbound": "auto"})
		route["rules"] = routeRules
		route["final"] = "direct"
		route["rule_set"] = []any{
			map[string]any{
				"type":            "remote",
				"tag":             "geoip-cn",
				"format":          "binary",
				"url":             cfg.GeoIPCNRuleSetURL,
				"download_detour": "direct",
				"update_interval": "7d",
			},
		}
	}

	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func Redacted(data []byte) []byte {
	var document any
	if json.Unmarshal(data, &document) != nil {
		return []byte("{}\n")
	}
	redact(document)
	out, _ := json.MarshalIndent(document, "", "  ")
	return append(out, '\n')
}

func redact(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			if strings.EqualFold(key, "password") {
				typed[key] = "<redacted>"
			} else {
				redact(item)
			}
		}
	case []any:
		for _, item := range typed {
			redact(item)
		}
	}
}

func durationSeconds(value time.Duration) string {
	seconds := int(value.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	return strconv.Itoa(seconds) + "s"
}
