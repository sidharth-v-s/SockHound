// Package config loads optional local SockHound configuration.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/zoro/sockhound/internal/model"
)

// MinRefreshInterval is the smallest automatic TUI refresh interval. Shorter
// values would rescan procfs too aggressively.
const MinRefreshInterval = time.Second

// RuleSettings overrides one rule.
type RuleSettings struct {
	Enabled  *bool  `json:"enabled,omitempty"`
	Severity string `json:"severity,omitempty"`
}

// Config is the on-disk configuration format.
type Config struct {
	SchemaVersion   int                     `json:"schema_version"`
	ReviewPorts     []int                   `json:"review_ports"`
	RevealCmdline   bool                    `json:"reveal_cmdline"`
	RefreshInterval string                  `json:"refresh_interval,omitempty"`
	Rules           map[string]RuleSettings `json:"rules,omitempty"`
}

// Default returns the built-in configuration.
func Default() Config {
	return Config{
		SchemaVersion: model.SchemaVersion,
		ReviewPorts:   []int{},
		Rules:         map[string]RuleSettings{},
	}
}

// ParseRefreshInterval parses a duration such as "5s" or "1m". An empty
// value, "0", "0s" or "off" disables automatic refresh.
func ParseRefreshInterval(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "0" || strings.EqualFold(raw, "off") {
		return 0, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid refresh_interval %q: %w", raw, err)
	}
	if d < 0 {
		return 0, fmt.Errorf("refresh_interval must not be negative")
	}
	if d > 0 && d < MinRefreshInterval {
		return 0, fmt.Errorf("refresh_interval must be at least %s, or 0s to disable", MinRefreshInterval)
	}
	return d, nil
}

// RefreshEvery returns the configured automatic refresh interval, or zero when
// automatic refresh is disabled. Load validates the value.
func (c Config) RefreshEvery() time.Duration {
	d, _ := ParseRefreshInterval(c.RefreshInterval)
	return d
}

// Load reads a JSON configuration file. An empty path returns Default.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("reading config: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("parsing config %s: %w", path, err)
	}
	if cfg.SchemaVersion == 0 {
		cfg.SchemaVersion = model.SchemaVersion
	}
	if cfg.SchemaVersion != model.SchemaVersion {
		return cfg, fmt.Errorf("unsupported config schema_version %d (want %d)", cfg.SchemaVersion, model.SchemaVersion)
	}
	if cfg.Rules == nil {
		cfg.Rules = map[string]RuleSettings{}
	}
	for _, port := range cfg.ReviewPorts {
		if port < 1 || port > 65535 {
			return cfg, fmt.Errorf("review port %d is outside 1-65535", port)
		}
	}
	if _, err := ParseRefreshInterval(cfg.RefreshInterval); err != nil {
		return cfg, err
	}
	for id, rule := range cfg.Rules {
		if rule.Severity != "" {
			switch model.Severity(rule.Severity) {
			case model.SeverityInfo, model.SeverityLow, model.SeverityMedium, model.SeverityHigh:
			default:
				return cfg, fmt.Errorf("rule %s: invalid severity %q (use INFO, LOW, MEDIUM or HIGH)", id, rule.Severity)
			}
		}
	}
	return cfg, nil
}

// RuleEnabled reports whether a rule is enabled (default true).
func (c Config) RuleEnabled(id string) bool {
	if r, ok := c.Rules[id]; ok && r.Enabled != nil {
		return *r.Enabled
	}
	return true
}

// RuleSeverity returns the configured severity for a rule, if any.
func (c Config) RuleSeverity(id string) (model.Severity, bool) {
	if r, ok := c.Rules[id]; ok && r.Severity != "" {
		return model.Severity(r.Severity), true
	}
	return "", false
}
