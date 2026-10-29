// Package config loads optional local SockHound configuration.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/zoro/sockhound/internal/model"
)

// RuleSettings overrides one rule.
type RuleSettings struct {
	Enabled  *bool  `json:"enabled,omitempty"`
	Severity string `json:"severity,omitempty"`
}

// Config is the on-disk configuration format.
type Config struct {
	SchemaVersion int                     `json:"schema_version"`
	ReviewPorts   []int                   `json:"review_ports"`
	RevealCmdline bool                    `json:"reveal_cmdline"`
	Rules         map[string]RuleSettings `json:"rules,omitempty"`
}

// Default returns the built-in configuration.
func Default() Config {
	return Config{
		SchemaVersion: model.SchemaVersion,
		ReviewPorts:   []int{},
		Rules:         map[string]RuleSettings{},
	}
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
