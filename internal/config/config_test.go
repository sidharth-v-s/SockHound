package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zoro/sockhound/internal/model"
)

func write(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadDefault(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SchemaVersion != model.SchemaVersion {
		t.Errorf("schema = %d", cfg.SchemaVersion)
	}
	if len(cfg.ReviewPorts) != 0 {
		t.Errorf("review ports = %v", cfg.ReviewPorts)
	}
	if !cfg.RuleEnabled("SH-WILD-001") {
		t.Errorf("rule should be enabled by default")
	}
}

func TestLoadValid(t *testing.T) {
	path := write(t, `{
		"schema_version": 1,
		"review_ports": [22, 3389],
		"reveal_cmdline": true,
		"rules": {
			"SH-WILD-001": {"enabled": false, "severity": "MEDIUM"}
		}
	}`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.ReviewPorts) != 2 || !cfg.RevealCmdline {
		t.Errorf("cfg = %+v", cfg)
	}
	if cfg.RuleEnabled("SH-WILD-001") {
		t.Errorf("rule should be disabled")
	}
	sev, ok := cfg.RuleSeverity("SH-WILD-001")
	if !ok || sev != model.SeverityMedium {
		t.Errorf("severity = %s, %v", sev, ok)
	}
	if !cfg.RuleEnabled("SH-OWNER-001") {
		t.Errorf("unlisted rule should stay enabled")
	}
}

func TestLoadErrors(t *testing.T) {
	cases := map[string]string{
		"unknown field": `{"schema_version":1,"nope":true}`,
		"bad schema":    `{"schema_version":99}`,
		"bad port":      `{"schema_version":1,"review_ports":[0]}`,
		"bad severity":  `{"schema_version":1,"rules":{"SH-WILD-001":{"severity":"CRITICAL"}}}`,
		"bad refresh":   `{"schema_version":1,"refresh_interval":"soon"}`,
		"short refresh": `{"schema_version":1,"refresh_interval":"500ms"}`,
		"invalid json":  `{`,
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(write(t, content)); err == nil {
				t.Fatalf("expected error for %s", name)
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("expected error")
	}
}

func TestRefreshInterval(t *testing.T) {
	cfg, err := Load(write(t, `{"schema_version":1,"refresh_interval":"5s"}`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.RefreshEvery(); got != 5*time.Second {
		t.Errorf("RefreshEvery = %s, want 5s", got)
	}

	for _, raw := range []string{"", "0", "0s", "off"} {
		got, err := ParseRefreshInterval(raw)
		if err != nil || got != 0 {
			t.Errorf("ParseRefreshInterval(%q) = %s, %v; want 0", raw, got, err)
		}
	}
	if _, err := ParseRefreshInterval("500ms"); err == nil {
		t.Errorf("expected a minimum-interval error")
	}
	if _, err := ParseRefreshInterval("soon"); err == nil {
		t.Errorf("expected an invalid-duration error")
	}
}
