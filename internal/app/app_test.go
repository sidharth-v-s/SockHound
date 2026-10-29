package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zoro/sockhound/internal/analysis"
	"github.com/zoro/sockhound/internal/model"
	"github.com/zoro/sockhound/internal/scanner"
	"github.com/zoro/sockhound/internal/tui"
)

func ptr(n int) *int         { return &n }
func inode(n uint64) *uint64 { return &n }

func snap(partial bool) model.Snapshot {
	return model.Snapshot{
		SchemaVersion: model.SchemaVersion,
		ToolVersion:   "test",
		CollectedAt:   time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC),
		DurationMS:    5,
		Scope:         "current network namespace net:[1]",
		Visibility:    model.Visibility{Partial: partial, Warnings: []string{}},
		Stats: model.Stats{
			TotalSockets: 2, TCP: 1, Unix: 1, Listeners: 1,
			TCPStates:  map[string]int{"LISTEN": 1},
			Severities: map[string]int{"INFO": 1, "LOW": 0, "MEDIUM": 0, "HIGH": 0},
		},
		Sockets: []model.Socket{
			{
				ID: "tcp:1", Protocol: model.ProtocolTCP, Family: model.FamilyIPv4,
				LocalAddress: "0.0.0.0", LocalPort: ptr(8080), State: "LISTEN",
				Inode: inode(1), IsListening: true, BindScope: model.BindScopeWildcard,
				OwnerPIDs: []int{123}, OwnerNames: []string{"demo"}, OwnerUIDs: []int{1000}, OwnerUsers: []string{"demo"},
				CollectedAt: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC),
			},
			{
				ID: "unix:2", Protocol: model.ProtocolUnix, Family: model.FamilyUnix,
				UnixPath: "/tmp/demo.sock", State: "CONNECTED", Inode: inode(2),
				BindScope: model.BindScopeNotApplicable,
				OwnerPIDs: []int{123}, OwnerNames: []string{"demo"}, OwnerUIDs: []int{1000}, OwnerUsers: []string{"demo"},
				CollectedAt: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC),
			},
		},
		Processes: []model.Process{
			{PID: 123, Name: "demo", SocketIDs: []string{"tcp:1", "unix:2"}, Sockets: 2, Listeners: 1},
		},
		Findings: []model.Finding{
			{
				RuleID: "SH-WILD-001", RuleName: "Wildcard-bound TCP listener", Severity: model.SeverityInfo,
				Summary: "Wildcard-bound TCP listener on 0.0.0.0:8080", SocketID: "tcp:1",
				Evidence: model.Evidence{Protocol: "tcp", LocalEndpoint: "0.0.0.0:8080", State: "LISTEN", Inode: inode(1), PID: ptr(123)},
			},
		},
	}
}

func testIO(scan func(context.Context, scanner.Options) (model.Snapshot, error)) (IO, *bytes.Buffer, *bytes.Buffer) {
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	ios := IO{
		Out:        out,
		Err:        errOut,
		IsTerminal: func() bool { return false },
		Scan:       scan,
	}
	return ios, out, errOut
}

func TestVersion(t *testing.T) {
	ios, out, _ := testIO(nil)
	if code := Run([]string{"--version"}, ios); code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out.String(), "SockHound") {
		t.Errorf("output = %q", out.String())
	}
}

func TestHelp(t *testing.T) {
	ios, out, _ := testIO(nil)
	if code := Run([]string{"--help"}, ios); code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out.String(), "sockhound scan") {
		t.Errorf("help output = %q", out.String())
	}
}

func TestNoArgsNonTerminal(t *testing.T) {
	ios, _, errOut := testIO(nil)
	if code := Run(nil, ios); code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(errOut.String(), "sockhound scan") {
		t.Errorf("stderr = %q", errOut.String())
	}
}

func TestNoArgsLaunchesTUI(t *testing.T) {
	ios, _, _ := testIO(func(context.Context, scanner.Options) (model.Snapshot, error) {
		return snap(false), nil
	})
	ios.IsTerminal = func() bool { return true }
	called := false
	ios.RunTUI = func(opts tui.Options) error {
		called = true
		if opts.Scan == nil {
			t.Errorf("TUI scan function is nil")
		}
		if opts.Version == "" {
			t.Errorf("TUI version is empty")
		}
		if _, err := opts.Scan(context.Background()); err != nil {
			t.Errorf("TUI scan failed: %v", err)
		}
		return nil
	}
	if code := Run(nil, ios); code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if !called {
		t.Errorf("RunTUI was not called")
	}
}

func TestTUINonTerminal(t *testing.T) {
	ios, _, errOut := testIO(nil)
	if code := Run([]string{"tui"}, ios); code != ExitUsage {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(errOut.String(), "not a terminal") {
		t.Errorf("stderr = %q", errOut.String())
	}
}

func TestTUIRefreshInterval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"refresh_interval":"7s"}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	ios, _, _ := testIO(nil)
	ios.IsTerminal = func() bool { return true }
	var got time.Duration
	ios.RunTUI = func(opts tui.Options) error {
		got = opts.RefreshInterval
		return nil
	}

	if code := Run([]string{"tui", "--config", path}, ios); code != ExitOK {
		t.Fatalf("config exit = %d", code)
	}
	if got != 7*time.Second {
		t.Errorf("config interval = %s, want 7s", got)
	}

	if code := Run([]string{"tui", "--config", path, "--refresh-interval", "3s"}, ios); code != ExitOK {
		t.Fatalf("override exit = %d", code)
	}
	if got != 3*time.Second {
		t.Errorf("override interval = %s, want 3s", got)
	}

	if code := Run([]string{"tui", "--refresh-interval", "0s"}, ios); code != ExitOK {
		t.Fatalf("disable exit = %d", code)
	}
	if got != 0 {
		t.Errorf("disabled interval = %s, want 0", got)
	}

	ios.RunTUI = func(tui.Options) error {
		t.Errorf("RunTUI should not be called for an invalid interval")
		return nil
	}
	if code := Run([]string{"tui", "--refresh-interval", "soon"}, ios); code != ExitUsage {
		t.Fatalf("invalid exit = %d, want %d", code, ExitUsage)
	}
}

func TestScanText(t *testing.T) {
	ios, out, _ := testIO(func(context.Context, scanner.Options) (model.Snapshot, error) {
		return snap(false), nil
	})
	if code := Run([]string{"scan"}, ios); code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out.String(), "SOCKET") && !strings.Contains(out.String(), "PROTO") {
		t.Errorf("output = %q", out.String())
	}
}

func TestScanPartialExitCode(t *testing.T) {
	ios, _, _ := testIO(func(context.Context, scanner.Options) (model.Snapshot, error) {
		return snap(true), nil
	})
	if code := Run([]string{"scan"}, ios); code != ExitPartial {
		t.Fatalf("exit = %d, want %d", code, ExitPartial)
	}
}

func TestScanCollectionError(t *testing.T) {
	ios, _, errOut := testIO(func(context.Context, scanner.Options) (model.Snapshot, error) {
		return model.Snapshot{}, errors.New("boom")
	})
	if code := Run([]string{"scan"}, ios); code != ExitCollect {
		t.Fatalf("exit = %d, want %d", code, ExitCollect)
	}
	if !strings.Contains(errOut.String(), "collection failed") {
		t.Errorf("stderr = %q", errOut.String())
	}
}

func TestScanJSON(t *testing.T) {
	ios, out, _ := testIO(func(context.Context, scanner.Options) (model.Snapshot, error) {
		return snap(false), nil
	})
	if code := Run([]string{"scan", "--json"}, ios); code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	var got model.Snapshot
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out.String())
	}
	if got.SchemaVersion != model.SchemaVersion || len(got.Sockets) != 2 {
		t.Errorf("decoded snapshot = %+v", got)
	}
}

func TestScanFilterProtocol(t *testing.T) {
	ios, out, _ := testIO(func(context.Context, scanner.Options) (model.Snapshot, error) {
		return snap(false), nil
	})
	if code := Run([]string{"scan", "--json", "--protocol", "tcp"}, ios); code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	var got model.Snapshot
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(got.Sockets) != 1 || got.Sockets[0].Protocol != model.ProtocolTCP {
		t.Errorf("filtered sockets = %+v", got.Sockets)
	}
	if got.Stats.TotalSockets != 1 || got.Stats.Unix != 0 {
		t.Errorf("filtered stats = %+v", got.Stats)
	}
	if len(got.Findings) != 1 || got.Findings[0].RuleID != "SH-WILD-001" {
		t.Errorf("filtered findings = %+v", got.Findings)
	}
	if len(got.Processes) != 1 || got.Processes[0].Sockets != 1 {
		t.Errorf("filtered processes = %+v", got.Processes)
	}
}

func TestScanFilterOwnerUnknown(t *testing.T) {
	s := snap(false)
	s.Sockets[0].OwnerPIDs = nil
	s.Sockets[0].OwnerNames = nil
	ios, out, _ := testIO(func(context.Context, scanner.Options) (model.Snapshot, error) {
		return s, nil
	})
	if code := Run([]string{"scan", "--json", "--owner", "unknown"}, ios); code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	var got model.Snapshot
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(got.Sockets) != 1 || got.Sockets[0].ID != "tcp:1" {
		t.Errorf("filtered sockets = %+v", got.Sockets)
	}
}

func TestScanInvalidFilters(t *testing.T) {
	cases := [][]string{
		{"scan", "--protocol", "sctp"},
		{"scan", "--owner", "maybe"},
		{"scan", "--severity", "CRITICAL"},
		{"scan", "--filter", "pid:abc"},
	}
	for _, args := range cases {
		ios, _, _ := testIO(func(context.Context, scanner.Options) (model.Snapshot, error) {
			t.Fatalf("scan should not run for %v", args)
			return model.Snapshot{}, nil
		})
		if code := Run(args, ios); code != ExitUsage {
			t.Errorf("Run(%v) exit = %d, want %d", args, code, ExitUsage)
		}
	}
}

func TestScanDebugKeepsStdoutClean(t *testing.T) {
	ios, out, errOut := testIO(func(context.Context, scanner.Options) (model.Snapshot, error) {
		s := snap(false)
		s.Visibility.Warnings = []string{"test warning"}
		return s, nil
	})
	if code := Run([]string{"scan", "--json", "--debug"}, ios); code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	var got model.Snapshot
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("stdout is not pure JSON: %v\n%s", err, out.String())
	}
	if !strings.Contains(errOut.String(), "scan duration") || !strings.Contains(errOut.String(), "test warning") {
		t.Errorf("stderr = %q", errOut.String())
	}
}

func TestScanOutputFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	ios, out, _ := testIO(func(context.Context, scanner.Options) (model.Snapshot, error) {
		return snap(false), nil
	})
	if code := Run([]string{"scan", "--output", path}, ios); code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if out.Len() != 0 {
		t.Errorf("stdout should be empty when --output is used, got %q", out.String())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	var got model.Snapshot
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("invalid output JSON: %v", err)
	}
	// Refuses to overwrite without --force.
	if code := Run([]string{"scan", "--output", path}, ios); code != ExitCollect {
		t.Fatalf("overwrite exit = %d, want %d", code, ExitCollect)
	}
	if code := Run([]string{"scan", "--output", path, "--force"}, ios); code != ExitOK {
		t.Fatalf("force exit = %d", code)
	}
}

func TestScanConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	content := `{"schema_version":1,"review_ports":[22],"rules":{"SH-WILD-001":{"severity":"HIGH"}}}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	var captured scanner.Options
	ios, _, _ := testIO(func(_ context.Context, opts scanner.Options) (model.Snapshot, error) {
		captured = opts
		return snap(false), nil
	})
	if code := Run([]string{"scan", "--config", path}, ios); code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if len(captured.Analysis.ReviewPorts) != 1 || captured.Analysis.ReviewPorts[0] != 22 {
		t.Errorf("review ports = %v", captured.Analysis.ReviewPorts)
	}
	rule := captured.Analysis.Rules[analysis.RuleWildcardListener]
	if !rule.HasSeverity || rule.Severity != model.SeverityHigh {
		t.Errorf("rule config = %+v", rule)
	}
}

func TestScanInvalidConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"review_ports":[99999]}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	ios, _, _ := testIO(func(context.Context, scanner.Options) (model.Snapshot, error) {
		t.Fatalf("scan should not run")
		return model.Snapshot{}, nil
	})
	if code := Run([]string{"scan", "--config", path}, ios); code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
}
