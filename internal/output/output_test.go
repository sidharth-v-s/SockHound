package output

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zoro/sockhound/internal/model"
)

func p(n int) *int         { return &n }
func ino(n uint64) *uint64 { return &n }

func snapshot() model.Snapshot {
	return model.Snapshot{
		SchemaVersion:    model.SchemaVersion,
		ToolVersion:      "test",
		CollectedAt:      time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC),
		DurationMS:       12,
		NetworkNamespace: "net:[123]",
		Scope:            "current network namespace net:[123]",
		Visibility: model.Visibility{
			Partial:  true,
			Warnings: []string{"process visibility limited: 1"},
		},
		Stats: model.Stats{
			TotalSockets: 2, TCP: 1, Unix: 1, Listeners: 1, UnresolvedOwners: 1,
			TCPStates:  map[string]int{"LISTEN": 1},
			Severities: map[string]int{"INFO": 1, "LOW": 0, "MEDIUM": 0, "HIGH": 0},
		},
		Sockets: []model.Socket{
			{
				ID: "tcp:1", Protocol: model.ProtocolTCP, Family: model.FamilyIPv4,
				LocalAddress: "0.0.0.0", LocalPort: p(8080), State: "LISTEN",
				Inode: ino(1), IsListening: true, BindScope: model.BindScopeWildcard,
				OwnerPIDs: []int{}, OwnerNames: []string{}, OwnerUIDs: []int{}, OwnerUsers: []string{},
				CollectedAt: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC),
			},
			{
				ID: "unix:2", Protocol: model.ProtocolUnix, Family: model.FamilyUnix,
				UnixPath: "/tmp/with space.sock", UnixType: "STREAM", State: "CONNECTED",
				Inode: ino(2), BindScope: model.BindScopeNotApplicable,
				OwnerPIDs: []int{123}, OwnerNames: []string{"demo"}, OwnerUIDs: []int{1000}, OwnerUsers: []string{"demo"},
				CollectedAt: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC),
			},
		},
		Processes: []model.Process{
			{PID: 123, Name: "demo", Cmdline: "demo [1 args hidden]", SocketIDs: []string{"unix:2"}, Sockets: 1},
		},
		Findings: []model.Finding{
			{
				RuleID: "SH-WILD-001", RuleName: "Wildcard-bound TCP listener", Severity: model.SeverityInfo,
				Summary: "Wildcard-bound TCP listener on 0.0.0.0:8080", SocketID: "tcp:1",
				Evidence:    model.Evidence{Protocol: "tcp", LocalEndpoint: "0.0.0.0:8080", State: "LISTEN", Inode: ino(1)},
				CollectedAt: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC),
			},
		},
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, snapshot()); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if strings.Contains(buf.String(), "\x1b") {
		t.Errorf("JSON contains a raw escape byte")
	}
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if decoded["schema_version"].(float64) != model.SchemaVersion {
		t.Errorf("schema_version = %v", decoded["schema_version"])
	}
	for _, key := range []string{"sockets", "processes", "findings"} {
		arr, ok := decoded[key].([]any)
		if !ok {
			t.Errorf("%s is not an array: %T", key, decoded[key])
		}
		if arr == nil {
			t.Errorf("%s is null, want []", key)
		}
	}
}

func TestWriteFileOverwriteGuard(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if err := WriteFile(path, snapshot(), false); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := WriteFile(path, snapshot(), false); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second write error = %v, want already exists", err)
	}
	if err := WriteFile(path, snapshot(), true); err != nil {
		t.Fatalf("force write: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var snap model.Snapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if snap.SchemaVersion != model.SchemaVersion {
		t.Errorf("schema = %d", snap.SchemaVersion)
	}
}

func TestWriteText(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteText(&buf, snapshot()); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"SockHound test", "Scope:", "Visibility: partial", "Sockets: 2 total",
		"PROTO", "0.0.0.0:8080", "/tmp/with space.sock", "SH-WILD-001",
		"Collection warnings:", "process visibility limited",
		"JSON exports may contain",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Errorf("text output contains ANSI escape")
	}
}

func TestTextSanitizesControlCharacters(t *testing.T) {
	snap := snapshot()
	snap.Sockets[1].UnixPath = "/tmp/\x1b[31mevil\x07.sock"
	snap.Processes[0].Name = "demo\x1b[2J"
	var buf bytes.Buffer
	if err := WriteText(&buf, snap); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "\x1b") || strings.Contains(out, "\x07") {
		t.Errorf("control characters leaked into text output: %q", out)
	}
}

func TestMarshalJSON(t *testing.T) {
	b, err := MarshalJSON(snapshot())
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	if !json.Valid(b) {
		t.Errorf("MarshalJSON returned invalid JSON")
	}
}
