package tui

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/zoro/sockhound/internal/model"
)

func ptr(n int) *int         { return &n }
func inode(n uint64) *uint64 { return &n }

func testSnapshot() model.Snapshot {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	return model.Snapshot{
		SchemaVersion:    model.SchemaVersion,
		ToolVersion:      "test",
		CollectedAt:      now,
		DurationMS:       8,
		NetworkNamespace: "net:[123]",
		Scope:            "current network namespace net:[123]",
		Visibility:       model.Visibility{Partial: true, Warnings: []string{"process visibility limited"}},
		Stats: model.Stats{
			TotalSockets: 3, TCP: 2, Unix: 1, Listeners: 2, UnresolvedOwners: 1,
			TCPStates:  map[string]int{"LISTEN": 2},
			Severities: map[string]int{"INFO": 2, "LOW": 0, "MEDIUM": 0, "HIGH": 0},
		},
		Sockets: []model.Socket{
			{
				ID: "tcp:1", Protocol: model.ProtocolTCP, Family: model.FamilyIPv4,
				LocalAddress: "0.0.0.0", LocalPort: ptr(8080), State: "LISTEN",
				Inode: inode(1), IsListening: true, BindScope: model.BindScopeWildcard,
				OwnerPIDs: []int{123}, OwnerNames: []string{"demo"}, OwnerUIDs: []int{1000}, OwnerUsers: []string{"demo"},
				CollectedAt: now,
			},
			{
				ID: "tcp6:2", Protocol: model.ProtocolTCP6, Family: model.FamilyIPv6,
				LocalAddress: "2001:df0:b240:573b:520c:f5d2:918:559", LocalPort: ptr(443), State: "LISTEN",
				Inode: inode(2), IsListening: true, BindScope: model.BindScopeSpecific,
				OwnerPIDs: []int{123}, OwnerNames: []string{"demo"}, OwnerUIDs: []int{1000}, OwnerUsers: []string{"demo"},
				CollectedAt: now,
			},
			{
				ID: "unix:3", Protocol: model.ProtocolUnix, Family: model.FamilyUnix,
				UnixPath: "/tmp/demo.sock", UnixType: "STREAM", State: "CONNECTED", Inode: inode(3),
				BindScope: model.BindScopeNotApplicable,
				OwnerPIDs: []int{}, OwnerNames: []string{}, OwnerUIDs: []int{}, OwnerUsers: []string{},
				CollectedAt: now,
			},
		},
		Processes: []model.Process{
			{PID: 123, Name: "demo", Cmdline: "demo [1 args hidden]", SocketIDs: []string{"tcp:1", "tcp6:2"}, Sockets: 2, Listeners: 2},
		},
		Findings: []model.Finding{
			{
				RuleID: "SH-WILD-001", RuleName: "Wildcard-bound TCP listener", Severity: model.SeverityInfo,
				Summary: "Wildcard-bound TCP listener on 0.0.0.0:8080", SocketID: "tcp:1",
				Evidence:    model.Evidence{Protocol: "tcp", LocalEndpoint: "0.0.0.0:8080", State: "LISTEN", Inode: inode(1), PID: ptr(123), Process: "demo", User: "demo"},
				CollectedAt: now,
			},
			{
				RuleID: "SH-OWNER-001", RuleName: "Owner unresolved", Severity: model.SeverityInfo,
				Summary: "No visible process owns /tmp/demo.sock", SocketID: "unix:3",
				Evidence:    model.Evidence{Protocol: "unix", LocalEndpoint: "/tmp/demo.sock", State: "CONNECTED", Inode: inode(3)},
				CollectedAt: now,
			},
		},
	}
}

func newTestModel(t *testing.T, opts ...Options) *Model {
	t.Helper()
	s := testSnapshot()
	o := Options{Initial: &s, Version: "test"}
	if len(opts) > 0 {
		o = opts[0]
	}
	m := New(o)
	m.Init()
	m.Update(tea.WindowSizeMsg{Width: 140, Height: 40})
	return m
}

func send(m *Model, msg tea.Msg) tea.Cmd {
	_, cmd := m.Update(msg)
	return cmd
}

func runeKey(r rune) tea.KeyPressMsg {
	return tea.KeyPressMsg{Code: r, Text: string(r)}
}

func specialKey(code rune) tea.KeyPressMsg {
	return tea.KeyPressMsg{Code: code}
}

func viewString(m *Model) string {
	return m.View().Content
}

func TestInitialView(t *testing.T) {
	m := newTestModel(t)
	out := viewString(m)
	for _, want := range []string{"SockHound", "SOCKET SUMMARY", "TCP STATES", "SOCKET INVENTORY", "SELECTED", "FINDINGS"} {
		if !strings.Contains(out, want) {
			t.Errorf("view missing %q\n%s", want, out)
		}
	}
}

func TestTabSwitching(t *testing.T) {
	m := newTestModel(t)
	cases := []struct {
		key  rune
		tab  Tab
		want string
	}{
		{'2', TabSockets, "TCP/UDP SOCKETS"},
		{'3', TabUnix, "UNIX SOCKETS"},
		{'4', TabProcesses, "PROCESSES"},
		{'5', TabFindings, "FINDINGS"},
		{'1', TabDashboard, "SOCKET INVENTORY"},
	}
	for _, tc := range cases {
		send(m, runeKey(tc.key))
		if m.tab != tc.tab {
			t.Errorf("key %c tab = %d, want %d", tc.key, m.tab, tc.tab)
		}
		if !strings.Contains(viewString(m), tc.want) {
			t.Errorf("tab %d view missing %q", tc.tab, tc.want)
		}
	}
}

func TestFilter(t *testing.T) {
	m := newTestModel(t)
	send(m, runeKey('/'))
	if !m.filterMode {
		t.Fatalf("filter mode not enabled")
	}
	for _, r := range "tcp" {
		send(m, runeKey(r))
	}
	if got := m.query.Raw; got != "tcp" {
		t.Errorf("query = %q, want tcp", got)
	}
	if len(m.socketRows) != 2 {
		t.Errorf("filtered rows = %d, want 2 TCP sockets", len(m.socketRows))
	}
	send(m, specialKey(tea.KeyEnter))
	if m.filterMode {
		t.Errorf("filter mode should close on enter")
	}
	send(m, specialKey(tea.KeyEsc))
	if m.query.Raw != "" || len(m.socketRows) != 3 {
		t.Errorf("esc did not clear filter: query=%q rows=%d", m.query.Raw, len(m.socketRows))
	}
}

func TestOwnerFilter(t *testing.T) {
	m := newTestModel(t)
	send(m, runeKey('f'))
	if m.ownerFilter != 1 {
		t.Fatalf("owner filter = %d, want 1", m.ownerFilter)
	}
	if len(m.socketRows) != 1 || m.socketRows[0].ID != "unix:3" {
		t.Errorf("unknown-owner rows = %+v", m.socketRows)
	}
	send(m, runeKey('f'))
	if m.ownerFilter != 2 || len(m.socketRows) != 2 {
		t.Errorf("known-owner rows = %+v", m.socketRows)
	}
	send(m, runeKey('f'))
	if m.ownerFilter != 0 || len(m.socketRows) != 3 {
		t.Errorf("all-owner rows = %d", len(m.socketRows))
	}
}

func TestSortCycling(t *testing.T) {
	m := newTestModel(t)
	first := m.currentSort().key
	send(m, runeKey('s'))
	second := m.currentSort().key
	if first == second {
		t.Errorf("sort did not change from %q", first)
	}
	if m.status == "" {
		t.Errorf("sort did not set a status message")
	}
}

func TestDetailView(t *testing.T) {
	m := newTestModel(t)
	send(m, specialKey(tea.KeyEnter))
	if !m.detailOpen {
		t.Fatalf("detail did not open")
	}
	out := viewString(m)
	for _, want := range []string{"SELECTED SOCKET", "Inode", "OWNER", "demo"} {
		if !strings.Contains(out, want) {
			t.Errorf("detail missing %q\n%s", want, out)
		}
	}
	send(m, specialKey(tea.KeyEsc))
	if m.detailOpen {
		t.Errorf("detail did not close")
	}
}

func TestFindingsTabAndFilter(t *testing.T) {
	m := newTestModel(t)
	send(m, runeKey('5'))
	if len(m.findingRows) != 2 {
		t.Fatalf("findings = %d, want 2", len(m.findingRows))
	}
	for i := 0; i < 4; i++ {
		send(m, runeKey('f'))
	}
	if m.severityFilter != model.SeverityInfo {
		t.Fatalf("severity filter = %q, want INFO", m.severityFilter)
	}
	if len(m.findingRows) != 2 {
		t.Errorf("INFO findings = %d, want 2", len(m.findingRows))
	}
	send(m, specialKey(tea.KeyEnter))
	if !strings.Contains(viewString(m), "FINDING") {
		t.Errorf("finding detail missing")
	}
}

func TestProcessTab(t *testing.T) {
	m := newTestModel(t)
	send(m, runeKey('4'))
	if len(m.processRows) != 1 {
		t.Fatalf("processes = %d", len(m.processRows))
	}
	send(m, specialKey(tea.KeyEnter))
	out := viewString(m)
	if !strings.Contains(out, "PROCESS") || !strings.Contains(out, "demo") || !strings.Contains(out, "SOCKETS") {
		t.Errorf("process detail missing content\n%s", out)
	}
}

func TestHelp(t *testing.T) {
	m := newTestModel(t)
	send(m, runeKey('?'))
	if !m.helpOpen {
		t.Fatalf("help did not open")
	}
	out := viewString(m)
	for _, want := range []string{"HELP", "TABS"} {
		if !strings.Contains(out, want) {
			t.Errorf("help missing %q\n%s", want, out)
		}
	}
	for i := 0; i < 8; i++ {
		send(m, specialKey(tea.KeyPgDown))
	}
	out = viewString(m)
	for _, want := range []string{"RULES", "SH-WILD-001"} {
		if !strings.Contains(out, want) {
			t.Errorf("help missing %q after scrolling\n%s", want, out)
		}
	}
	send(m, specialKey(tea.KeyEsc))
	if m.helpOpen || m.tab != TabDashboard {
		t.Errorf("help did not close to previous tab")
	}
}

func TestSmallTerminal(t *testing.T) {
	m := newTestModel(t)
	m.Update(tea.WindowSizeMsg{Width: 60, Height: 20})
	out := viewString(m)
	if !strings.Contains(out, "larger terminal") {
		t.Errorf("small-terminal hint missing:\n%s", out)
	}
}

func TestResizeAndLineWidths(t *testing.T) {
	m := newTestModel(t)
	for _, size := range [][2]int{{80, 24}, {100, 30}, {140, 40}, {160, 50}} {
		m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		out := viewString(m)
		for i, line := range strings.Split(out, "\n") {
			if w := ansi.StringWidth(line); w > size[0] {
				t.Errorf("size %dx%d line %d width %d exceeds terminal: %q", size[0], size[1], i, w, line)
			}
		}
	}
}

func TestLongIPv6Detail(t *testing.T) {
	m := newTestModel(t)
	send(m, runeKey('2'))
	// Render once so the table receives its columns and rows, then use the
	// same navigation path a user would.
	viewString(m)
	send(m, runeKey('j'))
	send(m, specialKey(tea.KeyEnter))
	out := viewString(m)
	if !strings.Contains(out, "2001:df0:b240:573b:520c:f5d2:918:559") {
		t.Errorf("full IPv6 address missing from detail\n%s", out)
	}
}

func TestExportModal(t *testing.T) {
	m := newTestModel(t)
	send(m, runeKey('e'))
	if !m.exportOpen {
		t.Fatalf("export modal did not open")
	}
	if !strings.Contains(viewString(m), "EXPORT SNAPSHOT") {
		t.Errorf("export modal missing from view")
	}
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatalf("write existing file: %v", err)
	}
	m.exportInput.SetValue(path)
	send(m, specialKey(tea.KeyEnter))
	if !m.exportOpen || !strings.Contains(m.exportMsg, "exists") {
		t.Errorf("overwrite confirmation missing: open=%v msg=%q", m.exportOpen, m.exportMsg)
	}
	send(m, specialKey(tea.KeyEnter))
	if m.exportOpen {
		t.Errorf("export modal should close after overwrite")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	var snap model.Snapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		t.Fatalf("invalid export JSON: %v", err)
	}
	if snap.SchemaVersion != model.SchemaVersion {
		t.Errorf("export schema = %d", snap.SchemaVersion)
	}
}

func TestExportEmptyPath(t *testing.T) {
	m := newTestModel(t)
	send(m, runeKey('e'))
	m.exportInput.SetValue("")
	send(m, specialKey(tea.KeyEnter))
	if !m.exportOpen || m.exportMsg == "" {
		t.Errorf("empty path was not rejected")
	}
}

func TestAutoRefresh(t *testing.T) {
	s := testSnapshot()
	m := New(Options{
		Version:         "test",
		RefreshInterval: time.Second,
		Scan: func(context.Context) (model.Snapshot, error) {
			return s, nil
		},
	})
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 35})
	cmd := send(m, autoRefreshMsg{})
	if !m.loading {
		t.Fatalf("auto refresh did not start a scan")
	}
	if cmd == nil {
		t.Fatalf("auto refresh returned no command")
	}
	if m.cancel != nil {
		m.cancel()
	}
}

func TestAutoRefreshDisabled(t *testing.T) {
	m := newTestModel(t)
	if cmd := send(m, autoRefreshMsg{}); cmd != nil || m.loading {
		t.Errorf("auto refresh ran while disabled: cmd=%v loading=%v", cmd != nil, m.loading)
	}
}

func TestRefresh(t *testing.T) {
	s := testSnapshot()
	calls := 0
	m := New(Options{
		Version: "test",
		Scan: func(context.Context) (model.Snapshot, error) {
			calls++
			return s, nil
		},
	})
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 35})
	cmd := send(m, runeKey('r'))
	if !m.loading {
		t.Fatalf("refresh did not set loading")
	}
	if cmd == nil {
		t.Fatalf("refresh returned no command")
	}
	// Drain the batch: run commands until a scanDoneMsg is produced.
	var done tea.Msg
	queue := []tea.Cmd{cmd}
	for len(queue) > 0 && done == nil {
		c := queue[0]
		queue = queue[1:]
		if c == nil {
			continue
		}
		msg := c()
		switch v := msg.(type) {
		case scanDoneMsg:
			done = v
		case tea.BatchMsg:
			queue = append(queue, v...)
		}
	}
	if done == nil {
		t.Fatalf("no scanDoneMsg produced")
	}
	send(m, done)
	if m.loading {
		t.Errorf("loading still true after scan done")
	}
	if calls != 1 {
		t.Errorf("scan calls = %d, want 1", calls)
	}
	if !strings.Contains(m.status, "Snapshot") {
		t.Errorf("status = %q", m.status)
	}
}

func TestSpinnerTickWithoutLoading(t *testing.T) {
	m := newTestModel(t)
	if cmd := send(m, spinner.TickMsg{}); cmd != nil {
		t.Errorf("spinner tick scheduled a command while not loading")
	}
}

func TestQuit(t *testing.T) {
	m := newTestModel(t)
	cmd := send(m, runeKey('q'))
	if cmd == nil {
		t.Errorf("quit returned no command")
	}
}

func TestEmptySnapshotView(t *testing.T) {
	s := testSnapshot()
	s.Sockets = nil
	s.Findings = nil
	s.Processes = nil
	m := New(Options{Initial: &s, Version: "test"})
	m.Init()
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 35})
	out := viewString(m)
	if !strings.Contains(out, "No sockets match") {
		t.Errorf("empty snapshot view = %q", out)
	}
}

func TestPartialVisibilityStatus(t *testing.T) {
	m := newTestModel(t)
	if !strings.Contains(viewString(m), "visibility partial") {
		t.Errorf("partial visibility not shown in status")
	}
}
