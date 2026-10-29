// Package tui implements the full-screen SockHound terminal interface.
package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/table"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"github.com/zoro/sockhound/internal/filter"
	"github.com/zoro/sockhound/internal/model"
)

// Tab identifies a top-level screen.
type Tab int

const (
	TabDashboard Tab = iota
	TabSockets
	TabUnix
	TabProcesses
	TabFindings
	TabHelp
)

// Options configures the TUI model.
type Options struct {
	// Scan performs a fresh scan. It is injected so the TUI does not read
	// procfs during rendering and can be tested with fixtures.
	Scan func(context.Context) (model.Snapshot, error)
	// Initial is an optional pre-collected snapshot (tests, alternate modes).
	Initial *model.Snapshot
	// RefreshInterval enables automatic rescans in the TUI. Zero disables it.
	RefreshInterval time.Duration
	Version         string
	NoColor         bool
}

type scanDoneMsg struct {
	snapshot model.Snapshot
	err      error
}

// autoRefreshMsg fires when the configured refresh interval elapses.
type autoRefreshMsg struct{}

type sortMode struct {
	key   string
	label string
}

var sortModes = map[Tab][]sortMode{
	TabDashboard: {
		{"default", "collection"},
		{"protocol", "protocol"},
		{"local", "local address"},
		{"state", "state"},
		{"pid", "pid"},
		{"process", "process"},
		{"severity", "severity"},
	},
	TabSockets: {
		{"default", "collection"},
		{"protocol", "protocol"},
		{"local", "local address"},
		{"state", "state"},
		{"pid", "pid"},
		{"process", "process"},
		{"severity", "severity"},
	},
	TabUnix: {
		{"default", "collection"},
		{"local", "path"},
		{"state", "state"},
		{"pid", "pid"},
		{"process", "process"},
		{"severity", "severity"},
	},
	TabProcesses: {
		{"pid", "pid"},
		{"name", "name"},
		{"sockets", "socket count"},
		{"listeners", "listener count"},
	},
	TabFindings: {
		{"severity", "severity"},
		{"rule", "rule"},
		{"socket", "socket"},
	},
}

// Model is the root Bubble Tea model.
type Model struct {
	opts Options
	keys keyMap
	st   styles

	width, height int
	tab           Tab
	prevTab       Tab
	helpOpen      bool

	snap     *model.Snapshot
	loading  bool
	scanErr  string
	status   string
	statusOK bool
	cancel   context.CancelFunc

	refreshInterval time.Duration

	table       table.Model
	spinner     spinner.Model
	filterInput textinput.Model
	exportInput textinput.Model

	filterMode     bool
	exportOpen     bool
	exportConfirm  bool
	exportMsg      string
	exportMsgIsErr bool

	query          filter.Query
	sortIdx        map[Tab]int
	ownerFilter    int // 0 all, 1 unknown, 2 known
	severityFilter model.Severity

	detailOpen   bool
	detailScroll int
	helpScroll   int

	socketRows  []model.Socket
	processRows []model.Process
	findingRows []model.Finding

	// pendingRows holds table rows built before the table has columns (for
	// example during Init, before the first WindowSizeMsg).
	pendingRows       []table.Row
	pendingIdx        int
	rowsGeneration    int
	appliedGeneration int
}

// New creates a TUI model.
func New(opts Options) *Model {
	st := newStyles(opts.NoColor)
	sp := spinner.New(spinner.WithSpinner(spinner.Dot))
	sp.Style = st.accent

	fi := textinput.New()
	fi.Prompt = "/ "
	fi.Placeholder = "tcp, pid:123, port:8080, proc:nginx, owner:unknown"
	fi.CharLimit = 256

	ei := textinput.New()
	ei.Prompt = "path: "
	ei.CharLimit = 512

	tb := table.New(table.WithFocused(true))
	tb.SetStyles(table.Styles{
		Header:   st.tableHeader,
		Cell:     st.tableCell,
		Selected: st.selected,
	})

	m := &Model{
		opts:            opts,
		keys:            defaultKeyMap(),
		st:              st,
		tab:             TabDashboard,
		prevTab:         TabDashboard,
		table:           tb,
		spinner:         sp,
		filterInput:     fi,
		exportInput:     ei,
		sortIdx:         map[Tab]int{},
		severityFilter:  "",
		statusOK:        true,
		refreshInterval: opts.RefreshInterval,
	}
	return m
}

// Init starts the first scan (unless an initial snapshot was supplied) and the
// automatic refresh timer when configured.
func (m *Model) Init() tea.Cmd {
	var cmds []tea.Cmd
	switch {
	case m.opts.Initial != nil:
		m.setSnapshot(*m.opts.Initial)
	case m.opts.Scan == nil:
		m.scanErr = "no scan function configured"
	default:
		cmds = append(cmds, m.spinner.Tick, m.startScan())
	}
	if m.opts.Scan != nil {
		if cmd := m.autoRefreshTick(); cmd != nil {
			cmds = append(cmds, cmd)
		}
	}
	if len(cmds) == 0 {
		return nil
	}
	return tea.Batch(cmds...)
}

func (m *Model) autoRefreshTick() tea.Cmd {
	if m.refreshInterval <= 0 {
		return nil
	}
	return tea.Tick(m.refreshInterval, func(time.Time) tea.Msg {
		return autoRefreshMsg{}
	})
}

func (m *Model) startScan() tea.Cmd {
	if m.loading {
		return nil
	}
	scan := m.opts.Scan
	if scan == nil {
		m.scanErr = "no scan function configured"
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.loading = true
	m.scanErr = ""
	return func() tea.Msg {
		defer cancel()
		snap, err := scan(ctx)
		return scanDoneMsg{snapshot: snap, err: err}
	}
}

func (m *Model) setSnapshot(snap model.Snapshot) {
	m.snap = &snap
	m.rebuild()
	if m.status == "" {
		m.status = "Snapshot collected " + snap.CollectedAt.Format("15:04:05")
		m.statusOK = true
	}
}

func (m *Model) quit() tea.Cmd {
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	return tea.Quit
}

func (m *Model) currentSort() sortMode {
	modes := sortModes[m.tab]
	if len(modes) == 0 {
		return sortMode{"default", "collection"}
	}
	i := m.sortIdx[m.tab]
	if i < 0 || i >= len(modes) {
		i = 0
	}
	return modes[i]
}

func (m *Model) cycleSort() {
	modes := sortModes[m.tab]
	if len(modes) == 0 {
		return
	}
	m.sortIdx[m.tab] = (m.sortIdx[m.tab] + 1) % len(modes)
	m.rebuild()
	m.status = "Sort: " + m.currentSort().label
	m.statusOK = true
}

func (m *Model) selectedSocket() (model.Socket, bool) {
	if m.snap == nil || len(m.socketRows) == 0 {
		return model.Socket{}, false
	}
	i := m.table.Cursor()
	if i < 0 || i >= len(m.socketRows) {
		return model.Socket{}, false
	}
	return m.socketRows[i], true
}

func (m *Model) selectedProcess() (model.Process, bool) {
	if len(m.processRows) == 0 {
		return model.Process{}, false
	}
	i := m.table.Cursor()
	if i < 0 || i >= len(m.processRows) {
		return model.Process{}, false
	}
	return m.processRows[i], true
}

func (m *Model) selectedFinding() (model.Finding, bool) {
	if len(m.findingRows) == 0 {
		return model.Finding{}, false
	}
	i := m.table.Cursor()
	if i < 0 || i >= len(m.findingRows) {
		return model.Finding{}, false
	}
	return m.findingRows[i], true
}

func (m *Model) maxSeverity(socketID string) model.Severity {
	if m.snap == nil {
		return ""
	}
	best := model.Severity("")
	for _, f := range m.snap.Findings {
		if f.SocketID != socketID {
			continue
		}
		if f.Severity.Rank() > best.Rank() {
			best = f.Severity
		}
	}
	return best
}

func findingKey(f model.Finding) string {
	return f.RuleID + "|" + f.SocketID
}

func (m *Model) defaultExportName() string {
	ts := time.Now()
	if m.snap != nil && !m.snap.CollectedAt.IsZero() {
		ts = m.snap.CollectedAt
	}
	return fmt.Sprintf("sockhound-snapshot-%s.json", ts.Format("20060102-150405"))
}

func (m *Model) tabName(t Tab) string {
	switch t {
	case TabDashboard:
		return "Dashboard"
	case TabSockets:
		return "TCP/UDP"
	case TabUnix:
		return "Unix"
	case TabProcesses:
		return "Processes"
	case TabFindings:
		return "Findings"
	case TabHelp:
		return "Help"
	default:
		return "?"
	}
}

func (m *Model) ownerFilterLabel() string {
	switch m.ownerFilter {
	case 1:
		return "owner unknown"
	case 2:
		return "owner known"
	default:
		return "all owners"
	}
}

func (m *Model) setStatus(format string, args ...any) {
	m.status = fmt.Sprintf(format, args...)
	m.statusOK = true
}

func (m *Model) setError(format string, args ...any) {
	m.status = fmt.Sprintf(format, args...)
	m.statusOK = false
}

func cleanCell(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t':
			return ' '
		case r == '\n' || r == '\r':
			return ' '
		case r < 0x20 || r == 0x7f:
			return '?'
		default:
			return r
		}
	}, s)
}
