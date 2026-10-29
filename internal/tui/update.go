package tui

import (
	"strings"

	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
	"github.com/zoro/sockhound/internal/filter"
	"github.com/zoro/sockhound/internal/model"
	"github.com/zoro/sockhound/internal/output"
)

// Update handles messages and key presses.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case tea.KeyPressMsg:
		return m.handleKey(msg)

	case scanDoneMsg:
		m.loading = false
		m.cancel = nil
		if msg.err != nil {
			if m.snap == nil {
				m.scanErr = msg.err.Error()
				m.setError("Scan failed: %v", msg.err)
			} else {
				m.setError("Refresh failed: %v", msg.err)
			}
			return m, nil
		}
		snap := msg.snapshot
		m.snap = &snap
		m.scanErr = ""
		m.rebuild()
		if m.detailOpen {
			m.detailScroll = 0
		}
		m.setStatus("Snapshot %s | %d sockets | %d findings",
			snap.CollectedAt.Format("15:04:05"), len(snap.Sockets), len(snap.Findings))
		return m, nil

	case spinner.TickMsg:
		if !m.loading {
			return m, nil
		}
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m *Model) handleKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	if m.exportOpen {
		return m.handleExportKey(msg)
	}
	if m.filterMode {
		return m.handleFilterKey(msg)
	}
	if m.helpOpen {
		return m.handleHelpKey(key)
	}
	if m.detailOpen {
		return m.handleDetailKey(key)
	}

	switch key {
	case "q", "ctrl+c":
		return m, m.quit()
	case "?":
		m.openHelp()
		return m, nil
	case "1":
		m.switchTab(TabDashboard)
	case "2":
		m.switchTab(TabSockets)
	case "3":
		m.switchTab(TabUnix)
	case "4":
		m.switchTab(TabProcesses)
	case "5":
		m.switchTab(TabFindings)
	case "tab":
		m.switchTab(Tab((int(m.tab) + 1) % 5))
	case "shift+tab":
		m.switchTab(Tab((int(m.tab) + 4) % 5))
	case "up", "k":
		m.table.MoveUp(1)
	case "down", "j":
		m.table.MoveDown(1)
	case "pgup", "b":
		m.table.MoveUp(max(1, m.table.Height()))
	case "pgdown":
		m.table.MoveDown(max(1, m.table.Height()))
	case "g", "home":
		m.table.GotoTop()
	case "G", "end":
		m.table.GotoBottom()
	case "enter":
		if m.hasSelection() {
			m.detailOpen = true
			m.detailScroll = 0
		}
	case "esc":
		if m.query.Raw != "" {
			m.query = filter.Parse("")
			m.filterInput.SetValue("")
			m.rebuild()
			m.setStatus("Filter cleared")
		}
	case "/":
		return m, m.openFilter()
	case "s":
		m.cycleSort()
	case "f":
		m.cycleContextFilter()
	case "r":
		if m.loading {
			m.setStatus("Scan already running")
			return m, nil
		}
		return m, m.refresh()
	case "e":
		return m, m.openExport()
	}
	return m, nil
}

func (m *Model) hasSelection() bool {
	switch m.tab {
	case TabProcesses:
		_, ok := m.selectedProcess()
		return ok
	case TabFindings:
		_, ok := m.selectedFinding()
		return ok
	default:
		_, ok := m.selectedSocket()
		return ok
	}
}

func (m *Model) switchTab(t Tab) {
	if t == TabHelp {
		m.openHelp()
		return
	}
	m.helpOpen = false
	m.tab = t
	m.detailOpen = false
	m.detailScroll = 0
	m.rebuild()
}

func (m *Model) openHelp() {
	if !m.helpOpen {
		m.prevTab = m.tab
	}
	m.helpOpen = true
	m.tab = TabHelp
	m.detailOpen = false
	m.helpScroll = 0
}

func (m *Model) closeHelp() {
	m.helpOpen = false
	m.tab = m.prevTab
	m.rebuild()
}

func (m *Model) handleHelpKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "q", "ctrl+c":
		return m, m.quit()
	case "?", "esc":
		m.closeHelp()
	case "up", "k":
		m.helpScroll = max(0, m.helpScroll-1)
	case "down", "j":
		m.helpScroll++
	case "pgup", "b":
		m.helpScroll = max(0, m.helpScroll-10)
	case "pgdown":
		m.helpScroll += 10
	case "g", "home":
		m.helpScroll = 0
	case "1":
		m.closeHelp()
		m.switchTab(TabDashboard)
	case "2":
		m.closeHelp()
		m.switchTab(TabSockets)
	case "3":
		m.closeHelp()
		m.switchTab(TabUnix)
	case "4":
		m.closeHelp()
		m.switchTab(TabProcesses)
	case "5":
		m.closeHelp()
		m.switchTab(TabFindings)
	}
	return m, nil
}

func (m *Model) handleDetailKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "q", "ctrl+c":
		return m, m.quit()
	case "esc", "enter":
		m.detailOpen = false
	case "up", "k":
		m.detailScroll = max(0, m.detailScroll-1)
	case "down", "j":
		m.detailScroll++
	case "pgup", "b":
		m.detailScroll = max(0, m.detailScroll-10)
	case "pgdown":
		m.detailScroll += 10
	case "g", "home":
		m.detailScroll = 0
	case "G", "end":
		m.detailScroll = 1 << 30
	case "?":
		m.openHelp()
	case "r":
		if !m.loading {
			return m, m.refresh()
		}
	}
	return m, nil
}

func (m *Model) openFilter() tea.Cmd {
	m.filterMode = true
	m.detailOpen = false
	m.filterInput.SetValue(m.query.Raw)
	m.filterInput.CursorEnd()
	return m.filterInput.Focus()
}

func (m *Model) handleFilterKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.filterMode = false
		m.filterInput.Blur()
		m.query = filter.Parse("")
		m.filterInput.SetValue("")
		m.rebuild()
		m.setStatus("Filter cleared")
		return m, nil
	case "enter":
		m.filterMode = false
		m.filterInput.Blur()
		m.setStatus("Filter: %s", orDash(m.query.Raw))
		return m, nil
	}
	var cmd tea.Cmd
	m.filterInput, cmd = m.filterInput.Update(msg)
	m.query = filter.Parse(m.filterInput.Value())
	m.rebuild()
	return m, cmd
}

func (m *Model) cycleContextFilter() {
	if m.tab == TabFindings {
		switch m.severityFilter {
		case "":
			m.severityFilter = model.SeverityHigh
		case model.SeverityHigh:
			m.severityFilter = model.SeverityMedium
		case model.SeverityMedium:
			m.severityFilter = model.SeverityLow
		case model.SeverityLow:
			m.severityFilter = model.SeverityInfo
		default:
			m.severityFilter = ""
		}
		if m.severityFilter == "" {
			m.setStatus("Severity filter: all")
		} else {
			m.setStatus("Severity filter: %s", m.severityFilter)
		}
	} else {
		m.ownerFilter = (m.ownerFilter + 1) % 3
		m.setStatus("Filter: %s", m.ownerFilterLabel())
	}
	m.rebuild()
}

func (m *Model) refresh() tea.Cmd {
	m.setStatus("Scanning local sockets…")
	return tea.Batch(m.spinner.Tick, m.startScan())
}

func (m *Model) openExport() tea.Cmd {
	if m.snap == nil {
		m.setError("No snapshot to export")
		return nil
	}
	m.exportOpen = true
	m.exportConfirm = false
	m.exportMsg = ""
	m.exportMsgIsErr = false
	m.exportInput.SetValue(m.defaultExportName())
	m.exportInput.CursorEnd()
	return m.exportInput.Focus()
}

func (m *Model) handleExportKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.exportOpen = false
		m.exportInput.Blur()
		m.exportMsg = ""
		return m, nil
	case "enter":
		m.doExport()
		return m, nil
	}
	var cmd tea.Cmd
	m.exportInput, cmd = m.exportInput.Update(msg)
	m.exportConfirm = false
	m.exportMsg = ""
	return m, cmd
}

func (m *Model) doExport() {
	if m.snap == nil {
		m.exportMsg = "No snapshot to export"
		m.exportMsgIsErr = true
		return
	}
	path := strings.TrimSpace(m.exportInput.Value())
	if path == "" {
		m.exportMsg = "Enter a destination path"
		m.exportMsgIsErr = true
		return
	}
	err := output.WriteFile(path, *m.snap, m.exportConfirm)
	if err != nil {
		if !m.exportConfirm && strings.Contains(err.Error(), "already exists") {
			m.exportConfirm = true
			m.exportMsg = "File exists. Press Enter again to overwrite, or edit the path."
			m.exportMsgIsErr = true
			return
		}
		m.exportMsg = err.Error()
		m.exportMsgIsErr = true
		return
	}
	m.exportOpen = false
	m.exportInput.Blur()
	m.exportMsg = ""
	m.setStatus("Exported snapshot to %s", path)
}
