package tui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

const (
	minWidth  = 80
	minHeight = 24
)

// View renders the current screen.
func (m *Model) View() tea.View {
	v := tea.View{AltScreen: true, WindowTitle: "SockHound"}
	if m.width <= 0 || m.height <= 0 {
		v.SetContent("SockHound — starting…")
		return v
	}
	if m.width < minWidth || m.height < minHeight {
		v.SetContent(m.renderTooSmall())
		return v
	}

	header := m.fitLine(m.renderHeader(), m.width)
	status := m.fitLine(m.renderStatus(), m.width)
	footer := m.fitLine(m.renderFooter(), m.width)
	bodyH := m.height - lipgloss.Height(header) - lipgloss.Height(status) - lipgloss.Height(footer)
	if bodyH < 1 {
		bodyH = 1
	}
	body := m.renderBody(bodyH)
	content := lipgloss.JoinVertical(lipgloss.Left, header, status, body, footer)
	v.SetContent(m.fitBlock(content, m.width, m.height))
	return v
}

func (m *Model) renderTooSmall() string {
	msg := []string{
		"SockHound needs a larger terminal.",
		fmt.Sprintf("Minimum: %dx%d   Current: %dx%d", minWidth, minHeight, m.width, m.height),
		"Resize the terminal, or press q to quit.",
	}
	var b strings.Builder
	top := max(0, (m.height-len(msg))/2)
	for i := 0; i < top; i++ {
		b.WriteString("\n")
	}
	for _, line := range msg {
		pad := max(0, (m.width-len(line))/2)
		b.WriteString(strings.Repeat(" ", pad))
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

func (m *Model) renderHeader() string {
	parts := []string{m.st.accent.Render("SockHound")}
	tabs := []struct {
		tab  Tab
		key  string
		name string
	}{
		{TabDashboard, "1", "Dashboard"},
		{TabSockets, "2", "TCP/UDP"},
		{TabUnix, "3", "Unix"},
		{TabProcesses, "4", "Processes"},
		{TabFindings, "5", "Findings"},
	}
	for _, t := range tabs {
		label := fmt.Sprintf("[%s] %s", t.key, t.name)
		if m.tab == t.tab {
			parts = append(parts, m.st.activeTab.Render(label))
		} else {
			parts = append(parts, m.st.inactiveTab.Render(label))
		}
	}
	if m.helpOpen {
		parts = append(parts, m.st.activeTab.Render("[?] Help"))
	}
	return strings.Join(parts, "  ")
}

func (m *Model) renderStatus() string {
	var parts []string
	if m.loading {
		parts = append(parts, m.spinner.View()+" scanning")
	}
	if m.status != "" {
		if m.statusOK {
			parts = append(parts, m.status)
		} else {
			parts = append(parts, m.st.errorText.Render(m.status))
		}
	}
	if m.snap != nil {
		parts = append(parts, "Snapshot "+m.snap.CollectedAt.Format("15:04:05"))
		parts = append(parts, "netns "+shortNetNS(m.snap.NetworkNamespace))
		if m.snap.Visibility.Partial {
			parts = append(parts, "visibility partial")
		} else {
			parts = append(parts, "visibility complete")
		}
	} else if m.scanErr != "" {
		parts = append(parts, m.st.errorText.Render("scan error: "+m.scanErr))
	} else {
		parts = append(parts, "no snapshot")
	}
	if m.filterMode {
		parts = append(parts, "filtering")
	} else if m.query.Raw != "" {
		parts = append(parts, "filter: "+m.query.Raw)
	}
	if m.tab != TabHelp {
		parts = append(parts, "sort: "+m.currentSort().label)
	}
	if m.refreshInterval > 0 {
		parts = append(parts, "auto: "+m.refreshInterval.String())
	}
	if m.ownerFilter != 0 && (m.tab == TabDashboard || m.tab == TabSockets || m.tab == TabUnix) {
		parts = append(parts, m.ownerFilterLabel())
	}
	if m.severityFilter != "" && m.tab == TabFindings {
		parts = append(parts, "severity: "+string(m.severityFilter))
	}
	return strings.Join(parts, "  │  ")
}

func (m *Model) renderFooter() string {
	m.st.help.SetWidth(m.width)
	switch {
	case m.filterMode:
		hint := m.st.dim.Render("  enter apply  ·  esc clear  ·  terms are ANDed")
		return m.filterInput.View() + hint
	case m.exportOpen:
		return m.st.dim.Render("enter export  ·  esc cancel  ·  enter twice overwrites an existing file")
	case m.detailOpen:
		return m.st.help.View(shortHelp{m.keys.Esc, m.keys.Up, m.keys.Down, m.keys.PageUp, m.keys.PageDown, m.keys.Help, m.keys.Quit})
	case m.helpOpen:
		return m.st.help.View(shortHelp{m.keys.Esc, m.keys.Up, m.keys.Down, m.keys.PageUp, m.keys.PageDown, m.keys.Quit})
	default:
		return m.st.help.View(shortHelp{
			m.keys.Up, m.keys.Down, m.keys.Enter, m.keys.Filter, m.keys.Sort,
			m.keys.Refresh, m.keys.Export, m.keys.Cycle, m.keys.Help, m.keys.Quit,
		})
	}
}

func (m *Model) renderBody(h int) string {
	switch {
	case m.exportOpen:
		return m.renderExportModal(h)
	case m.helpOpen || m.tab == TabHelp:
		return m.renderHelp(h)
	case m.detailOpen:
		return m.renderDetail(h)
	case m.tab == TabDashboard:
		return m.renderDashboard(h)
	default:
		return m.renderTab(h)
	}
}

func (m *Model) renderDashboard(h int) string {
	summaryH := 8
	if h < 16 {
		summaryH = max(4, h/3)
	}
	top := m.renderSummaryRow(summaryH)
	rest := h - summaryH - 1
	if rest < 4 {
		return top
	}
	if m.width >= 120 && rest >= 9 {
		leftW := m.width * 62 / 100
		rightW := m.width - leftW - 1
		left := m.panel(m.inventoryTitle(), m.tableView(leftW-2, rest-3), leftW, rest)
		right := m.renderDashboardRight(rightW, rest)
		return lipgloss.JoinVertical(lipgloss.Left, top, "", lipgloss.JoinHorizontal(lipgloss.Top, left, " ", right))
	}
	return lipgloss.JoinVertical(lipgloss.Left, top, "",
		m.panel(m.inventoryTitle(), m.tableView(m.width-2, rest-3), m.width, rest))
}

func (m *Model) renderSummaryRow(h int) string {
	gap := 1
	w1 := (m.width - 2*gap) / 3
	w2 := w1
	w3 := m.width - w1 - w2 - 2*gap
	contentH := max(1, h-3)
	p1 := m.panel("SOCKET SUMMARY", m.fitBlock(m.socketSummary(), w1-2, contentH), w1, h)
	p2 := m.panel("TCP STATES", m.fitBlock(m.tcpSummary(), w2-2, contentH), w2, h)
	p3 := m.panel("FINDINGS", m.fitBlock(m.findingsSummary(), w3-2, contentH), w3, h)
	return lipgloss.JoinHorizontal(lipgloss.Top, p1, strings.Repeat(" ", gap), p2, strings.Repeat(" ", gap), p3)
}

func (m *Model) renderDashboardRight(w, h int) string {
	topH := h * 60 / 100
	if topH < 6 {
		topH = h
	}
	bottomH := h - topH - 1
	selected := m.panel("SELECTED", m.fitBlock(m.compactSelection(), w-2, max(1, topH-3)), w, topH)
	if bottomH < 4 {
		return selected
	}
	findings := m.panel("FINDINGS", m.fitBlock(m.findingsSummary(), w-2, max(1, bottomH-3)), w, bottomH)
	return lipgloss.JoinVertical(lipgloss.Left, selected, "", findings)
}

func (m *Model) renderTab(h int) string {
	if m.width >= 112 {
		leftW := m.width * 66 / 100
		rightW := m.width - leftW - 1
		left := m.panel(m.inventoryTitle(), m.tableView(leftW-2, h-3), leftW, h)
		right := m.panel(m.detailTitle(), m.fitBlock(m.compactSelection(), rightW-2, max(1, h-3)), rightW, h)
		return lipgloss.JoinHorizontal(lipgloss.Top, left, " ", right)
	}
	return m.panel(m.inventoryTitle(), m.tableView(m.width-2, h-3), m.width, h)
}

func (m *Model) renderDetail(h int) string {
	lines := m.detailLines()
	bodyH := max(1, h-3)
	maxScroll := max(0, len(lines)-bodyH)
	if m.detailScroll > maxScroll {
		m.detailScroll = maxScroll
	}
	if m.detailScroll < 0 {
		m.detailScroll = 0
	}
	end := min(len(lines), m.detailScroll+bodyH)
	visible := strings.Join(lines[m.detailScroll:end], "\n")
	return m.panel(m.detailTitle(), m.fitBlock(visible, m.width-2, bodyH), m.width, h)
}

func (m *Model) renderHelp(h int) string {
	lines := m.helpLines()
	bodyH := max(1, h-3)
	maxScroll := max(0, len(lines)-bodyH)
	if m.helpScroll > maxScroll {
		m.helpScroll = maxScroll
	}
	if m.helpScroll < 0 {
		m.helpScroll = 0
	}
	end := min(len(lines), m.helpScroll+bodyH)
	visible := strings.Join(lines[m.helpScroll:end], "\n")
	return m.panel("HELP", m.fitBlock(visible, m.width-2, bodyH), m.width, h)
}

func (m *Model) renderExportModal(h int) string {
	w := min(76, m.width-4)
	if w < 40 {
		w = m.width - 2
	}
	bodyH := 9
	contentH := max(1, bodyH-3)
	lines := []string{
		"Export a versioned JSON snapshot to a local file.",
		m.st.dim.Render("The report may contain process names, users, endpoints and socket paths."),
		m.st.dim.Render("Review the file before sharing it."),
		"",
		m.exportInput.View(),
		"",
	}
	if m.exportMsg != "" {
		if m.exportMsgIsErr {
			lines = append(lines, m.st.errorText.Render(m.exportMsg))
		} else {
			lines = append(lines, m.st.successText.Render(m.exportMsg))
		}
	}
	panel := m.panel("EXPORT SNAPSHOT", m.fitBlock(strings.Join(lines, "\n"), w-2, contentH), w, bodyH)
	return placeBlock(panel, m.width, h)
}

func (m *Model) panel(title, content string, width, height int) string {
	if width < 4 || height < 3 {
		return m.fitBlock(content, max(1, width), max(1, height))
	}
	innerW := width - 2
	innerH := height - 2
	titleLine := m.fitLine(m.st.panelTitle.Render(title), innerW)
	bodyH := max(0, innerH-1)
	body := m.fitBlock(content, innerW, bodyH)
	block := titleLine
	if body != "" {
		block += "\n" + body
	}
	return m.st.panel.Width(innerW).Height(innerH).Render(block)
}

func (m *Model) tableView(w, h int) string {
	if m.snap == nil {
		return m.st.dim.Render("No snapshot yet. Press r to scan.")
	}
	m.prepareTable(w, h)
	if !m.hasVisibleRows() {
		switch m.tab {
		case TabFindings:
			return m.st.dim.Render("No findings match the current filter.")
		case TabProcesses:
			return m.st.dim.Render("No visible processes own the collected sockets.")
		default:
			return m.st.dim.Render("No sockets match the current filter.")
		}
	}
	return m.table.View()
}

func (m *Model) inventoryTitle() string {
	title := "SOCKET INVENTORY"
	switch m.tab {
	case TabSockets:
		title = "TCP/UDP SOCKETS"
	case TabUnix:
		title = "UNIX SOCKETS"
	case TabProcesses:
		title = "PROCESSES"
	case TabFindings:
		title = "FINDINGS"
	}
	total := 0
	shown := 0
	if m.snap != nil {
		switch m.tab {
		case TabProcesses:
			total = len(m.snap.Processes)
		case TabFindings:
			total = len(m.snap.Findings)
		default:
			total = len(m.snap.Sockets)
		}
	}
	switch m.tab {
	case TabProcesses:
		shown = len(m.processRows)
	case TabFindings:
		shown = len(m.findingRows)
	default:
		shown = len(m.socketRows)
	}
	return fmt.Sprintf("%s  %d/%d", title, shown, total)
}

func (m *Model) detailTitle() string {
	switch m.tab {
	case TabProcesses:
		return "PROCESS"
	case TabFindings:
		return "FINDING"
	default:
		return "SELECTED SOCKET"
	}
}

func (m *Model) socketSummary() string {
	if m.snap == nil {
		return "No snapshot."
	}
	st := m.snap.Stats
	lines := []string{
		row("Total sockets", st.TotalSockets),
		row("TCP", st.TCP),
		row("UDP", st.UDP),
		row("Unix", st.Unix),
		row("Listeners", st.Listeners),
		row("Unknown owners", st.UnresolvedOwners),
	}
	return strings.Join(lines, "\n")
}

func (m *Model) tcpSummary() string {
	if m.snap == nil {
		return "No snapshot."
	}
	states := m.snap.Stats.TCPStates
	listen := states["LISTEN"]
	est := states["ESTABLISHED"]
	tw := states["TIME_WAIT"]
	other := 0
	for name, n := range states {
		if name != "LISTEN" && name != "ESTABLISHED" && name != "TIME_WAIT" {
			other += n
		}
	}
	return strings.Join([]string{
		row("LISTEN", listen),
		row("ESTABLISHED", est),
		row("TIME_WAIT", tw),
		row("Other", other),
	}, "\n")
}

func (m *Model) findingsSummary() string {
	if m.snap == nil {
		return "No snapshot."
	}
	counts := m.snap.Stats.Severities
	lines := []string{
		row("HIGH", counts["HIGH"]),
		row("MEDIUM", counts["MEDIUM"]),
		row("LOW", counts["LOW"]),
		row("INFO", counts["INFO"]),
	}
	top := 0
	for _, f := range m.snap.Findings {
		if top >= 3 {
			break
		}
		lines = append(lines, m.st.dim.Render(fmt.Sprintf("%s %s", f.Severity, f.RuleID)))
		top++
	}
	if len(m.snap.Findings) == 0 {
		lines = append(lines, m.st.dim.Render("No findings."))
	}
	return strings.Join(lines, "\n")
}

func row(label string, n int) string {
	return fmt.Sprintf("%-18s %6d", label, n)
}

func shortNetNS(ns string) string {
	if ns == "" {
		return "unknown"
	}
	if i := strings.Index(ns, "net:["); i >= 0 {
		return ns[i:]
	}
	return ns
}

func (m *Model) fitLine(s string, width int) string {
	if width <= 0 {
		return ""
	}
	return ansi.Truncate(s, width, "…")
}

func (m *Model) fitBlock(s string, width, height int) string {
	if width <= 0 || height <= 0 {
		return ""
	}
	lines := strings.Split(s, "\n")
	if len(lines) > height {
		lines = lines[:height]
	}
	for i, line := range lines {
		lines[i] = ansi.Truncate(line, width, "…")
	}
	for len(lines) < height {
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}

func placeBlock(block string, width, height int) string {
	bw := lipgloss.Width(block)
	bh := lipgloss.Height(block)
	left := max(0, (width-bw)/2)
	top := max(0, (height-bh)/2)
	lines := strings.Split(block, "\n")
	pad := strings.Repeat(" ", left)
	for i := range lines {
		lines[i] = pad + lines[i]
	}
	prefix := strings.Repeat("\n", top)
	return prefix + strings.Join(lines, "\n")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
