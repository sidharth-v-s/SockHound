package tui

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"charm.land/bubbles/v2/table"
	"github.com/zoro/sockhound/internal/model"
)

type colSpec struct {
	title  string
	weight int
	min    int
}

func (m *Model) rebuild() {
	selSocket := ""
	if s, ok := m.selectedSocket(); ok {
		selSocket = s.ID
	}
	selPID := 0
	if p, ok := m.selectedProcess(); ok {
		selPID = p.PID
	}
	selFinding := ""
	if f, ok := m.selectedFinding(); ok {
		selFinding = findingKey(f)
	}

	m.socketRows = nil
	m.processRows = nil
	m.findingRows = nil
	if m.snap == nil {
		m.table.SetRows(nil)
		return
	}

	findingsBySocket := make(map[string][]model.Finding)
	for _, f := range m.snap.Findings {
		if f.SocketID != "" {
			findingsBySocket[f.SocketID] = append(findingsBySocket[f.SocketID], f)
		}
	}

	switch m.tab {
	case TabDashboard, TabSockets, TabUnix:
		for _, s := range m.snap.Sockets {
			if m.tab == TabSockets && !s.Protocol.IsTCP() && !s.Protocol.IsUDP() {
				continue
			}
			if m.tab == TabUnix && s.Protocol != model.ProtocolUnix {
				continue
			}
			if !m.query.MatchSocket(s, findingsBySocket[s.ID]) {
				continue
			}
			switch m.ownerFilter {
			case 1:
				if len(s.OwnerPIDs) > 0 {
					continue
				}
			case 2:
				if len(s.OwnerPIDs) == 0 {
					continue
				}
			}
			if m.severityFilter != "" && !hasSeverity(findingsBySocket[s.ID], m.severityFilter) {
				continue
			}
			m.socketRows = append(m.socketRows, s)
		}
		m.sortSockets()
		rows := make([]table.Row, 0, len(m.socketRows))
		for _, s := range m.socketRows {
			rows = append(rows, m.socketRow(s))
		}
		m.setRows(rows, findSocketIndex(m.socketRows, selSocket))

	case TabProcesses:
		for _, p := range m.snap.Processes {
			if !m.query.MatchProcess(p) {
				continue
			}
			m.processRows = append(m.processRows, p)
		}
		m.sortProcesses()
		rows := make([]table.Row, 0, len(m.processRows))
		for _, p := range m.processRows {
			rows = append(rows, m.processRow(p))
		}
		m.setRows(rows, findProcessIndex(m.processRows, selPID))

	case TabFindings:
		for _, f := range m.snap.Findings {
			if !m.query.MatchFinding(f) {
				continue
			}
			if m.severityFilter != "" && f.Severity != m.severityFilter {
				continue
			}
			m.findingRows = append(m.findingRows, f)
		}
		m.sortFindings()
		rows := make([]table.Row, 0, len(m.findingRows))
		for _, f := range m.findingRows {
			rows = append(rows, m.findingRow(f))
		}
		m.setRows(rows, findFindingIndex(m.findingRows, selFinding))

	default:
		m.table.SetRows(nil)
	}
}

func (m *Model) setRows(rows []table.Row, idx int) {
	m.pendingRows = rows
	m.pendingIdx = idx
	m.rowsGeneration++
	// The Bubbles table renders rows immediately and panics when the row
	// width does not match the configured columns. That happens during Init,
	// before the first WindowSizeMsg, and while switching tabs before the
	// next render refreshes the columns.
	cols := m.table.Columns()
	if len(cols) == 0 || (len(rows) > 0 && len(rows[0]) != len(cols)) {
		return
	}
	m.applyRows(rows, idx)
}

func (m *Model) applyRows(rows []table.Row, idx int) {
	m.appliedGeneration = m.rowsGeneration
	m.table.SetRows(rows)
	if len(rows) == 0 {
		m.table.SetCursor(0)
		return
	}
	if idx < 0 || idx >= len(rows) {
		idx = 0
	}
	m.table.GotoTop()
	if idx > 0 {
		m.table.MoveDown(idx)
	}
}

func (m *Model) hasVisibleRows() bool {
	switch m.tab {
	case TabProcesses:
		return len(m.processRows) > 0
	case TabFindings:
		return len(m.findingRows) > 0
	default:
		return len(m.socketRows) > 0
	}
}

func (m *Model) prepareTable(innerW, innerH int) {
	if innerW < 4 || innerH < 2 {
		return
	}
	cols := m.columnsFor(m.tab, innerW)
	if len(cols) == 0 {
		return
	}
	if m.appliedGeneration != m.rowsGeneration {
		// SetColumns re-renders existing rows, so clear stale rows first.
		m.table.SetRows(nil)
	}
	m.table.SetColumns(cols)
	m.table.SetWidth(innerW)
	m.table.SetHeight(innerH)
	if m.appliedGeneration != m.rowsGeneration {
		m.applyRows(m.pendingRows, m.pendingIdx)
	}
	// Keep the selected row visible after resizes and rebuilds.
	idx := m.table.Cursor()
	if len(m.table.Rows()) > 0 && idx >= 0 {
		m.table.GotoTop()
		if idx > 0 {
			m.table.MoveDown(idx)
		}
	}
}

func (m *Model) columnsFor(tab Tab, innerW int) []table.Column {
	var specs []colSpec
	switch tab {
	case TabDashboard:
		specs = []colSpec{
			{"PROTO", 5, 5}, {"LOCAL", 24, 12}, {"REMOTE", 20, 10},
			{"STATE", 12, 8}, {"PID", 7, 5}, {"PROCESS", 14, 8},
		}
	case TabSockets:
		specs = []colSpec{
			{"PROTO", 5, 5}, {"LOCAL", 22, 12}, {"REMOTE", 18, 10},
			{"STATE", 12, 8}, {"BIND", 10, 8}, {"PID", 6, 5}, {"PROCESS", 13, 8},
		}
	case TabUnix:
		specs = []colSpec{
			{"PATH", 30, 12}, {"TYPE", 10, 8}, {"STATE", 12, 9},
			{"PID", 6, 5}, {"PROCESS", 14, 8}, {"INODE", 10, 7},
		}
	case TabProcesses:
		specs = []colSpec{
			{"PID", 7, 5}, {"PROCESS", 20, 10}, {"USER", 14, 8},
			{"SOCKETS", 9, 7}, {"LISTENERS", 10, 8},
		}
	case TabFindings:
		specs = []colSpec{
			{"SEV", 7, 6}, {"RULE", 13, 11}, {"SUBJECT", 26, 12}, {"SUMMARY", 42, 16},
		}
	default:
		return nil
	}
	avail := innerW - 2*len(specs)
	if avail < 3*len(specs) {
		avail = 3 * len(specs)
	}
	widths := allocateWidths(avail, specs)
	cols := make([]table.Column, len(specs))
	for i, spec := range specs {
		cols[i] = table.Column{Title: spec.title, Width: widths[i]}
	}
	return cols
}

func allocateWidths(avail int, specs []colSpec) []int {
	n := len(specs)
	widths := make([]int, n)
	minTotal := 0
	for i, spec := range specs {
		widths[i] = spec.min
		minTotal += spec.min
	}
	if minTotal > avail {
		for i := range widths {
			widths[i] = max(3, avail*widths[i]/minTotal)
		}
	}
	used := 0
	for _, w := range widths {
		used += w
	}
	rem := avail - used
	if rem > 0 {
		totalWeight := 0
		for _, spec := range specs {
			totalWeight += spec.weight
		}
		assigned := 0
		for i, spec := range specs {
			add := rem * spec.weight / totalWeight
			widths[i] += add
			assigned += add
		}
		widths[n-1] += rem - assigned
	}
	for sum(widths) > avail {
		idx := 0
		for i := range widths {
			if widths[i] > widths[idx] {
				idx = i
			}
		}
		if widths[idx] <= 3 {
			break
		}
		widths[idx]--
	}
	return widths
}

func sum(v []int) int {
	t := 0
	for _, n := range v {
		t += n
	}
	return t
}

func (m *Model) socketRow(s model.Socket) table.Row {
	proto := string(s.Protocol)
	if m.tab == TabDashboard {
		return table.Row{
			cleanCell(proto),
			cleanCell(s.Endpoint()),
			cleanCell(orDash(s.RemoteEndpoint())),
			cleanCell(orDash(s.State)),
			cleanCell(pidLabel(s)),
			cleanCell(procLabel(s)),
		}
	}
	if m.tab == TabUnix {
		inode := "-"
		if s.Inode != nil {
			inode = strconv.FormatUint(*s.Inode, 10)
		}
		return table.Row{
			cleanCell(orDash(s.UnixPath)),
			cleanCell(orDash(s.UnixType)),
			cleanCell(orDash(s.State)),
			cleanCell(pidLabel(s)),
			cleanCell(procLabel(s)),
			cleanCell(inode),
		}
	}
	return table.Row{
		cleanCell(proto),
		cleanCell(s.Endpoint()),
		cleanCell(orDash(s.RemoteEndpoint())),
		cleanCell(orDash(s.State)),
		cleanCell(string(s.BindScope)),
		cleanCell(pidLabel(s)),
		cleanCell(procLabel(s)),
	}
}

func (m *Model) processRow(p model.Process) table.Row {
	return table.Row{
		strconv.Itoa(p.PID),
		cleanCell(p.Name),
		cleanCell(orDash(p.User)),
		strconv.Itoa(p.Sockets),
		strconv.Itoa(p.Listeners),
	}
}

func (m *Model) findingRow(f model.Finding) table.Row {
	subject := f.Evidence.LocalEndpoint
	if subject == "" {
		subject = "snapshot"
	}
	return table.Row{
		string(f.Severity),
		cleanCell(f.RuleID),
		cleanCell(subject),
		cleanCell(f.Summary),
	}
}

func pidLabel(s model.Socket) string {
	if len(s.OwnerPIDs) == 0 {
		return "-"
	}
	if len(s.OwnerPIDs) == 1 {
		return strconv.Itoa(s.OwnerPIDs[0])
	}
	return fmt.Sprintf("%d+%d", s.OwnerPIDs[0], len(s.OwnerPIDs)-1)
}

func procLabel(s model.Socket) string {
	if len(s.OwnerNames) == 0 {
		return "-"
	}
	return strings.Join(s.OwnerNames, ",")
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func hasSeverity(findings []model.Finding, sev model.Severity) bool {
	for _, f := range findings {
		if f.Severity == sev {
			return true
		}
	}
	return false
}

func findSocketIndex(rows []model.Socket, id string) int {
	if id == "" {
		return 0
	}
	for i, s := range rows {
		if s.ID == id {
			return i
		}
	}
	return 0
}

func findProcessIndex(rows []model.Process, pid int) int {
	if pid == 0 {
		return 0
	}
	for i, p := range rows {
		if p.PID == pid {
			return i
		}
	}
	return 0
}

func findFindingIndex(rows []model.Finding, key string) int {
	if key == "" {
		return 0
	}
	for i, f := range rows {
		if findingKey(f) == key {
			return i
		}
	}
	return 0
}

func (m *Model) sortSockets() {
	mode := m.currentSort().key
	if mode == "default" {
		return
	}
	rank := func(s model.Socket) int {
		return m.maxSeverity(s.ID).Rank()
	}
	sort.SliceStable(m.socketRows, func(i, j int) bool {
		a, b := m.socketRows[i], m.socketRows[j]
		switch mode {
		case "protocol":
			if a.Protocol != b.Protocol {
				return protocolOrder(a.Protocol) < protocolOrder(b.Protocol)
			}
		case "local":
			if a.LocalAddress != b.LocalAddress {
				return a.LocalAddress < b.LocalAddress
			}
			if portVal(a.LocalPort) != portVal(b.LocalPort) {
				return portVal(a.LocalPort) < portVal(b.LocalPort)
			}
		case "state":
			if a.State != b.State {
				return a.State < b.State
			}
		case "pid":
			if pidVal(a) != pidVal(b) {
				return pidVal(a) < pidVal(b)
			}
		case "process":
			if procVal(a) != procVal(b) {
				return procVal(a) < procVal(b)
			}
		case "severity":
			if rank(a) != rank(b) {
				return rank(a) > rank(b)
			}
		}
		return a.Endpoint() < b.Endpoint()
	})
}

func (m *Model) sortProcesses() {
	mode := m.currentSort().key
	sort.SliceStable(m.processRows, func(i, j int) bool {
		a, b := m.processRows[i], m.processRows[j]
		switch mode {
		case "name":
			return a.Name < b.Name
		case "sockets":
			if a.Sockets != b.Sockets {
				return a.Sockets > b.Sockets
			}
		case "listeners":
			if a.Listeners != b.Listeners {
				return a.Listeners > b.Listeners
			}
		}
		return a.PID < b.PID
	})
}

func (m *Model) sortFindings() {
	mode := m.currentSort().key
	sort.SliceStable(m.findingRows, func(i, j int) bool {
		a, b := m.findingRows[i], m.findingRows[j]
		switch mode {
		case "rule":
			if a.RuleID != b.RuleID {
				return a.RuleID < b.RuleID
			}
		case "socket":
			if a.SocketID != b.SocketID {
				return a.SocketID < b.SocketID
			}
		default:
			if a.Severity.Rank() != b.Severity.Rank() {
				return a.Severity.Rank() > b.Severity.Rank()
			}
			if a.RuleID != b.RuleID {
				return a.RuleID < b.RuleID
			}
		}
		return a.SocketID < b.SocketID
	})
}

func protocolOrder(p model.Protocol) int {
	switch p {
	case model.ProtocolTCP:
		return 0
	case model.ProtocolTCP6:
		return 1
	case model.ProtocolUDP:
		return 2
	case model.ProtocolUDP6:
		return 3
	case model.ProtocolUnix:
		return 4
	default:
		return 5
	}
}

func portVal(p *int) int {
	if p == nil {
		return -1
	}
	return *p
}

func pidVal(s model.Socket) int {
	if len(s.OwnerPIDs) == 0 {
		return int(^uint(0) >> 1)
	}
	return s.OwnerPIDs[0]
}

func procVal(s model.Socket) string {
	if len(s.OwnerNames) == 0 {
		return "\uffff"
	}
	return s.OwnerNames[0]
}
