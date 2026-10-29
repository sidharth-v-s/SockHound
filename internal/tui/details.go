package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/zoro/sockhound/internal/analysis"
	"github.com/zoro/sockhound/internal/model"
)

func (m *Model) detailLines() []string {
	switch m.tab {
	case TabFindings:
		if f, ok := m.selectedFinding(); ok {
			return m.findingDetailLines(f)
		}
		return []string{m.st.dim.Render("No finding selected.")}
	case TabProcesses:
		if p, ok := m.selectedProcess(); ok {
			return m.processDetailLines(p)
		}
		return []string{m.st.dim.Render("No process selected.")}
	default:
		if s, ok := m.selectedSocket(); ok {
			return m.socketDetailLines(s)
		}
		return []string{m.st.dim.Render("No socket selected.")}
	}
}

func (m *Model) compactSelection() string {
	return strings.Join(m.detailLines(), "\n")
}

func (m *Model) section(title string) string {
	return m.st.accent.Render(title)
}

func (m *Model) field(label, value string) string {
	if value == "" {
		value = "-"
	}
	return fmt.Sprintf("  %-20s %s", label+":", cleanCell(value))
}

func (m *Model) socketDetailLines(s model.Socket) []string {
	var lines []string
	lines = append(lines,
		m.section("SOCKET"),
		m.field("Protocol", string(s.Protocol)),
		m.field("Family", string(s.Family)),
		m.field("Local", s.Endpoint()),
		m.field("Remote", orDash(s.RemoteEndpoint())),
		m.field("State", orDash(s.State)),
		m.field("Bind scope", string(s.BindScope)),
		m.field("Listening", yesNo(s.IsListening)),
	)
	if s.Inode != nil {
		lines = append(lines, m.field("Inode", strconv.FormatUint(*s.Inode, 10)))
	} else {
		lines = append(lines, m.field("Inode", "-"))
	}
	if s.SocketUID != nil {
		lines = append(lines, m.field("Socket UID", strconv.Itoa(*s.SocketUID)))
	}
	if s.RawLocal != "" {
		lines = append(lines, m.field("Raw local", s.RawLocal))
	}
	if s.RawRemote != "" && s.RawRemote != "00000000:0000" {
		lines = append(lines, m.field("Raw remote", s.RawRemote))
	}

	lines = append(lines, "", m.section("OWNER"))
	if len(s.OwnerPIDs) == 0 {
		lines = append(lines, m.st.dim.Render("  No visible owner."))
		lines = append(lines, m.st.dim.Render("  Permissions, hidepid, process exit or namespace boundaries may hide it."))
	} else {
		lines = append(lines,
			m.field("PID(s)", joinInts(s.OwnerPIDs)),
			m.field("Process(es)", strings.Join(s.OwnerNames, ", ")),
			m.field("User(s)", strings.Join(s.OwnerUsers, ", ")),
			m.field("UID(s)", joinInts(s.OwnerUIDs)),
		)
	}

	if s.Protocol == model.ProtocolUnix {
		lines = append(lines, "", m.section("UNIX SOCKET"))
		lines = append(lines,
			m.field("Path", orDash(s.UnixPath)),
			m.field("Type", orDash(s.UnixType)),
			m.field("Flags", orDash(s.UnixFlags)),
			m.field("Kernel state", orDash(s.UnixState)),
		)
		if s.UnixMetaAvailable != nil {
			lines = append(lines, m.field("Path metadata", yesNo(*s.UnixMetaAvailable)))
			if *s.UnixMetaAvailable {
				lines = append(lines, m.field("File mode", orDash(s.UnixMode)), m.field("File owner", orDash(s.UnixOwner)))
			} else {
				lines = append(lines, m.field("Metadata error", orDash(s.UnixMetaError)))
			}
		} else {
			lines = append(lines, m.field("Path metadata", "not applicable"))
		}
	}

	lines = append(lines, "", m.section("FINDINGS"))
	count := 0
	if m.snap != nil {
		for _, f := range m.snap.Findings {
			if f.SocketID != s.ID {
				continue
			}
			count++
			lines = append(lines, fmt.Sprintf("  [%s] %s  %s", f.Severity, f.RuleID, cleanCell(f.Summary)))
		}
	}
	if count == 0 {
		lines = append(lines, m.st.dim.Render("  No findings for this socket."))
	}
	if len(s.CollectionNotes) > 0 {
		lines = append(lines, "", m.section("COLLECTION NOTES"))
		for _, note := range s.CollectionNotes {
			lines = append(lines, "  - "+cleanCell(note))
		}
	}
	return lines
}

func (m *Model) findingDetailLines(f model.Finding) []string {
	lines := []string{
		m.section("FINDING"),
		m.field("Rule", f.RuleID),
		m.field("Name", f.RuleName),
		m.field("Severity", string(f.Severity)),
	}
	if f.SeverityOverride {
		lines = append(lines, m.st.dim.Render("  Severity was overridden by local configuration."))
	}
	lines = append(lines,
		"",
		m.section("SUMMARY"),
		"  "+cleanCell(f.Summary),
		"",
		m.section("WHY"),
	)
	lines = append(lines, wrapText(cleanCell(f.Explanation), 76, "  ")...)
	if f.Limitations != "" {
		lines = append(lines, "", m.section("LIMITATIONS"))
		lines = append(lines, wrapText(cleanCell(f.Limitations), 76, "  ")...)
	}
	if f.Remediation != "" {
		lines = append(lines, "", m.section("REVIEW GUIDANCE"))
		lines = append(lines, wrapText(cleanCell(f.Remediation), 76, "  ")...)
	}
	lines = append(lines, "", m.section("EVIDENCE"))
	ev := f.Evidence
	lines = append(lines,
		m.field("Protocol", ev.Protocol),
		m.field("Local", ev.LocalEndpoint),
		m.field("Remote", ev.RemoteEndpoint),
		m.field("State", ev.State),
		m.field("Bind scope", ev.BindScope),
	)
	if ev.Inode != nil {
		lines = append(lines, m.field("Inode", strconv.FormatUint(*ev.Inode, 10)))
	} else {
		lines = append(lines, m.field("Inode", "-"))
	}
	if ev.PID != nil {
		lines = append(lines, m.field("PID", strconv.Itoa(*ev.PID)))
	} else {
		lines = append(lines, m.field("PID", "-"))
	}
	lines = append(lines,
		m.field("Process", ev.Process),
		m.field("User", ev.User),
	)
	if ev.Detail != "" {
		lines = append(lines, m.field("Detail", ev.Detail))
	}
	return lines
}

func (m *Model) processDetailLines(p model.Process) []string {
	lines := []string{
		m.section("PROCESS"),
		m.field("PID", strconv.Itoa(p.PID)),
		m.field("Name", p.Name),
	}
	if p.UID != nil {
		lines = append(lines, m.field("UID", strconv.Itoa(*p.UID)))
	} else {
		lines = append(lines, m.field("UID", "-"))
	}
	lines = append(lines,
		m.field("User", p.User),
		m.field("Command line", orDash(p.Cmdline)),
		m.field("Visible sockets", strconv.Itoa(p.Sockets)),
		m.field("TCP listeners", strconv.Itoa(p.Listeners)),
		"",
		m.section("SOCKETS"),
	)
	if len(p.SocketIDs) == 0 {
		lines = append(lines, m.st.dim.Render("  No visible sockets."))
	}
	if m.snap != nil {
		for _, id := range p.SocketIDs {
			for _, s := range m.snap.Sockets {
				if s.ID != id {
					continue
				}
				subject := s.Endpoint()
				if s.Protocol == model.ProtocolUnix && s.UnixPath == "" {
					subject = "(unnamed unix socket)"
				}
				lines = append(lines, fmt.Sprintf("  %-6s %-32s %s", s.Protocol, cleanCell(subject), cleanCell(s.State)))
				break
			}
		}
	}
	lines = append(lines, "", m.st.dim.Render("Command-line arguments are redacted unless reveal_cmdline is enabled in config."))
	return lines
}

func (m *Model) helpLines() []string {
	var lines []string
	addSection := func(title string) {
		if len(lines) > 0 {
			lines = append(lines, "")
		}
		lines = append(lines, m.st.accent.Render(title))
	}
	addKey := func(k, desc string) {
		lines = append(lines, fmt.Sprintf("  %-12s %s", k, m.st.dim.Render(desc)))
	}
	addSection("TABS")
	addKey("1", "Dashboard: summary, inventory and selected socket")
	addKey("2", "TCP/UDP sockets")
	addKey("3", "Unix-domain sockets")
	addKey("4", "Processes with visible sockets")
	addKey("5", "Rule-based findings")
	addKey("?", "Toggle this help")
	addSection("NAVIGATION")
	addKey("↑/k, ↓/j", "Move selection")
	addKey("PgUp/PgDn", "Move by page")
	addKey("g / G", "Jump to top / bottom")
	addKey("enter", "Open detail view for the selected row")
	addKey("esc", "Close detail, or clear the active filter")
	addKey("q / ctrl+c", "Quit cleanly")
	addSection("FILTERS AND SORTING")
	addKey("/", "Edit the live filter (terms are ANDed)")
	addKey("s", "Cycle sort order for the current tab")
	addKey("f", "Cycle owner filter, or severity filter on Findings")
	lines = append(lines, m.st.dim.Render("  Query examples: tcp  ·  listen  ·  pid:123  ·  port:8080"))
	lines = append(lines, m.st.dim.Render("                  addr:127.0.0.1  ·  proc:nginx  ·  owner:unknown  ·  sev:INFO"))
	addSection("ACTIONS")
	addKey("r", "Refresh the snapshot")
	addKey("e", "Export the current snapshot as JSON")
	if m.refreshInterval > 0 {
		lines = append(lines, m.st.dim.Render("  Auto-refresh every "+m.refreshInterval.String()))
	} else {
		lines = append(lines, m.st.dim.Render("  Auto-refresh disabled; set --refresh-interval or refresh_interval"))
	}
	addSection("DATA NOTES")
	lines = append(lines, m.st.dim.Render("  • The snapshot covers the current network namespace, not every container namespace."))
	lines = append(lines, m.st.dim.Render("  • Root is not required. Inaccessible owners stay visible as unknown."))
	lines = append(lines, m.st.dim.Render("  • A wildcard bind does not prove internet reachability; SockHound does not test it."))
	lines = append(lines, m.st.dim.Render("  • JSON exports may contain process names, users, endpoints and socket paths."))
	addSection("RULES")
	for _, rule := range analysis.Catalog {
		lines = append(lines, fmt.Sprintf("  %-12s %-6s %s", rule.ID, rule.Severity, rule.Name))
	}
	return lines
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func joinInts(v []int) string {
	if len(v) == 0 {
		return ""
	}
	parts := make([]string, len(v))
	for i, n := range v {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ", ")
}

func wrapText(s string, width int, indent string) []string {
	if width < 10 {
		width = 10
	}
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{indent}
	}
	var lines []string
	current := indent
	for _, word := range words {
		if len(current)+len(word)+1 > width && strings.TrimSpace(current) != "" {
			lines = append(lines, current)
			current = indent + word
			continue
		}
		if strings.TrimSpace(current) == "" {
			current = indent + word
		} else {
			current += " " + word
		}
	}
	lines = append(lines, current)
	return lines
}
