// Package output renders snapshots as non-interactive text or versioned JSON.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/zoro/sockhound/internal/model"
)

// WriteJSON writes an indented, versioned snapshot to w.
func WriteJSON(w io.Writer, snap model.Snapshot) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(snap)
}

// MarshalJSON returns the same representation as WriteJSON.
func MarshalJSON(snap model.Snapshot) ([]byte, error) {
	return json.MarshalIndent(snap, "", "  ")
}

// WriteFile exports a snapshot. It refuses to overwrite an existing file
// unless force is true.
func WriteFile(path string, snap model.Snapshot, force bool) error {
	if path == "" {
		return fmt.Errorf("export path is empty")
	}
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists (use --force to overwrite)", path)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("checking %s: %w", path, err)
		}
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".sockhound-*.json")
	if err != nil {
		return fmt.Errorf("creating export file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(snap); err != nil {
		tmp.Close()
		return fmt.Errorf("writing export: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing export: %w", err)
	}
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists (use --force to overwrite)", path)
		}
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("installing export: %w", err)
	}
	return nil
}

// WriteText renders a human-readable scan summary.
func WriteText(w io.Writer, snap model.Snapshot) error {
	var b strings.Builder
	fmt.Fprintf(&b, "SockHound %s — snapshot %s (%dms)\n",
		snap.ToolVersion, snap.CollectedAt.Format("2006-01-02 15:04:05"), snap.DurationMS)
	fmt.Fprintf(&b, "Scope: %s\n", snap.Scope)
	if snap.Visibility.Partial {
		fmt.Fprintf(&b, "Visibility: partial (%d warning(s))\n", len(snap.Visibility.Warnings))
	} else {
		b.WriteString("Visibility: complete for accessible procfs sources\n")
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "Sockets: %d total | TCP %d | UDP %d | Unix %d | listeners %d | unresolved owners %d\n",
		snap.Stats.TotalSockets, snap.Stats.TCP, snap.Stats.UDP, snap.Stats.Unix,
		snap.Stats.Listeners, snap.Stats.UnresolvedOwners)
	b.WriteString("\n")

	headers := []string{"PROTO", "LOCAL", "REMOTE", "STATE", "BIND", "PID", "PROCESS", "INODE"}
	rows := make([][]string, 0, len(snap.Sockets))
	for _, s := range snap.Sockets {
		pid := "-"
		if len(s.OwnerPIDs) > 0 {
			pid = strconv.Itoa(s.OwnerPIDs[0])
		}
		proc := strings.Join(s.OwnerNames, ",")
		inode := "-"
		if s.Inode != nil {
			inode = strconv.FormatUint(*s.Inode, 10)
		}
		rows = append(rows, []string{
			string(s.Protocol),
			s.Endpoint(),
			orDash(s.RemoteEndpoint()),
			orDash(s.State),
			string(s.BindScope),
			pid,
			orDash(proc),
			inode,
		})
	}
	writeTable(&b, headers, rows)

	severity := []string{"HIGH", "MEDIUM", "LOW", "INFO"}
	b.WriteString("\nFindings: ")
	for i, sev := range severity {
		if i > 0 {
			b.WriteString(" | ")
		}
		fmt.Fprintf(&b, "%s %d", sev, snap.Stats.Severities[sev])
	}
	b.WriteString("\n")
	const maxFindings = 12
	for i, f := range snap.Findings {
		if i >= maxFindings {
			fmt.Fprintf(&b, "  … %d more finding(s); use --json for the full report\n", len(snap.Findings)-maxFindings)
			break
		}
		fmt.Fprintf(&b, "  %-6s %-12s %s\n", f.Severity, f.RuleID, sanitize(f.Summary))
	}
	if len(snap.Findings) == 0 {
		b.WriteString("  No findings.\n")
	}

	if len(snap.Visibility.Warnings) > 0 {
		b.WriteString("\nCollection warnings:\n")
		const maxWarnings = 20
		for i, warning := range snap.Visibility.Warnings {
			if i >= maxWarnings {
				fmt.Fprintf(&b, "  … %d more warning(s)\n", len(snap.Visibility.Warnings)-maxWarnings)
				break
			}
			fmt.Fprintf(&b, "  - %s\n", sanitize(warning))
		}
	}
	b.WriteString("\nNote: JSON exports may contain process names, users, endpoints and socket paths.\n")
	b.WriteString("      Review the output before sharing it.\n")
	_, err := io.WriteString(w, b.String())
	return err
}

func writeTable(w io.Writer, headers []string, rows [][]string) {
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i >= len(widths) {
				continue
			}
			if n := len([]rune(cell)); n > widths[i] {
				widths[i] = n
			}
		}
	}
	// Bound wide columns so long IPv6 endpoints and Unix paths stay readable
	// in ordinary terminals.
	limits := []int{5, 30, 30, 14, 14, 8, 22, 12}
	for i := range widths {
		if i < len(limits) && widths[i] > limits[i] {
			widths[i] = limits[i]
		}
	}
	writeRow := func(cells []string) {
		var b strings.Builder
		for i, cell := range cells {
			if i >= len(widths) {
				break
			}
			cell = truncate(sanitize(cell), widths[i])
			b.WriteString(cell)
			if pad := widths[i] - len([]rune(cell)); pad > 0 {
				b.WriteString(strings.Repeat(" ", pad))
			}
			if i < len(cells)-1 {
				b.WriteString("  ")
			}
		}
		fmt.Fprintln(w, strings.TrimRight(b.String(), " "))
	}
	writeRow(headers)
	for _, row := range rows {
		writeRow(row)
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) {
			return '�'
		}
		return r
	}, s)
}

func truncate(s string, width int) string {
	if width <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= width {
		return s
	}
	if width == 1 {
		return "…"
	}
	return string(r[:width-1]) + "…"
}
