package tui

import (
	"charm.land/bubbles/v2/help"
	"charm.land/lipgloss/v2"
)

type styles struct {
	panel       lipgloss.Style
	panelTitle  lipgloss.Style
	text        lipgloss.Style
	dim         lipgloss.Style
	accent      lipgloss.Style
	activeTab   lipgloss.Style
	inactiveTab lipgloss.Style
	selected    lipgloss.Style
	severity    map[string]lipgloss.Style
	errorText   lipgloss.Style
	successText lipgloss.Style
	help        help.Model
	tableHeader lipgloss.Style
	tableCell   lipgloss.Style
}

func newStyles(noColor bool) styles {
	s := styles{
		severity: map[string]lipgloss.Style{},
	}
	if noColor {
		s.panel = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("240"))
		s.panelTitle = lipgloss.NewStyle().Bold(true)
		s.text = lipgloss.NewStyle()
		s.dim = lipgloss.NewStyle()
		s.accent = lipgloss.NewStyle().Bold(true)
		s.activeTab = lipgloss.NewStyle().Bold(true).Reverse(true)
		s.inactiveTab = lipgloss.NewStyle()
		s.selected = lipgloss.NewStyle().Reverse(true)
		s.errorText = lipgloss.NewStyle().Bold(true)
		s.successText = lipgloss.NewStyle().Bold(true)
		for _, sev := range []string{"HIGH", "MEDIUM", "LOW", "INFO"} {
			s.severity[sev] = lipgloss.NewStyle().Bold(true)
		}
	} else {
		border := lipgloss.Color("#4a4a4a")
		s.panel = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(border)
		s.panelTitle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#c9d1d9"))
		s.text = lipgloss.NewStyle().Foreground(lipgloss.Color("#c9d1d9"))
		s.dim = lipgloss.NewStyle().Foreground(lipgloss.Color("#7d8590"))
		s.accent = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#79c0ff"))
		s.activeTab = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#0d1117")).Background(lipgloss.Color("#79c0ff"))
		s.inactiveTab = lipgloss.NewStyle().Foreground(lipgloss.Color("#8b949e"))
		s.selected = lipgloss.NewStyle().Foreground(lipgloss.Color("#f0f6fc")).Background(lipgloss.Color("#264f78"))
		s.errorText = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#ff7b72"))
		s.successText = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#7ee787"))
		s.severity["HIGH"] = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#ff7b72"))
		s.severity["MEDIUM"] = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#d29922"))
		s.severity["LOW"] = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#79c0ff"))
		s.severity["INFO"] = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#8b949e"))
	}
	s.help = help.New()
	if noColor {
		s.help.Styles = help.DefaultStyles(false)
	} else {
		s.help.Styles = help.DefaultDarkStyles()
		s.help.Styles.ShortKey = lipgloss.NewStyle().Foreground(lipgloss.Color("#79c0ff"))
		s.help.Styles.ShortDesc = lipgloss.NewStyle().Foreground(lipgloss.Color("#8b949e"))
		s.help.Styles.ShortSeparator = lipgloss.NewStyle().Foreground(lipgloss.Color("#484f58"))
	}
	s.tableHeader = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#8b949e")).Padding(0, 1)
	s.tableCell = lipgloss.NewStyle().Padding(0, 1)
	return s
}
