package tui

import "charm.land/bubbles/v2/key"

type keyMap struct {
	Tab1     key.Binding
	Tab2     key.Binding
	Tab3     key.Binding
	Tab4     key.Binding
	Tab5     key.Binding
	Up       key.Binding
	Down     key.Binding
	PageUp   key.Binding
	PageDown key.Binding
	Enter    key.Binding
	Esc      key.Binding
	Filter   key.Binding
	Sort     key.Binding
	Refresh  key.Binding
	Export   key.Binding
	Cycle    key.Binding
	Help     key.Binding
	Quit     key.Binding
	Top      key.Binding
	Bottom   key.Binding
}

func defaultKeyMap() keyMap {
	return keyMap{
		Tab1:     key.NewBinding(key.WithKeys("1"), key.WithHelp("1", "dashboard")),
		Tab2:     key.NewBinding(key.WithKeys("2"), key.WithHelp("2", "TCP/UDP")),
		Tab3:     key.NewBinding(key.WithKeys("3"), key.WithHelp("3", "Unix")),
		Tab4:     key.NewBinding(key.WithKeys("4"), key.WithHelp("4", "processes")),
		Tab5:     key.NewBinding(key.WithKeys("5"), key.WithHelp("5", "findings")),
		Up:       key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
		Down:     key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
		PageUp:   key.NewBinding(key.WithKeys("pgup", "b"), key.WithHelp("pgup", "page up")),
		PageDown: key.NewBinding(key.WithKeys("pgdown", "f"), key.WithHelp("pgdn", "page down")),
		Enter:    key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "details")),
		Esc:      key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "back/clear")),
		Filter:   key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "filter")),
		Sort:     key.NewBinding(key.WithKeys("s"), key.WithHelp("s", "sort")),
		Refresh:  key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "refresh")),
		Export:   key.NewBinding(key.WithKeys("e"), key.WithHelp("e", "export JSON")),
		Cycle:    key.NewBinding(key.WithKeys("f"), key.WithHelp("f", "cycle filter")),
		Help:     key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
		Quit:     key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
		Top:      key.NewBinding(key.WithKeys("g", "home"), key.WithHelp("g", "top")),
		Bottom:   key.NewBinding(key.WithKeys("G", "end"), key.WithHelp("G", "bottom")),
	}
}

func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Up, k.Down, k.Enter, k.Filter, k.Sort, k.Refresh, k.Export, k.Help, k.Quit}
}

func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Tab1, k.Tab2, k.Tab3, k.Tab4, k.Tab5},
		{k.Up, k.Down, k.PageUp, k.PageDown, k.Top, k.Bottom},
		{k.Enter, k.Esc, k.Filter, k.Sort, k.Cycle},
		{k.Refresh, k.Export, k.Help, k.Quit},
	}
}

// shortHelp adapts a list of bindings to the help.Model interface.
type shortHelp []key.Binding

func (s shortHelp) ShortHelp() []key.Binding { return []key.Binding(s) }
func (s shortHelp) FullHelp() [][]key.Binding {
	return [][]key.Binding{[]key.Binding(s)}
}
