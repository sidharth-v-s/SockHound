// Package app selects between the interactive TUI and one-shot scan modes.
package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/zoro/sockhound/internal/analysis"
	"github.com/zoro/sockhound/internal/config"
	"github.com/zoro/sockhound/internal/filter"
	"github.com/zoro/sockhound/internal/model"
	"github.com/zoro/sockhound/internal/output"
	"github.com/zoro/sockhound/internal/scanner"
	"github.com/zoro/sockhound/internal/tui"
	"github.com/zoro/sockhound/internal/version"
)

// Exit codes documented in the README.
const (
	ExitOK      = 0
	ExitUsage   = 1
	ExitCollect = 2
	ExitPartial = 3
)

// IO lets tests replace terminal and scan dependencies.
type IO struct {
	In         io.Reader
	Out        io.Writer
	Err        io.Writer
	IsTerminal func() bool
	Scan       func(context.Context, scanner.Options) (model.Snapshot, error)
	RunTUI     func(tui.Options) error
}

// DefaultIO returns the production dependencies.
func DefaultIO() IO {
	return IO{
		In:         os.Stdin,
		Out:        os.Stdout,
		Err:        os.Stderr,
		IsTerminal: stdinStdoutTerminal,
		Scan:       scanner.Run,
		RunTUI:     runTUIProgram,
	}
}

// Run dispatches the CLI. It returns a process exit code.
func Run(args []string, ios IO) int {
	ios = withDefaults(ios)
	if len(args) == 0 {
		if !ios.IsTerminal() {
			fmt.Fprintln(ios.Err, "sockhound: stdin/stdout are not a terminal.")
			fmt.Fprintln(ios.Err, "Use `sockhound scan` for a one-shot summary or `sockhound scan --json` for machine-readable output.")
			return ExitUsage
		}
		return runTUI("", false, false, "", ios)
	}

	switch args[0] {
	case "scan":
		return runScan(args[1:], ios)
	case "tui":
		return runTUIArgs(args[1:], ios)
	case "version", "--version", "-v":
		fmt.Fprintf(ios.Out, "SockHound %s\n", version.Version)
		return ExitOK
	case "help", "--help", "-h":
		printUsage(ios.Out)
		return ExitOK
	default:
		if strings.HasPrefix(args[0], "-") {
			return runTUIArgs(args, ios)
		}
		fmt.Fprintf(ios.Err, "sockhound: unknown command %q\n\n", args[0])
		printUsage(ios.Err)
		return ExitUsage
	}
}

func withDefaults(ios IO) IO {
	if ios.In == nil {
		ios.In = os.Stdin
	}
	if ios.Out == nil {
		ios.Out = os.Stdout
	}
	if ios.Err == nil {
		ios.Err = os.Stderr
	}
	if ios.IsTerminal == nil {
		ios.IsTerminal = stdinStdoutTerminal
	}
	if ios.Scan == nil {
		ios.Scan = scanner.Run
	}
	if ios.RunTUI == nil {
		ios.RunTUI = runTUIProgram
	}
	return ios
}

func stdinStdoutTerminal() bool {
	return isCharDevice(os.Stdin) && isCharDevice(os.Stdout)
}

func isCharDevice(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func runTUIArgs(args []string, ios IO) int {
	fs := flag.NewFlagSet("tui", flag.ContinueOnError)
	fs.SetOutput(ios.Err)
	fs.Usage = func() { printTUIUsage(ios.Err) }
	configPath := fs.String("config", "", "path to a JSON configuration file")
	noColor := fs.Bool("no-color", false, "disable colors")
	debug := fs.Bool("debug", false, "write diagnostics to stderr")
	procRoot := fs.String("proc-root", "/proc", "procfs mount point (advanced/testing)")
	noOwners := fs.Bool("no-owner-resolution", false, "skip process ownership resolution")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(ios.Err, "sockhound tui: unexpected argument %q\n", fs.Arg(0))
		return ExitUsage
	}
	if !ios.IsTerminal() {
		fmt.Fprintln(ios.Err, "sockhound tui: stdin/stdout are not a terminal; use `sockhound scan` instead.")
		return ExitUsage
	}
	return runTUI(*configPath, *noColor, *debug, *procRoot, ios, *noOwners)
}

func runTUI(configPath string, noColor, debug bool, procRoot string, ios IO, noOwners ...bool) int {
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(ios.Err, "sockhound: %v\n", err)
		return ExitUsage
	}
	if procRoot == "" {
		procRoot = "/proc"
	}
	opts := scanner.DefaultOptions()
	opts.ProcRoot = procRoot
	opts.Version = version.Version
	opts.RevealCmdline = cfg.RevealCmdline
	opts.Analysis = analysisOptions(cfg)
	if len(noOwners) > 0 && noOwners[0] {
		opts.ResolveOwners = false
	}
	runOpts := tui.Options{
		Version: version.Version,
		NoColor: noColor,
		Scan: func(ctx context.Context) (model.Snapshot, error) {
			return ios.Scan(ctx, opts)
		},
	}
	if err := ios.RunTUI(runOpts); err != nil {
		fmt.Fprintf(ios.Err, "sockhound: %v\n", err)
		return ExitCollect
	}
	return ExitOK
}

func runScan(args []string, ios IO) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(ios.Err)
	fs.Usage = func() { printScanUsage(ios.Err) }

	jsonOut := fs.Bool("json", false, "write a versioned JSON snapshot to stdout")
	outputPath := fs.String("output", "", "write the JSON snapshot to a file")
	force := fs.Bool("force", false, "overwrite an existing --output file")
	listening := fs.Bool("listening", false, "only TCP listeners")
	protocol := fs.String("protocol", "", "tcp, tcp6, udp, udp6, unix or all")
	pid := fs.Int("pid", 0, "only sockets owned by this PID")
	port := fs.Int("port", 0, "only sockets using this local or remote port")
	address := fs.String("address", "", "only sockets whose address or path contains this text")
	processName := fs.String("process", "", "only sockets whose owner process name contains this text")
	state := fs.String("state", "", "only this normalized state (for example LISTEN)")
	owner := fs.String("owner", "", "known or unknown owner visibility")
	severity := fs.String("severity", "", "only sockets/findings with this severity")
	filterExpr := fs.String("filter", "", "composable filter expression (ANDed terms)")
	configPath := fs.String("config", "", "path to a JSON configuration file")
	debug := fs.Bool("debug", false, "write diagnostics to stderr")
	_ = fs.Bool("no-color", false, "accepted for compatibility; text output is already plain")
	procRoot := fs.String("proc-root", "/proc", "procfs mount point (advanced/testing)")
	noOwners := fs.Bool("no-owner-resolution", false, "skip process ownership resolution")

	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(ios.Err, "sockhound scan: unexpected argument %q\n", fs.Arg(0))
		return ExitUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(ios.Err, "sockhound: %v\n", err)
		return ExitUsage
	}
	if *pid < 0 || *port < 0 || *port > 65535 {
		fmt.Fprintln(ios.Err, "sockhound scan: --pid must be >= 0 and --port must be 0-65535")
		return ExitUsage
	}

	q := filter.Parse(*filterExpr)
	if q.Err != "" {
		fmt.Fprintf(ios.Err, "sockhound scan: invalid filter: %s\n", q.Err)
		return ExitUsage
	}
	if *listening {
		q.Terms = append(q.Terms, filter.Term{Kind: "listen"})
	}
	if *protocol != "" {
		switch strings.ToLower(*protocol) {
		case "all":
		case "tcp", "tcp6", "udp", "udp6", "unix":
			q.Terms = append(q.Terms, filter.Term{Kind: "protocol", Value: strings.ToLower(*protocol)})
		default:
			fmt.Fprintf(ios.Err, "sockhound scan: invalid --protocol %q\n", *protocol)
			return ExitUsage
		}
	}
	if *pid > 0 {
		q.Terms = append(q.Terms, filter.Term{Kind: "pid", Int: *pid})
	}
	if *port > 0 {
		q.Terms = append(q.Terms, filter.Term{Kind: "port", Int: *port})
	}
	if *address != "" {
		q.Terms = append(q.Terms, filter.Term{Kind: "addr", Value: *address})
	}
	if *processName != "" {
		q.Terms = append(q.Terms, filter.Term{Kind: "proc", Value: *processName})
	}
	if *state != "" {
		q.Terms = append(q.Terms, filter.Term{Kind: "state", Value: strings.ToUpper(*state)})
	}
	if *owner != "" {
		switch strings.ToLower(*owner) {
		case "known", "unknown":
			q.Terms = append(q.Terms, filter.Term{Kind: "owner", Value: strings.ToLower(*owner)})
		default:
			fmt.Fprintf(ios.Err, "sockhound scan: --owner must be known or unknown\n")
			return ExitUsage
		}
	}
	if *severity != "" {
		sev := model.Severity(strings.ToUpper(*severity))
		switch sev {
		case model.SeverityInfo, model.SeverityLow, model.SeverityMedium, model.SeverityHigh:
			q.Terms = append(q.Terms, filter.Term{Kind: "sev", Value: string(sev)})
		default:
			fmt.Fprintf(ios.Err, "sockhound scan: invalid --severity %q\n", *severity)
			return ExitUsage
		}
	}

	if *outputPath != "" && *jsonOut {
		// fine: write the file and keep stdout empty for scripts
	}
	if *outputPath != "" {
		*jsonOut = true
	}

	opts := scanner.DefaultOptions()
	opts.ProcRoot = *procRoot
	opts.Version = version.Version
	opts.RevealCmdline = cfg.RevealCmdline
	opts.Analysis = analysisOptions(cfg)
	if *noOwners {
		opts.ResolveOwners = false
	}

	snap, err := ios.Scan(context.Background(), opts)
	if err != nil {
		fmt.Fprintf(ios.Err, "sockhound: collection failed: %v\n", err)
		return ExitCollect
	}
	if len(q.Terms) > 0 {
		applyQuery(&snap, q)
	}
	if *debug {
		writeDiagnostics(ios.Err, snap)
	}

	if *jsonOut {
		if *outputPath != "" {
			if err := output.WriteFile(*outputPath, snap, *force); err != nil {
				fmt.Fprintf(ios.Err, "sockhound: %v\n", err)
				return ExitCollect
			}
			if *debug {
				fmt.Fprintf(ios.Err, "wrote %s\n", *outputPath)
			}
		} else {
			if err := output.WriteJSON(ios.Out, snap); err != nil {
				fmt.Fprintf(ios.Err, "sockhound: writing JSON: %v\n", err)
				return ExitCollect
			}
		}
	} else {
		if err := output.WriteText(ios.Out, snap); err != nil {
			fmt.Fprintf(ios.Err, "sockhound: writing text: %v\n", err)
			return ExitCollect
		}
	}

	if snap.Visibility.Partial {
		return ExitPartial
	}
	return ExitOK
}

func analysisOptions(cfg config.Config) analysis.Options {
	opts := analysis.DefaultOptions()
	opts.ReviewPorts = cfg.ReviewPorts
	for _, rule := range analysis.Catalog {
		rc := analysis.RuleConfig{Enabled: cfg.RuleEnabled(rule.ID)}
		if sev, ok := cfg.RuleSeverity(rule.ID); ok {
			rc.Severity = sev
			rc.HasSeverity = true
		}
		opts.Rules[rule.ID] = rc
	}
	return opts
}

func applyQuery(snap *model.Snapshot, q filter.Query) {
	findingsBySocket := make(map[string][]model.Finding)
	for _, f := range snap.Findings {
		if f.SocketID != "" {
			findingsBySocket[f.SocketID] = append(findingsBySocket[f.SocketID], f)
		}
	}
	included := make(map[string]bool)
	sockets := make([]model.Socket, 0, len(snap.Sockets))
	for _, s := range snap.Sockets {
		if q.MatchSocket(s, findingsBySocket[s.ID]) {
			sockets = append(sockets, s)
			included[s.ID] = true
		}
	}

	findings := make([]model.Finding, 0, len(snap.Findings))
	for _, f := range snap.Findings {
		if f.SocketID == "" {
			if q.MatchFinding(f) {
				findings = append(findings, f)
			}
			continue
		}
		if included[f.SocketID] && q.MatchFinding(f) {
			findings = append(findings, f)
		}
	}

	socketByID := make(map[string]model.Socket, len(sockets))
	for _, s := range sockets {
		socketByID[s.ID] = s
	}
	processes := make([]model.Process, 0, len(snap.Processes))
	for _, p := range snap.Processes {
		ids := make([]string, 0, len(p.SocketIDs))
		listeners := 0
		for _, id := range p.SocketIDs {
			if !included[id] {
				continue
			}
			ids = append(ids, id)
			if s, ok := socketByID[id]; ok && s.IsListening {
				listeners++
			}
		}
		if len(ids) == 0 {
			continue
		}
		p.SocketIDs = ids
		p.Sockets = len(ids)
		p.Listeners = listeners
		processes = append(processes, p)
	}

	snap.Sockets = sockets
	snap.Findings = findings
	snap.Processes = processes
	scanner.RecomputeStats(snap)
}

func writeDiagnostics(w io.Writer, snap model.Snapshot) {
	fmt.Fprintf(w, "sockhound: scan duration=%dms sockets=%d findings=%d partial=%v\n",
		snap.DurationMS, len(snap.Sockets), len(snap.Findings), snap.Visibility.Partial)
	fmt.Fprintf(w, "sockhound: sources: tcp=%d udp=%d unix=%d listeners=%d unresolved=%d\n",
		snap.Stats.TCP, snap.Stats.UDP, snap.Stats.Unix, snap.Stats.Listeners, snap.Stats.UnresolvedOwners)
	for _, warning := range snap.Visibility.Warnings {
		fmt.Fprintf(w, "sockhound: warning: %s\n", warning)
	}
}

func runTUIProgram(opts tui.Options) error {
	m := tui.New(opts)
	p := tea.NewProgram(m)
	_, err := p.Run()
	if err != nil && (errors.Is(err, tea.ErrInterrupted) || errors.Is(err, tea.ErrProgramKilled)) {
		return nil
	}
	return err
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, `SockHound %s — Linux socket inspector

Usage:
  sockhound                 Launch the interactive TUI (requires a terminal)
  sockhound tui             Launch the interactive TUI
  sockhound scan [flags]    One-shot scan, text or JSON
  sockhound version         Print the version
  sockhound help            Show this help

Run "sockhound scan --help" for scan flags. SockHound is read-only and does
not capture packets, scan remote hosts, or modify system state.
`, version.Version)
}

func printTUIUsage(w io.Writer) {
	fmt.Fprintf(w, `Usage: sockhound [tui] [flags]

Flags:
  --config PATH             JSON rules/configuration file
  --no-color                Disable colors
  --debug                   Write diagnostics to stderr
  --proc-root PATH          procfs mount point (advanced/testing)
  --no-owner-resolution     Skip process ownership resolution

Keybindings: 1-5 tabs, / filter, s sort, r refresh, e export, ? help, q quit.
`)
}

func printScanUsage(w io.Writer) {
	fmt.Fprintf(w, `Usage: sockhound scan [flags]

Flags:
  --json                    Write a versioned JSON snapshot to stdout
  --output PATH             Write JSON to a file (refuses to overwrite without --force)
  --force                   Overwrite an existing --output file
  --listening               Only TCP listeners
  --protocol NAME           tcp, tcp6, udp, udp6, unix or all
  --pid N                   Only sockets owned by PID N
  --port N                  Only sockets using local or remote port N
  --address TEXT            Match local/remote address or Unix path
  --process TEXT            Match owner process name (case-insensitive substring)
  --state NAME              Match normalized state, for example LISTEN
  --owner known|unknown     Filter by owner visibility
  --severity LEVEL          INFO, LOW, MEDIUM or HIGH
  --filter EXPR             Composable ANDed query, e.g. "tcp port:8080 owner:unknown"
  --config PATH             JSON rules/configuration file
  --debug                   Write diagnostics to stderr
  --proc-root PATH          procfs mount point (advanced/testing)
  --no-owner-resolution     Skip process ownership resolution

Exit codes:
  0 scan completed        1 usage/configuration error
  2 collection failed     3 report produced with partial visibility
`)
}
