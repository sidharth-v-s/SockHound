// Package scanner coordinates procfs collection, process ownership resolution,
// Unix path metadata and rule analysis into one immutable snapshot.
package scanner

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/zoro/sockhound/internal/analysis"
	"github.com/zoro/sockhound/internal/model"
	"github.com/zoro/sockhound/internal/process"
	"github.com/zoro/sockhound/internal/procfs"
)

// Options configures a scan.
type Options struct {
	ProcRoot      string
	ResolveOwners bool
	RevealCmdline bool
	UnixMetadata  bool
	Analysis      analysis.Options
	Now           func() time.Time
	Version       string
}

// DefaultOptions returns the normal read-only scan configuration.
func DefaultOptions() Options {
	return Options{
		ProcRoot:      "/proc",
		ResolveOwners: true,
		UnixMetadata:  true,
		Analysis:      analysis.DefaultOptions(),
		Now:           time.Now,
	}
}

// Run performs one scan. It returns an error only when collection failed
// entirely or the context was cancelled; partial visibility is reported in the
// snapshot.
func Run(ctx context.Context, opts Options) (model.Snapshot, error) {
	if opts.ProcRoot == "" {
		opts.ProcRoot = "/proc"
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Version == "" {
		opts.Version = "dev"
	}
	started := opts.Now()
	snap := model.Snapshot{
		SchemaVersion: model.SchemaVersion,
		ToolVersion:   opts.Version,
		CollectedAt:   started,
		Scope:         "current network namespace",
		Sockets:       []model.Socket{},
		Processes:     []model.Process{},
		Findings:      []model.Finding{},
		Stats: model.Stats{
			TCPStates:  map[string]int{},
			Severities: map[string]int{},
		},
		Visibility: model.Visibility{
			Warnings: []string{},
		},
	}
	snap.NetworkNamespace = procfs.ReadNetNS(opts.ProcRoot)
	if snap.NetworkNamespace != "" {
		snap.Scope = "current network namespace " + snap.NetworkNamespace
	}

	collector := procfs.Collector{Root: opts.ProcRoot, Now: opts.Now}
	collected, err := collector.Collect(ctx)
	if err != nil {
		return snap, err
	}
	snap.Sockets = collected.Sockets
	snap.Visibility.Warnings = append(snap.Visibility.Warnings, collected.Warnings...)

	assignIDs(snap.Sockets)
	sortSockets(snap.Sockets)

	if opts.ResolveOwners {
		wanted := make(map[uint64]struct{}, len(snap.Sockets))
		for _, s := range snap.Sockets {
			if s.Inode != nil {
				wanted[*s.Inode] = struct{}{}
			}
		}
		resolved, err := process.Resolve(ctx, opts.ProcRoot, wanted, opts.RevealCmdline)
		if err != nil {
			if ctx.Err() != nil {
				return snap, ctx.Err()
			}
			snap.Visibility.Warnings = append(snap.Visibility.Warnings,
				fmt.Sprintf("process ownership resolution failed: %v", err))
		} else {
			enrichOwners(snap.Sockets, resolved)
			snap.Processes = buildProcesses(snap.Sockets, resolved)
			snap.Stats.ProcessesScanned = resolved.Stats.ProcessesScanned
			snap.Stats.ProcessesInaccessible = resolved.Stats.ProcessesInaccessible
			snap.Stats.FDsScanned = resolved.Stats.FDsScanned
			snap.Stats.FDsUnreadable = resolved.Stats.FDsUnreadable
			snap.Visibility.ProcessesInaccessible = resolved.Stats.ProcessesInaccessible
			snap.Visibility.FDsUnreadable = resolved.Stats.FDsUnreadable
			snap.Visibility.Warnings = append(snap.Visibility.Warnings, resolved.Warnings...)
		}
	}

	if opts.UnixMetadata {
		unavailable := enrichUnixMetadata(ctx, snap.Sockets)
		if unavailable > 0 {
			snap.Visibility.Warnings = append(snap.Visibility.Warnings,
				fmt.Sprintf("unix: filesystem metadata unavailable for %d socket path(s)", unavailable))
		}
	}

	computeStats(&snap)
	snap.Findings = analysis.Analyze(&snap, opts.Analysis)
	snap.Stats.Severities = analysis.CountBySeverity(snap.Findings)
	snap.Visibility.Partial = len(snap.Visibility.Warnings) > 0 ||
		snap.Stats.ProcessesInaccessible > 0 || snap.Stats.FDsUnreadable > 0
	snap.DurationMS = opts.Now().Sub(started).Milliseconds()
	if snap.DurationMS < 0 {
		snap.DurationMS = 0
	}
	return snap, nil
}

func assignIDs(sockets []model.Socket) {
	seen := make(map[string]int, len(sockets))
	for i := range sockets {
		s := &sockets[i]
		base := string(s.Protocol) + ":"
		if s.Inode != nil {
			base += strconv.FormatUint(*s.Inode, 10)
		} else {
			base += "anon-" + strconv.Itoa(i)
		}
		if n := seen[base]; n > 0 {
			seen[base] = n + 1
			base = base + "#" + strconv.Itoa(n)
		} else {
			seen[base] = 1
		}
		s.ID = base
	}
}

func sortSockets(sockets []model.Socket) {
	order := map[model.Protocol]int{
		model.ProtocolTCP: 0, model.ProtocolTCP6: 1,
		model.ProtocolUDP: 2, model.ProtocolUDP6: 3, model.ProtocolUnix: 4,
	}
	sort.SliceStable(sockets, func(i, j int) bool {
		a, b := sockets[i], sockets[j]
		if order[a.Protocol] != order[b.Protocol] {
			return order[a.Protocol] < order[b.Protocol]
		}
		if a.Protocol == model.ProtocolUnix {
			if a.UnixPath != b.UnixPath {
				return a.UnixPath < b.UnixPath
			}
		} else {
			if a.LocalAddress != b.LocalAddress {
				return a.LocalAddress < b.LocalAddress
			}
			ap, bp := portValue(a.LocalPort), portValue(b.LocalPort)
			if ap != bp {
				return ap < bp
			}
		}
		return idValue(a.Inode) < idValue(b.Inode)
	})
}

func portValue(p *int) int {
	if p == nil {
		return -1
	}
	return *p
}

func idValue(p *uint64) uint64 {
	if p == nil {
		return 0
	}
	return *p
}

func enrichOwners(sockets []model.Socket, resolved process.Result) {
	for i := range sockets {
		s := &sockets[i]
		if s.Inode == nil {
			continue
		}
		owners := resolved.Owners[*s.Inode]
		seenPID := map[int]struct{}{}
		seenName := map[string]struct{}{}
		seenUID := map[int]struct{}{}
		seenUser := map[string]struct{}{}
		for _, o := range owners {
			if _, ok := seenPID[o.PID]; !ok {
				seenPID[o.PID] = struct{}{}
				s.OwnerPIDs = append(s.OwnerPIDs, o.PID)
			}
			if o.Name != "" {
				if _, ok := seenName[o.Name]; !ok {
					seenName[o.Name] = struct{}{}
					s.OwnerNames = append(s.OwnerNames, o.Name)
				}
			}
			if o.UID != nil {
				if _, ok := seenUID[*o.UID]; !ok {
					seenUID[*o.UID] = struct{}{}
					s.OwnerUIDs = append(s.OwnerUIDs, *o.UID)
				}
			}
			if o.User != "" {
				if _, ok := seenUser[o.User]; !ok {
					seenUser[o.User] = struct{}{}
					s.OwnerUsers = append(s.OwnerUsers, o.User)
				}
			}
		}
	}
}

func buildProcesses(sockets []model.Socket, resolved process.Result) []model.Process {
	byInode := make(map[uint64][]string, len(sockets))
	for _, s := range sockets {
		if s.Inode != nil {
			byInode[*s.Inode] = append(byInode[*s.Inode], s.ID)
		}
	}
	procs := make([]model.Process, 0, len(resolved.Processes))
	for pid, info := range resolved.Processes {
		ids := []string{}
		listeners := 0
		for _, inode := range info.Inodes {
			ids = append(ids, byInode[inode]...)
		}
		sort.Strings(ids)
		for _, s := range sockets {
			if s.IsListening && containsString(ids, s.ID) {
				listeners++
			}
		}
		procs = append(procs, model.Process{
			PID:       pid,
			Name:      info.Name,
			Cmdline:   info.Cmdline,
			UID:       info.UID,
			User:      info.User,
			SocketIDs: ids,
			Sockets:   len(ids),
			Listeners: listeners,
		})
	}
	sort.Slice(procs, func(i, j int) bool { return procs[i].PID < procs[j].PID })
	return procs
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func enrichUnixMetadata(ctx context.Context, sockets []model.Socket) int {
	unavailable := 0
	for i := range sockets {
		if err := ctx.Err(); err != nil {
			return unavailable
		}
		s := &sockets[i]
		if s.Protocol != model.ProtocolUnix || s.UnixPath == "" {
			continue
		}
		if strings.HasPrefix(s.UnixPath, "@") || !filepath.IsAbs(s.UnixPath) {
			// Abstract names and relative paths are not ordinary filesystem
			// socket files, so no stat is attempted.
			continue
		}
		info, err := os.Stat(s.UnixPath)
		if err != nil {
			available := false
			s.UnixMetaAvailable = &available
			s.UnixMetaError = err.Error()
			s.CollectionNotes = append(s.CollectionNotes, "unix metadata unavailable: "+err.Error())
			unavailable++
			continue
		}
		available := true
		s.UnixMetaAvailable = &available
		s.UnixMode = info.Mode().String()
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			uid := int(st.Uid)
			if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
				s.UnixOwner = u.Username
			} else {
				s.UnixOwner = strconv.Itoa(uid)
			}
		}
	}
	return unavailable
}

// RecomputeStats recalculates socket counts and severity counts after a caller
// filters a snapshot in place.
func RecomputeStats(snap *model.Snapshot) {
	computeStats(snap)
	snap.Stats.Severities = analysis.CountBySeverity(snap.Findings)
}

func computeStats(snap *model.Snapshot) {
	stats := model.Stats{
		TCPStates:  map[string]int{},
		Severities: map[string]int{},
	}
	stats.ProcessesScanned = snap.Stats.ProcessesScanned
	stats.ProcessesInaccessible = snap.Stats.ProcessesInaccessible
	stats.FDsScanned = snap.Stats.FDsScanned
	stats.FDsUnreadable = snap.Stats.FDsUnreadable
	for _, s := range snap.Sockets {
		stats.TotalSockets++
		switch s.Protocol {
		case model.ProtocolTCP, model.ProtocolTCP6:
			stats.TCP++
			stats.TCPStates[s.State]++
		case model.ProtocolUDP, model.ProtocolUDP6:
			stats.UDP++
		case model.ProtocolUnix:
			stats.Unix++
		}
		if s.IsListening {
			stats.Listeners++
		}
		if s.Inode != nil && len(s.OwnerPIDs) == 0 {
			stats.UnresolvedOwners++
		}
	}
	snap.Stats = stats
}
