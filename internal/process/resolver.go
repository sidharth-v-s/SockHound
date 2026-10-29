// Package process associates socket inodes with visible processes by walking
// /proc/PID/fd, and enriches owners with comm, UID and (redacted) command
// metadata.
package process

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Stats records the cost and visibility limits of a resolution pass.
type Stats struct {
	ProcessesScanned      int
	ProcessesInaccessible int
	FDsScanned            int
	FDsUnreadable         int
	MatchedOwners         int
}

// Owner is a process associated with a socket inode.
type Owner struct {
	PID     int
	Name    string
	UID     *int
	User    string
	Cmdline string
}

// Info is metadata for one process with at least one matched socket.
type Info struct {
	PID     int
	Name    string
	UID     *int
	User    string
	Cmdline string
	Inodes  []uint64
}

// Result is a single-pass inode-to-process index.
type Result struct {
	Owners    map[uint64][]Owner
	Processes map[int]Info
	Stats     Stats
	Warnings  []string
}

// Resolve scans /proc/PID/fd once and records only sockets whose inodes are in
// wanted. Metadata is read only for processes that own at least one wanted
// socket.
func Resolve(ctx context.Context, root string, wanted map[uint64]struct{}, revealCmdline bool) (Result, error) {
	if root == "" {
		root = "/proc"
	}
	res := Result{
		Owners:    make(map[uint64][]Owner),
		Processes: make(map[int]Info),
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return res, fmt.Errorf("reading %s: %w", root, err)
	}

	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		fdDir := filepath.Join(root, entry.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				// Process exited between listing and opening its fd directory.
				continue
			}
			res.Stats.ProcessesInaccessible++
			continue
		}
		res.Stats.ProcessesScanned++

		matched := make(map[uint64]struct{})
		for _, fd := range fds {
			if err := ctx.Err(); err != nil {
				return res, err
			}
			res.Stats.FDsScanned++
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					continue
				}
				res.Stats.FDsUnreadable++
				continue
			}
			inode, ok := ParseSocketLink(target)
			if !ok {
				continue
			}
			if _, want := wanted[inode]; !want {
				continue
			}
			matched[inode] = struct{}{}
		}
		if len(matched) == 0 {
			continue
		}

		meta := readMetadata(root, pid, revealCmdline)
		inodes := make([]uint64, 0, len(matched))
		for inode := range matched {
			inodes = append(inodes, inode)
		}
		sort.Slice(inodes, func(i, j int) bool { return inodes[i] < inodes[j] })
		meta.Inodes = inodes
		res.Processes[pid] = meta

		owner := Owner{
			PID:     meta.PID,
			Name:    meta.Name,
			UID:     meta.UID,
			User:    meta.User,
			Cmdline: meta.Cmdline,
		}
		for _, inode := range inodes {
			res.Owners[inode] = append(res.Owners[inode], owner)
			res.Stats.MatchedOwners++
		}
	}

	for inode := range res.Owners {
		owners := res.Owners[inode]
		sort.Slice(owners, func(i, j int) bool { return owners[i].PID < owners[j].PID })
		res.Owners[inode] = owners
	}
	if res.Stats.ProcessesInaccessible > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"process visibility limited: %d process directories could not be read (permissions or races)",
			res.Stats.ProcessesInaccessible))
	}
	if res.Stats.FDsUnreadable > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"file descriptor visibility limited: %d entries could not be resolved", res.Stats.FDsUnreadable))
	}
	return res, nil
}

// ParseSocketLink extracts an inode from a procfs fd symlink such as
// "socket:[12345]".
func ParseSocketLink(target string) (uint64, bool) {
	const prefix = "socket:["
	if !strings.HasPrefix(target, prefix) || !strings.HasSuffix(target, "]") {
		return 0, false
	}
	inode, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(target, prefix), "]"), 10, 64)
	if err != nil || inode == 0 {
		return 0, false
	}
	return inode, true
}

func readMetadata(root string, pid int, revealCmdline bool) Info {
	info := Info{PID: pid}
	dir := filepath.Join(root, strconv.Itoa(pid))

	if b, err := os.ReadFile(filepath.Join(dir, "comm")); err == nil {
		info.Name = strings.TrimSpace(string(b))
	}
	if uid := readUID(filepath.Join(dir, "status")); uid != nil {
		info.UID = uid
		if u, err := user.LookupId(strconv.Itoa(*uid)); err == nil {
			info.User = u.Username
		}
	}
	if b, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil {
		info.Cmdline = formatCmdline(b, revealCmdline)
	}
	if info.Name == "" {
		info.Name = cmdlineBase(info.Cmdline)
	}
	if info.Name == "" {
		info.Name = "?"
	}
	return info
}

func readUID(statusPath string) *int {
	b, err := os.ReadFile(statusPath)
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
		if len(fields) == 0 {
			return nil
		}
		uid, err := strconv.Atoi(fields[0])
		if err != nil {
			return nil
		}
		return &uid
	}
	return nil
}

// formatCmdline redacts arguments after argv[0] unless explicitly enabled,
// because command lines can contain tokens or passwords.
func formatCmdline(raw []byte, reveal bool) string {
	parts := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
	if len(parts) == 0 || parts[0] == "" {
		return ""
	}
	if reveal {
		return strings.Join(parts, " ")
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return fmt.Sprintf("%s [%d args hidden]", parts[0], len(parts)-1)
}

func cmdlineBase(cmdline string) string {
	if cmdline == "" {
		return ""
	}
	first := strings.Fields(cmdline)
	if len(first) == 0 {
		return ""
	}
	return filepath.Base(first[0])
}
