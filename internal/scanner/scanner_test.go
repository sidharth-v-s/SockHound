package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zoro/sockhound/internal/model"
)

var fixedTime = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

func TestRunIntegration(t *testing.T) {
	root := buildProcRoot(t)
	sockPath := filepath.Join(t.TempDir(), "demo.sock")
	if err := os.WriteFile(sockPath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write socket file: %v", err)
	}
	writeNet(t, root, "unix", fmt.Sprintf(`Num       RefCount Protocol Flags    Type St Inode Path
0000000000000001: 00000003 00000000 00010000 0001 03 5001 %s
0000000000000002: 00000003 00000000 00000000 0001 03 5002 /tmp/sockhound-definitely-missing.sock
0000000000000003: 00000003 00000000 00000000 0001 03 5003 @abstract.demo
`, sockPath))

	makeProc(t, root, 123, "demo", 1000, "demo\x00--secret\x00")
	link(t, root, 123, "3", "socket:[100]")
	link(t, root, 123, "4", "socket:[5001]")
	makeProc(t, root, 456, "db", 1000, "db\x00")
	link(t, root, 456, "5", "socket:[101]")

	opts := DefaultOptions()
	opts.ProcRoot = root
	opts.Version = "test-version"
	opts.Now = func() time.Time { return fixedTime }
	snap, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if snap.SchemaVersion != model.SchemaVersion || snap.ToolVersion != "test-version" {
		t.Errorf("schema/version = %d/%s", snap.SchemaVersion, snap.ToolVersion)
	}
	if snap.NetworkNamespace != "net:[12345]" {
		t.Errorf("netns = %q", snap.NetworkNamespace)
	}
	if snap.DurationMS != 0 {
		t.Errorf("duration = %d, want 0", snap.DurationMS)
	}
	if len(snap.Sockets) != 24 {
		t.Errorf("sockets = %d, want 24", len(snap.Sockets))
	}
	if len(snap.Processes) != 2 {
		t.Errorf("processes = %d, want 2: %+v", len(snap.Processes), snap.Processes)
	}
	if snap.Stats.TotalSockets != len(snap.Sockets) || snap.Stats.TCP != 13 || snap.Stats.UDP != 8 || snap.Stats.Unix != 3 {
		t.Errorf("stats = %+v", snap.Stats)
	}
	if snap.Stats.Listeners != 5 {
		t.Errorf("listeners = %d, want 5", snap.Stats.Listeners)
	}
	if !snap.Visibility.Partial {
		t.Errorf("snapshot should be partial because one unix path is missing")
	}
	if len(snap.Visibility.Warnings) == 0 {
		t.Errorf("expected collection warnings")
	}

	ids := map[string]bool{}
	for _, s := range snap.Sockets {
		if s.ID == "" || ids[s.ID] {
			t.Errorf("duplicate or empty socket ID %q", s.ID)
		}
		ids[s.ID] = true
	}

	byInode := map[uint64]model.Socket{}
	for _, s := range snap.Sockets {
		if s.Inode != nil {
			byInode[*s.Inode] = s
		}
	}
	listener := byInode[100]
	if len(listener.OwnerPIDs) != 1 || listener.OwnerPIDs[0] != 123 {
		t.Errorf("inode 100 owners = %v, want [123]", listener.OwnerPIDs)
	}
	if len(listener.OwnerNames) != 1 || listener.OwnerNames[0] != "demo" {
		t.Errorf("inode 100 names = %v", listener.OwnerNames)
	}
	if listener.OwnerUIDs[0] != 1000 {
		t.Errorf("inode 100 uid = %v", listener.OwnerUIDs)
	}
	if listener.BindScope != model.BindScopeWildcard || !listener.IsListening {
		t.Errorf("inode 100 scope/listening = %s/%v", listener.BindScope, listener.IsListening)
	}
	if byInode[101].OwnerPIDs[0] != 456 {
		t.Errorf("inode 101 owner = %v", byInode[101].OwnerPIDs)
	}

	var demo model.Process
	for _, p := range snap.Processes {
		if p.PID == 123 {
			demo = p
		}
	}
	if demo.Name != "demo" || demo.Sockets != 2 || demo.Listeners != 1 {
		t.Errorf("demo process = %+v", demo)
	}
	if demo.Cmdline != "demo [1 args hidden]" {
		t.Errorf("cmdline redaction = %q", demo.Cmdline)
	}

	unixOK := byInode[5001]
	if unixOK.UnixMetaAvailable == nil || !*unixOK.UnixMetaAvailable || unixOK.UnixMode == "" {
		t.Errorf("unix metadata for existing path = %+v", unixOK)
	}
	unixMissing := byInode[5002]
	if unixMissing.UnixMetaAvailable == nil || *unixMissing.UnixMetaAvailable || unixMissing.UnixMetaError == "" {
		t.Errorf("unix metadata for missing path = %+v", unixMissing)
	}
	unixAbstract := byInode[5003]
	if unixAbstract.UnixMetaAvailable != nil {
		t.Errorf("abstract unix socket should not attempt metadata: %+v", unixAbstract.UnixMetaAvailable)
	}

	if !hasFinding(snap, "SH-WILD-001") {
		t.Errorf("missing wildcard finding")
	}
	if !hasFinding(snap, "SH-UNIX-001") {
		t.Errorf("missing unix metadata finding")
	}
	if snap.Stats.Severities["INFO"] == 0 {
		t.Errorf("severity stats not computed: %v", snap.Stats.Severities)
	}
}

func TestRunNoOwnerResolution(t *testing.T) {
	root := buildProcRoot(t)
	writeNet(t, root, "unix", "Num RefCount Protocol Flags Type St Inode Path\n")
	opts := DefaultOptions()
	opts.ProcRoot = root
	opts.ResolveOwners = false
	opts.Now = func() time.Time { return fixedTime }
	snap, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, s := range snap.Sockets {
		if len(s.OwnerPIDs) != 0 {
			t.Errorf("owner resolved with ResolveOwners=false: %v", s.OwnerPIDs)
		}
	}
	if len(snap.Processes) != 0 {
		t.Errorf("processes = %d, want 0", len(snap.Processes))
	}
}

func TestRunPartialSource(t *testing.T) {
	root := buildProcRoot(t)
	writeNet(t, root, "unix", "Num RefCount Protocol Flags Type St Inode Path\n")
	if err := os.Remove(filepath.Join(root, "self", "net", "tcp6")); err != nil {
		t.Fatalf("remove tcp6: %v", err)
	}
	opts := DefaultOptions()
	opts.ProcRoot = root
	opts.ResolveOwners = false
	opts.Now = func() time.Time { return fixedTime }
	snap, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run should tolerate one missing source: %v", err)
	}
	if !snap.Visibility.Partial {
		t.Errorf("snapshot should be partial")
	}
	found := false
	for _, w := range snap.Visibility.Warnings {
		if strings.Contains(w, "tcp6") {
			found = true
		}
	}
	if !found {
		t.Errorf("missing tcp6 warning: %v", snap.Visibility.Warnings)
	}
}

func TestRunAllSourcesMissing(t *testing.T) {
	root := t.TempDir()
	opts := DefaultOptions()
	opts.ProcRoot = root
	opts.Now = func() time.Time { return fixedTime }
	if _, err := Run(context.Background(), opts); err == nil {
		t.Fatal("expected an error when every source is missing")
	}
}

func TestRunCanceled(t *testing.T) {
	root := buildProcRoot(t)
	writeNet(t, root, "unix", "Num RefCount Protocol Flags Type St Inode Path\n")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	opts := DefaultOptions()
	opts.ProcRoot = root
	opts.Now = func() time.Time { return fixedTime }
	if _, err := Run(ctx, opts); err == nil {
		t.Fatal("expected context cancellation error")
	}
}

func buildProcRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	netDir := filepath.Join(root, "self", "net")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatalf("mkdir net: %v", err)
	}
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6", "unix"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "proc-net-"+name+".txt"))
		if err != nil {
			t.Fatalf("read fixture %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(netDir, name), b, 0o644); err != nil {
			t.Fatalf("write net %s: %v", name, err)
		}
	}
	nsDir := filepath.Join(root, "self", "ns")
	if err := os.MkdirAll(nsDir, 0o755); err != nil {
		t.Fatalf("mkdir ns: %v", err)
	}
	if err := os.Symlink("net:[12345]", filepath.Join(nsDir, "net")); err != nil {
		t.Fatalf("symlink netns: %v", err)
	}
	return root
}

func writeNet(t *testing.T, root, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, "self", "net", name), []byte(content), 0o644); err != nil {
		t.Fatalf("write net %s: %v", name, err)
	}
}

func makeProc(t *testing.T, root string, pid int, comm string, uid int, cmdline string) {
	t.Helper()
	dir := filepath.Join(root, fmt.Sprint(pid))
	if err := os.MkdirAll(filepath.Join(dir, "fd"), 0o755); err != nil {
		t.Fatalf("mkdir proc: %v", err)
	}
	writeFile(t, filepath.Join(dir, "comm"), comm+"\n")
	writeFile(t, filepath.Join(dir, "status"), fmt.Sprintf("Name:\t%s\nUid:\t%d\t%d\t%d\t%d\n", comm, uid, uid, uid, uid))
	writeFile(t, filepath.Join(dir, "cmdline"), cmdline)
}

func link(t *testing.T, root string, pid int, fd, target string) {
	t.Helper()
	if err := os.Symlink(target, filepath.Join(root, fmt.Sprint(pid), "fd", fd)); err != nil {
		t.Fatalf("symlink fd: %v", err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func hasFinding(snap model.Snapshot, id string) bool {
	for _, f := range snap.Findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}
