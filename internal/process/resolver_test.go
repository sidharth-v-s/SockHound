package process

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestParseSocketLink(t *testing.T) {
	cases := map[string]uint64{
		"socket:[42]":     42,
		"socket:[123456]": 123456,
	}
	for input, want := range cases {
		got, ok := ParseSocketLink(input)
		if !ok || got != want {
			t.Errorf("ParseSocketLink(%q) = %d,%v want %d,true", input, got, ok, want)
		}
	}
	for _, input := range []string{"pipe:[42]", "socket:[]", "socket:[0]", "socket:[abc]", "anon_inode:[eventfd]"} {
		if _, ok := ParseSocketLink(input); ok {
			t.Errorf("ParseSocketLink(%q) unexpectedly succeeded", input)
		}
	}
}

func TestResolve(t *testing.T) {
	root := t.TempDir()
	makeProcess(t, root, 123, map[string]string{
		"comm":    "app\n",
		"status":  "Name:\tapp\nUid:\t1000\t1000\t1000\t1000\n",
		"cmdline": "app\x00--token=secret\x00",
	})
	symlink(t, root, 123, "3", "socket:[42]")
	symlink(t, root, 123, "4", "pipe:[7]")
	symlink(t, root, 123, "5", "socket:[99]")
	makeProcess(t, root, 124, nil)
	symlink(t, root, 124, "8", "socket:[42]")
	mkdir(t, root, "126") // process disappeared before fd scan
	mkdir(t, root, "notapid")

	wanted := map[uint64]struct{}{42: {}, 55: {}}
	res, err := Resolve(context.Background(), root, wanted, false)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(res.Owners[42]) != 2 {
		t.Fatalf("owners for inode 42 = %v, want 2", res.Owners[42])
	}
	if res.Owners[42][0].PID != 123 || res.Owners[42][1].PID != 124 {
		t.Errorf("owners not sorted: %+v", res.Owners[42])
	}
	first := res.Owners[42][0]
	if first.Name != "app" {
		t.Errorf("name = %q, want app", first.Name)
	}
	if first.UID == nil || *first.UID != 1000 {
		t.Errorf("uid = %v, want 1000", first.UID)
	}
	if first.Cmdline != "app [1 args hidden]" {
		t.Errorf("redacted cmdline = %q", first.Cmdline)
	}
	second := res.Owners[42][1]
	if second.Name != "?" {
		t.Errorf("missing metadata name = %q, want ?", second.Name)
	}
	if res.Processes[124].Name != "?" {
		t.Errorf("process fallback name = %q", res.Processes[124].Name)
	}
	if len(res.Processes) != 2 {
		t.Errorf("processes = %d, want 2", len(res.Processes))
	}
	if res.Stats.ProcessesScanned != 2 || res.Stats.FDsScanned != 4 {
		t.Errorf("stats = %+v, want 2 processes / 4 fds", res.Stats)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", res.Warnings)
	}
}

func TestResolveRevealCmdline(t *testing.T) {
	root := t.TempDir()
	makeProcess(t, root, 10, map[string]string{"cmdline": "app\x00--token=secret\x00"})
	symlink(t, root, 10, "3", "socket:[42]")
	res, err := Resolve(context.Background(), root, map[uint64]struct{}{42: {}}, true)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := res.Owners[42][0].Cmdline; got != "app --token=secret" {
		t.Errorf("revealed cmdline = %q", got)
	}
}

func TestResolveUnreadableProcess(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("procfs test")
	}
	if os.Geteuid() == 0 {
		t.Skip("root can read mode-000 directories")
	}
	root := t.TempDir()
	makeProcess(t, root, 10, nil)
	if err := os.Chmod(filepath.Join(root, "10", "fd"), 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(root, "10", "fd"), 0o755) })
	res, err := Resolve(context.Background(), root, map[uint64]struct{}{42: {}}, false)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Stats.ProcessesInaccessible != 1 {
		t.Errorf("inaccessible = %d, want 1", res.Stats.ProcessesInaccessible)
	}
	if len(res.Warnings) == 0 {
		t.Errorf("expected a visibility warning")
	}
}

func TestResolveMissingRoot(t *testing.T) {
	_, err := Resolve(context.Background(), filepath.Join(t.TempDir(), "missing"), nil, false)
	if err == nil {
		t.Fatal("expected an error for a missing proc root")
	}
}

func makeProcess(t *testing.T, root string, pid int, files map[string]string) {
	t.Helper()
	dir := filepath.Join(root, itoa(pid))
	mkdir(t, dir, "fd")
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
}

func symlink(t *testing.T, root string, pid int, fd, target string) {
	t.Helper()
	if err := os.Symlink(target, filepath.Join(root, itoa(pid), "fd", fd)); err != nil {
		t.Fatalf("symlink: %v", err)
	}
}

func mkdir(t *testing.T, root string, parts ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(append([]string{root}, parts...)...), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
