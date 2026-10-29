package procfs

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zoro/sockhound/internal/model"
)

var fixtureTime = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

func fixture(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.Open("../../testdata/" + name)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestParseTCPTable(t *testing.T) {
	sockets, warnings, err := ParseTCPTable(fixture(t, "proc-net-tcp.txt"), model.ProtocolTCP, fixtureTime)
	if err != nil {
		t.Fatalf("ParseTCPTable: %v", err)
	}
	if len(sockets) != 8 {
		t.Fatalf("got %d sockets, want 8 (warnings: %v)", len(sockets), warnings)
	}
	if len(warnings) != 2 {
		t.Fatalf("got %d warnings, want 2: %v", len(warnings), warnings)
	}

	first := sockets[0]
	if first.LocalAddress != "0.0.0.0" || first.LocalPort == nil || *first.LocalPort != 8080 {
		t.Errorf("first local = %s:%v, want 0.0.0.0:8080", first.LocalAddress, first.LocalPort)
	}
	if first.State != "LISTEN" || !first.IsListening {
		t.Errorf("first state = %q listening=%v, want LISTEN/true", first.State, first.IsListening)
	}
	if first.BindScope != model.BindScopeWildcard {
		t.Errorf("first bind scope = %q, want wildcard", first.BindScope)
	}
	if first.RemoteAddress != "" || first.RemotePort != nil {
		t.Errorf("listener remote = %q/%v, want empty", first.RemoteAddress, first.RemotePort)
	}
	if first.Inode == nil || *first.Inode != 100 {
		t.Errorf("first inode = %v, want 100", first.Inode)
	}
	if first.SocketUID == nil || *first.SocketUID != 1000 {
		t.Errorf("first uid = %v, want 1000", first.SocketUID)
	}
	if first.CollectedAt != fixtureTime {
		t.Errorf("collected_at = %v, want %v", first.CollectedAt, fixtureTime)
	}

	second := sockets[1]
	if second.LocalAddress != "127.0.0.1" || second.BindScope != model.BindScopeLoopback {
		t.Errorf("second = %s scope=%s, want 127.0.0.1 loopback", second.LocalAddress, second.BindScope)
	}
	third := sockets[2]
	if third.State != "ESTABLISHED" || third.RemoteAddress != "127.0.0.1" || third.RemotePort == nil || *third.RemotePort != 8080 {
		t.Errorf("third = %s %s:%v, want ESTABLISHED 127.0.0.1:8080", third.State, third.RemoteAddress, third.RemotePort)
	}
	fourth := sockets[3]
	if fourth.LocalAddress != "192.168.1.8" || fourth.LocalPort == nil || *fourth.LocalPort != 54321 {
		t.Errorf("fourth local = %s:%v, want 192.168.1.8:54321", fourth.LocalAddress, fourth.LocalPort)
	}
	if fourth.RemoteAddress != "192.168.81.34" || fourth.RemotePort == nil || *fourth.RemotePort != 443 {
		t.Errorf("fourth remote = %s:%v, want 192.168.81.34:443", fourth.RemoteAddress, fourth.RemotePort)
	}
	if fourth.State != "TIME_WAIT" || fourth.BindScope != model.BindScopeSpecific {
		t.Errorf("fourth state/scope = %s/%s", fourth.State, fourth.BindScope)
	}
	unknown := sockets[5]
	if unknown.State != "UNKNOWN" || unknown.IsListening {
		t.Errorf("unknown state record = %q listening=%v", unknown.State, unknown.IsListening)
	}
	if sockets[6].Inode == nil || sockets[7].Inode == nil || *sockets[6].Inode != *sockets[7].Inode {
		t.Errorf("duplicate inode records were not preserved")
	}
}

func TestParseTCP6Table(t *testing.T) {
	sockets, warnings, err := ParseTCPTable(fixture(t, "proc-net-tcp6.txt"), model.ProtocolTCP6, fixtureTime)
	if err != nil {
		t.Fatalf("ParseTCPTable: %v", err)
	}
	if len(sockets) != 5 {
		t.Fatalf("got %d sockets, want 5 (warnings: %v)", len(sockets), warnings)
	}
	if len(warnings) != 1 {
		t.Fatalf("got %d warnings, want 1", len(warnings))
	}
	cases := []struct {
		index int
		addr  string
		scope model.BindScope
	}{
		{0, "::", model.BindScopeWildcard},
		{1, "::1", model.BindScopeLoopback},
		{2, "127.0.0.1", model.BindScopeLoopback},
		{3, "2001:df0:b240:573b:520c:f5d2:918:559", model.BindScopeSpecific},
		{4, "::", model.BindScopeWildcard},
	}
	for _, tc := range cases {
		s := sockets[tc.index]
		if s.LocalAddress != tc.addr {
			t.Errorf("socket %d local = %q, want %q", tc.index, s.LocalAddress, tc.addr)
		}
		if s.BindScope != tc.scope {
			t.Errorf("socket %d scope = %q, want %q", tc.index, s.BindScope, tc.scope)
		}
	}
	if sockets[3].LocalPort == nil || *sockets[3].LocalPort != 443 {
		t.Errorf("public IPv6 port = %v, want 443", sockets[3].LocalPort)
	}
	if sockets[4].State != "UNKNOWN" {
		t.Errorf("unknown TCP6 state = %q", sockets[4].State)
	}
}

func TestParseUDPTable(t *testing.T) {
	sockets, warnings, err := ParseUDPTable(fixture(t, "proc-net-udp.txt"), model.ProtocolUDP, fixtureTime)
	if err != nil {
		t.Fatalf("ParseUDPTable: %v", err)
	}
	if len(sockets) != 5 || len(warnings) != 0 {
		t.Fatalf("got %d sockets, %d warnings", len(sockets), len(warnings))
	}
	wantStates := []string{"UNCONN", "CONNECTED", "UNCONN", "UNKNOWN", "UNCONN"}
	for i, want := range wantStates {
		if sockets[i].State != want {
			t.Errorf("socket %d state = %q, want %q", i, sockets[i].State, want)
		}
		if sockets[i].IsListening {
			t.Errorf("UDP socket %d was labelled listening", i)
		}
	}
	if sockets[1].RemoteAddress != "127.0.0.1" || sockets[1].RemotePort == nil || *sockets[1].RemotePort != 53 {
		t.Errorf("connected UDP remote = %s:%v", sockets[1].RemoteAddress, sockets[1].RemotePort)
	}
	if sockets[4].Inode != nil {
		t.Errorf("inode 0 should be nil, got %v", sockets[4].Inode)
	}
}

func TestParseUDP6Table(t *testing.T) {
	sockets, _, err := ParseUDPTable(fixture(t, "proc-net-udp6.txt"), model.ProtocolUDP6, fixtureTime)
	if err != nil {
		t.Fatalf("ParseUDPTable: %v", err)
	}
	if len(sockets) != 3 {
		t.Fatalf("got %d sockets, want 3", len(sockets))
	}
	if sockets[0].LocalAddress != "2001:df0:b240:573b:520c:f5d2:918:559" {
		t.Errorf("public UDP6 address = %q", sockets[0].LocalAddress)
	}
	if sockets[2].LocalAddress != "::1" || sockets[2].RemoteAddress != "::1" {
		t.Errorf("connected UDP6 = %q -> %q", sockets[2].LocalAddress, sockets[2].RemoteAddress)
	}
}

func TestParseUnixTable(t *testing.T) {
	sockets, warnings, err := ParseUnixTable(fixture(t, "proc-net-unix.txt"), fixtureTime)
	if err != nil {
		t.Fatalf("ParseUnixTable: %v", err)
	}
	if len(sockets) != 6 {
		t.Fatalf("got %d sockets, want 6 (warnings: %v)", len(sockets), warnings)
	}
	if len(warnings) != 1 {
		t.Fatalf("got %d warnings, want 1: %v", len(warnings), warnings)
	}
	if sockets[0].UnixPath != "/run/systemd/journal/stdout" || sockets[0].UnixType != "STREAM" || sockets[0].State != "CONNECTED" {
		t.Errorf("first unix = %+v", sockets[0])
	}
	if sockets[1].UnixPath != "" {
		t.Errorf("unnamed unix path = %q, want empty", sockets[1].UnixPath)
	}
	if sockets[2].UnixType != "DGRAM" || sockets[2].State != "UNCONNECTED" {
		t.Errorf("dgram unix = type %s state %s", sockets[2].UnixType, sockets[2].State)
	}
	if sockets[3].UnixPath != "@abstract.name" {
		t.Errorf("abstract path = %q", sockets[3].UnixPath)
	}
	if sockets[4].UnixPath != "/tmp/with space.sock" || sockets[4].UnixType != "SEQPACKET" {
		t.Errorf("space path = %q type %s", sockets[4].UnixPath, sockets[4].UnixType)
	}
	if sockets[5].State != "UNKNOWN" {
		t.Errorf("unknown unix state = %q", sockets[5].State)
	}
}

func TestTCPStateNames(t *testing.T) {
	cases := map[string]string{
		"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
		"04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
		"07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
		"0A": "LISTEN", "0B": "CLOSING", "0C": "NEW_SYN_RECV",
		"0a": "LISTEN", "FF": "UNKNOWN", "": "UNKNOWN",
	}
	for code, want := range cases {
		if got := TCPStateName(code); got != want {
			t.Errorf("TCPStateName(%q) = %q, want %q", code, got, want)
		}
	}
}

func TestParseEndpoint(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		family  model.Family
		addr    string
		port    int
		wantErr bool
	}{
		{"ipv4 loopback", "0100007F:1F90", model.FamilyIPv4, "127.0.0.1", 8080, false},
		{"ipv4 wildcard", "00000000:0000", model.FamilyIPv4, "0.0.0.0", 0, false},
		{"ipv6 loopback", "00000000000000000000000001000000:1538", model.FamilyIPv6, "::1", 5432, false},
		{"ipv6 public", "F00D01203B5740B2D2F50C5259051809:01BB", model.FamilyIPv6, "2001:df0:b240:573b:520c:f5d2:918:559", 443, false},
		{"missing colon", "0100007F", model.FamilyIPv4, "", 0, true},
		{"short ipv4", "0100:1F90", model.FamilyIPv4, "", 0, true},
		{"bad port", "0100007F:ZZZZ", model.FamilyIPv4, "", 0, true},
		{"short ipv6", "0000:1F90", model.FamilyIPv6, "", 0, true},
		{"bad hex ipv6", "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ:1F90", model.FamilyIPv6, "", 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr, port, err := ParseEndpoint(tc.raw, tc.family)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %s:%v", addr, port)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if addr != tc.addr {
				t.Errorf("addr = %q, want %q", addr, tc.addr)
			}
			if port == nil || *port != tc.port {
				t.Errorf("port = %v, want %d", port, tc.port)
			}
		})
	}
}

func TestBindScope(t *testing.T) {
	cases := map[string]model.BindScope{
		"0.0.0.0":     model.BindScopeWildcard,
		"::":          model.BindScopeWildcard,
		"127.0.0.1":   model.BindScopeLoopback,
		"::1":         model.BindScopeLoopback,
		"192.168.1.8": model.BindScopeSpecific,
		"2001:db8::1": model.BindScopeSpecific,
		"not-an-ip":   model.BindScopeUnknown,
	}
	for addr, want := range cases {
		if got := BindScope(addr); got != want {
			t.Errorf("BindScope(%q) = %q, want %q", addr, got, want)
		}
	}
}

func TestEmptyTable(t *testing.T) {
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	sockets, warnings, err := ParseTCPTable(strings.NewReader(header), model.ProtocolTCP, fixtureTime)
	if err != nil || len(sockets) != 0 || len(warnings) != 0 {
		t.Fatalf("empty table: sockets=%d warnings=%v err=%v", len(sockets), warnings, err)
	}
}

func FuzzParseTCPTable(f *testing.F) {
	f.Add("  sl  local_address rem_address st\n 0: 0100007F:1F90 00000000:0000 0A 0:0 0:0 0 1000 0 1\n")
	f.Add("garbage\n")
	f.Fuzz(func(t *testing.T, input string) {
		_, _, _ = ParseTCPTable(strings.NewReader(input), model.ProtocolTCP, fixtureTime)
	})
}

func FuzzParseUnixTable(f *testing.F) {
	f.Add("Num RefCount Protocol Flags Type St Inode Path\n0: 1 0 0 0001 03 1 /tmp/x\n")
	f.Add("garbage\n")
	f.Fuzz(func(t *testing.T, input string) {
		_, _, _ = ParseUnixTable(strings.NewReader(input), fixtureTime)
	})
}
