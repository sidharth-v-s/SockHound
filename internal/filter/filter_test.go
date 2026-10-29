package filter

import (
	"testing"

	"github.com/zoro/sockhound/internal/model"
)

func p(n int) *int         { return &n }
func ino(n uint64) *uint64 { return &n }

func sample() model.Socket {
	return model.Socket{
		ID:            "tcp:42",
		Protocol:      model.ProtocolTCP,
		Family:        model.FamilyIPv4,
		LocalAddress:  "0.0.0.0",
		LocalPort:     p(8080),
		RemoteAddress: "192.168.1.4",
		RemotePort:    p(5555),
		State:         "LISTEN",
		Inode:         ino(42),
		IsListening:   true,
		BindScope:     model.BindScopeWildcard,
		OwnerPIDs:     []int{123},
		OwnerNames:    []string{"nginx"},
		OwnerUsers:    []string{"www-data"},
	}
}

func TestParseTerms(t *testing.T) {
	q := Parse("tcp pid:123 port:8080 proc:nginx owner:unknown sev:INFO listen")
	if q.Err != "" {
		t.Fatalf("unexpected parse error: %s", q.Err)
	}
	want := []string{"protocol", "pid", "port", "proc", "owner", "sev", "listen"}
	if len(q.Terms) != len(want) {
		t.Fatalf("terms = %+v, want %d", q.Terms, len(want))
	}
	for i, kind := range want {
		if q.Terms[i].Kind != kind {
			t.Errorf("term %d kind = %q, want %q", i, q.Terms[i].Kind, kind)
		}
	}
}

func TestParseInvalidNumbers(t *testing.T) {
	for _, input := range []string{"pid:abc", "port:xyz", "inode:nope"} {
		if q := Parse(input); q.Err == "" {
			t.Errorf("Parse(%q) did not report an error", input)
		}
	}
}

func TestMatchProtocol(t *testing.T) {
	tcp := sample()
	tcp6 := sample()
	tcp6.Protocol = model.ProtocolTCP6
	udp := sample()
	udp.Protocol = model.ProtocolUDP
	udp.IsListening = false
	udp6 := sample()
	udp6.Protocol = model.ProtocolUDP6
	unix := sample()
	unix.Protocol = model.ProtocolUnix

	if !Parse("tcp").MatchSocket(tcp, nil) || !Parse("tcp").MatchSocket(tcp6, nil) {
		t.Errorf("tcp should match tcp and tcp6")
	}
	if Parse("tcp").MatchSocket(udp, nil) {
		t.Errorf("tcp matched udp")
	}
	if !Parse("udp").MatchSocket(udp, nil) || !Parse("udp").MatchSocket(udp6, nil) {
		t.Errorf("udp should match udp and udp6")
	}
	if !Parse("tcp6").MatchSocket(tcp6, nil) || Parse("tcp6").MatchSocket(tcp, nil) {
		t.Errorf("tcp6 matching is wrong")
	}
	if !Parse("unix").MatchSocket(unix, nil) {
		t.Errorf("unix did not match")
	}
}

func TestMatchSocketFields(t *testing.T) {
	s := sample()
	cases := []struct {
		query string
		want  bool
	}{
		{"pid:123", true},
		{"pid:124", false},
		{"port:8080", true},
		{"port:5555", true},
		{"port:80", false},
		{"addr:192.168", true},
		{"addr:0.0.0.0", true},
		{"proc:ngin", true},
		{"proc:apache", false},
		{"user:www", true},
		{"inode:42", true},
		{"inode:43", false},
		{"state:listen", true},
		{"state:established", false},
		{"owner:known", true},
		{"owner:unknown", false},
		{"listen", true},
		{"nginx 8080", true},
		{"nginx 9090", false},
	}
	for _, tc := range cases {
		if got := Parse(tc.query).MatchSocket(s, nil); got != tc.want {
			t.Errorf("MatchSocket(%q) = %v, want %v", tc.query, got, tc.want)
		}
	}
}

func TestMatchSeverity(t *testing.T) {
	s := sample()
	findings := []model.Finding{{SocketID: s.ID, Severity: model.SeverityInfo}}
	if !Parse("sev:INFO").MatchSocket(s, findings) {
		t.Errorf("sev:INFO did not match")
	}
	if Parse("sev:HIGH").MatchSocket(s, findings) {
		t.Errorf("sev:HIGH matched an INFO finding")
	}
}

func TestMatchFinding(t *testing.T) {
	f := model.Finding{
		RuleID:   "SH-WILD-001",
		RuleName: "Wildcard-bound TCP listener",
		Severity: model.SeverityInfo,
		Summary:  "Wildcard-bound TCP listener on 0.0.0.0:8080",
		SocketID: "tcp:42",
		Evidence: model.Evidence{
			Protocol:      "tcp",
			LocalEndpoint: "0.0.0.0:8080",
			State:         "LISTEN",
			Inode:         ino(42),
			Process:       "nginx",
			User:          "www-data",
		},
	}
	cases := []struct {
		query string
		want  bool
	}{
		{"sev:INFO", true},
		{"sev:HIGH", false},
		{"tcp", true},
		{"udp", false},
		{"port:8080", true},
		{"state:LISTEN", true},
		{"proc:nginx", true},
		{"addr:0.0.0.0", true},
		{"inode:42", true},
		{"wildcard", true},
		{"owner:unknown", true}, // evidence has no PID
	}
	for _, tc := range cases {
		if got := Parse(tc.query).MatchFinding(f); got != tc.want {
			t.Errorf("MatchFinding(%q) = %v, want %v", tc.query, got, tc.want)
		}
	}
}

func TestMatchProcess(t *testing.T) {
	proc := model.Process{PID: 123, Name: "nginx", User: "www-data", Cmdline: "nginx [2 args hidden]"}
	if !Parse("pid:123").MatchProcess(proc) {
		t.Errorf("pid filter did not match")
	}
	if Parse("pid:124").MatchProcess(proc) {
		t.Errorf("pid filter matched wrong pid")
	}
	if !Parse("proc:ngin user:www").MatchProcess(proc) {
		t.Errorf("process filters did not compose")
	}
	if Parse("proc:apache").MatchProcess(proc) {
		t.Errorf("wrong process matched")
	}
}

func TestEmptyQueryMatchesEverything(t *testing.T) {
	q := Parse("")
	if !q.MatchSocket(sample(), nil) {
		t.Errorf("empty query did not match socket")
	}
	if !q.MatchFinding(model.Finding{}) {
		t.Errorf("empty query did not match finding")
	}
	if !q.MatchProcess(model.Process{}) {
		t.Errorf("empty query did not match process")
	}
}
