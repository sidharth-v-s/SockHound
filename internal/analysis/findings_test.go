package analysis

import (
	"strings"
	"testing"
	"time"

	"github.com/zoro/sockhound/internal/model"
)

func port(n int) *int        { return &n }
func inode(n uint64) *uint64 { return &n }

func baseSnapshot(sockets ...model.Socket) *model.Snapshot {
	return &model.Snapshot{
		CollectedAt: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC),
		Sockets:     sockets,
		Findings:    []model.Finding{},
	}
}

func listener(addr string, p int, proto model.Protocol) model.Socket {
	scope := model.BindScopeSpecific
	switch addr {
	case "0.0.0.0", "::":
		scope = model.BindScopeWildcard
	case "127.0.0.1", "::1":
		scope = model.BindScopeLoopback
	case "":
		scope = model.BindScopeUnknown
	}
	return model.Socket{
		ID:           string(proto) + ":1",
		Protocol:     proto,
		Family:       model.FamilyIPv4,
		LocalAddress: addr,
		LocalPort:    port(p),
		State:        "LISTEN",
		IsListening:  proto.IsTCP(),
		BindScope:    scope,
		Inode:        inode(1),
		OwnerPIDs:    []int{},
		OwnerNames:   []string{},
		OwnerUsers:   []string{},
	}
}

func hasRule(findings []model.Finding, id string) bool {
	for _, f := range findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func TestWildcardListenerRule(t *testing.T) {
	snap := baseSnapshot(
		listener("0.0.0.0", 8080, model.ProtocolTCP),
		listener("127.0.0.1", 5432, model.ProtocolTCP),
		listener("::", 9090, model.ProtocolTCP6),
		listener("0.0.0.0", 5353, model.ProtocolUDP),
	)
	findings := Analyze(snap, DefaultOptions())
	count := 0
	for _, f := range findings {
		if f.RuleID == RuleWildcardListener {
			count++
			if f.Evidence.LocalEndpoint == "127.0.0.1:5432" {
				t.Errorf("loopback listener produced a wildcard finding")
			}
			if f.Evidence.LocalEndpoint == "0.0.0.0:5353" {
				t.Errorf("UDP socket produced a TCP wildcard-listener finding")
			}
			if f.Severity != model.SeverityInfo {
				t.Errorf("severity = %s, want INFO", f.Severity)
			}
			if f.Evidence.State != "LISTEN" || f.Evidence.Inode == nil || *f.Evidence.Inode != 1 {
				t.Errorf("evidence incomplete: %+v", f.Evidence)
			}
			if f.Limitations == "" {
				t.Errorf("wildcard finding lacks reachability limitation")
			}
		}
	}
	if count != 2 {
		t.Errorf("wildcard findings = %d, want 2", count)
	}
}

func TestReviewPortRule(t *testing.T) {
	tcp := listener("0.0.0.0", 2323, model.ProtocolTCP)
	udp := listener("0.0.0.0", 2323, model.ProtocolUDP)
	udp.State = "UNCONN"
	snap := baseSnapshot(tcp, udp)
	opts := DefaultOptions()
	opts.ReviewPorts = []int{2323}
	findings := Analyze(snap, opts)
	count := 0
	for _, f := range findings {
		if f.RuleID != RuleReviewPort {
			continue
		}
		count++
		if f.Severity != model.SeverityInfo {
			t.Errorf("review port severity = %s, want INFO", f.Severity)
		}
		if f.Evidence.Protocol == "udp" && f.Summary == "" {
			t.Errorf("UDP review finding has no summary")
		}
		if f.Evidence.Protocol == "udp" && contains(f.Summary, "listener") {
			t.Errorf("UDP socket was mislabelled as a listener: %q", f.Summary)
		}
	}
	if count != 2 {
		t.Errorf("review-port findings = %d, want 2", count)
	}

	// Disable the rule.
	disabled := DefaultOptions()
	disabled.ReviewPorts = []int{2323}
	disabled.Rules[RuleReviewPort] = RuleConfig{Enabled: false}
	if got := Analyze(snap, disabled); hasRule(got, RuleReviewPort) {
		t.Errorf("disabled review-port rule still fired")
	}
}

func TestSeverityOverrideIsVisible(t *testing.T) {
	snap := baseSnapshot(listener("0.0.0.0", 8080, model.ProtocolTCP))
	opts := DefaultOptions()
	opts.Rules[RuleWildcardListener] = RuleConfig{Enabled: true, Severity: model.SeverityMedium, HasSeverity: true}
	findings := Analyze(snap, opts)
	if len(findings) == 0 {
		t.Fatal("no findings")
	}
	f := findings[0]
	if f.Severity != model.SeverityMedium || !f.SeverityOverride {
		t.Errorf("severity = %s override=%v, want MEDIUM/true", f.Severity, f.SeverityOverride)
	}
	if !contains(f.Limitations, "overridden") {
		t.Errorf("override not visible in limitations: %q", f.Limitations)
	}
}

func TestOwnerUnresolvedRule(t *testing.T) {
	unowned := listener("127.0.0.1", 8080, model.ProtocolTCP)
	owned := listener("127.0.0.1", 8081, model.ProtocolTCP)
	owned.ID = "tcp:2"
	owned.OwnerPIDs = []int{42}
	owned.OwnerNames = []string{"app"}
	snap := baseSnapshot(unowned, owned)
	findings := Analyze(snap, DefaultOptions())
	count := 0
	for _, f := range findings {
		if f.RuleID == RuleOwnerUnresolved {
			count++
			if f.SocketID != unowned.ID {
				t.Errorf("owner finding on wrong socket %s", f.SocketID)
			}
			if f.Evidence.PID != nil {
				t.Errorf("unresolved owner evidence has a PID")
			}
		}
	}
	if count != 1 {
		t.Errorf("owner findings = %d, want 1", count)
	}
}

func TestUnixMetadataRule(t *testing.T) {
	available := true
	unavailable := false
	ok := listener("", 0, model.ProtocolUnix)
	ok.ID = "unix:1"
	ok.UnixPath = "/run/ok.sock"
	ok.UnixMetaAvailable = &available
	bad := listener("", 0, model.ProtocolUnix)
	bad.ID = "unix:2"
	bad.UnixPath = "/run/bad.sock"
	bad.UnixMetaAvailable = &unavailable
	bad.UnixMetaError = "permission denied"
	abstract := listener("", 0, model.ProtocolUnix)
	abstract.ID = "unix:3"
	abstract.UnixPath = "@abstract"
	abstract.UnixMetaAvailable = &unavailable
	snap := baseSnapshot(ok, bad, abstract)
	findings := Analyze(snap, DefaultOptions())
	count := 0
	for _, f := range findings {
		if f.RuleID == RuleUnixMeta {
			count++
			if f.SocketID != bad.ID {
				t.Errorf("unix metadata finding on wrong socket %s", f.SocketID)
			}
			if f.Evidence.Detail != "permission denied" {
				t.Errorf("evidence detail = %q", f.Evidence.Detail)
			}
		}
	}
	if count != 1 {
		t.Errorf("unix metadata findings = %d, want 1", count)
	}
}

func TestPartialScopeRule(t *testing.T) {
	snap := baseSnapshot()
	snap.Stats.ProcessesInaccessible = 2
	findings := Analyze(snap, DefaultOptions())
	if !hasRule(findings, RulePartialScope) {
		t.Errorf("partial scope finding missing")
	}
	snap.Stats.ProcessesInaccessible = 0
	if got := Analyze(snap, DefaultOptions()); hasRule(got, RulePartialScope) {
		t.Errorf("partial scope finding fired without limitations")
	}
}

func TestUnknownStateRule(t *testing.T) {
	tcp := listener("127.0.0.1", 8080, model.ProtocolTCP)
	tcp.State = "UNKNOWN"
	tcp.IsListening = false
	udp := listener("127.0.0.1", 8080, model.ProtocolUDP)
	udp.State = "UNKNOWN"
	snap := baseSnapshot(tcp, udp)
	findings := Analyze(snap, DefaultOptions())
	count := 0
	for _, f := range findings {
		if f.RuleID == RuleUnknownState {
			count++
			if f.Evidence.Protocol != "tcp" {
				t.Errorf("unknown-state rule fired for %s", f.Evidence.Protocol)
			}
		}
	}
	if count != 1 {
		t.Errorf("unknown-state findings = %d, want 1", count)
	}
}

func TestFindingsSortedBySeverity(t *testing.T) {
	snap := baseSnapshot(listener("0.0.0.0", 8080, model.ProtocolTCP))
	opts := DefaultOptions()
	opts.Rules[RuleWildcardListener] = RuleConfig{Enabled: true, Severity: model.SeverityHigh, HasSeverity: true}
	findings := Analyze(snap, opts)
	for i := 1; i < len(findings); i++ {
		if findings[i-1].Severity.Rank() < findings[i].Severity.Rank() {
			t.Errorf("findings are not sorted by severity: %s before %s", findings[i-1].Severity, findings[i].Severity)
		}
	}
}

func TestCountBySeverity(t *testing.T) {
	counts := CountBySeverity([]model.Finding{
		{Severity: model.SeverityInfo},
		{Severity: model.SeverityInfo},
		{Severity: model.SeverityHigh},
	})
	if counts["INFO"] != 2 || counts["HIGH"] != 1 || counts["LOW"] != 0 || counts["MEDIUM"] != 0 {
		t.Errorf("counts = %v", counts)
	}
}

func contains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}
