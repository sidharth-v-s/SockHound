// Package analysis runs evidence-backed heuristic rules over a snapshot.
package analysis

import (
	"fmt"
	"sort"
	"strings"

	"github.com/zoro/sockhound/internal/model"
)

// Rule IDs.
const (
	RuleWildcardListener = "SH-WILD-001"
	RuleReviewPort       = "SH-PORT-001"
	RuleOwnerUnresolved  = "SH-OWNER-001"
	RuleUnixMeta         = "SH-UNIX-001"
	RulePartialScope     = "SH-SCOPE-001"
	RuleUnknownState     = "SH-STATE-001"
)

// Rule describes a rule's identity and default severity.
type Rule struct {
	ID       string
	Name     string
	Severity model.Severity
}

// Catalog lists every rule in a stable order.
var Catalog = []Rule{
	{RuleWildcardListener, "Wildcard-bound TCP listener", model.SeverityInfo},
	{RuleReviewPort, "Socket on review-listed port", model.SeverityInfo},
	{RuleOwnerUnresolved, "Owner unresolved", model.SeverityInfo},
	{RuleUnixMeta, "Unix socket path metadata unavailable", model.SeverityInfo},
	{RulePartialScope, "Partial process visibility", model.SeverityInfo},
	{RuleUnknownState, "Unexpected/unknown TCP state", model.SeverityInfo},
}

// RuleConfig is a resolved override for one rule.
type RuleConfig struct {
	Enabled     bool
	Severity    model.Severity
	HasSeverity bool
}

// Options configures the rule runner.
type Options struct {
	ReviewPorts []int
	Rules       map[string]RuleConfig
}

// DefaultOptions returns the built-in rule configuration.
func DefaultOptions() Options {
	return Options{Rules: map[string]RuleConfig{}}
}

func (o Options) rule(id string) (Rule, bool, model.Severity) {
	var def Rule
	found := false
	for _, r := range Catalog {
		if r.ID == id {
			def = r
			found = true
			break
		}
	}
	if !found {
		return def, false, ""
	}
	rc, ok := o.Rules[id]
	if ok && !rc.Enabled {
		return def, false, def.Severity
	}
	sev := def.Severity
	if ok && rc.HasSeverity {
		sev = rc.Severity
	}
	return def, true, sev
}

// Analyze produces findings for a snapshot.
func Analyze(snap *model.Snapshot, opts Options) []model.Finding {
	if snap == nil {
		return []model.Finding{}
	}
	review := make(map[int]struct{}, len(opts.ReviewPorts))
	for _, p := range opts.ReviewPorts {
		review[p] = struct{}{}
	}

	var findings []model.Finding
	add := func(id string, f model.Finding) {
		def, enabled, sev := opts.rule(id)
		if !enabled {
			return
		}
		f.RuleID = def.ID
		f.RuleName = def.Name
		if sev != def.Severity {
			f.Severity = sev
			f.SeverityOverride = true
			f.Limitations = appendNote(f.Limitations, "Severity overridden by local configuration.")
		} else {
			f.Severity = def.Severity
		}
		f.CollectedAt = snap.CollectedAt
		findings = append(findings, f)
	}

	for i := range snap.Sockets {
		s := snap.Sockets[i]
		ev := evidenceFor(s)

		if s.Protocol.IsTCP() && s.IsListening && s.BindScope == model.BindScopeWildcard {
			add(RuleWildcardListener, model.Finding{
				Summary:     fmt.Sprintf("Wildcard-bound TCP listener on %s", s.Endpoint()),
				Explanation: "The TCP socket is listening on a wildcard address (0.0.0.0 or ::), so it accepts connections addressed to any local interface.",
				Limitations: "A wildcard bind does not prove the service is reachable from the internet. Firewall policy, routing, host/container networking and other controls determine exposure; SockHound does not test external reachability.",
				Remediation: "Confirm the service is intended to be reachable on all interfaces. Bind to a specific address or loopback, or restrict access with firewall policy, if it is not.",
				SocketID:    s.ID,
				Evidence:    ev,
			})
		}

		if s.LocalPort != nil && s.Protocol.IsTCP() && s.IsListening {
			if _, ok := review[*s.LocalPort]; ok {
				add(RuleReviewPort, model.Finding{
					Summary:     fmt.Sprintf("TCP listener on review-listed port %d", *s.LocalPort),
					Explanation: "This TCP listener uses a port that appears in the local review list. The list is user-controlled; a port number alone does not indicate a vulnerability.",
					Limitations: "The review list is local configuration, not a vulnerability database. Interpret this finding with the service identity, bind address and firewall policy.",
					Remediation: "Review the service and its intended exposure, or remove the port from review_ports if it does not need attention.",
					SocketID:    s.ID,
					Evidence:    ev,
				})
			}
		}
		if s.LocalPort != nil && s.Protocol.IsUDP() {
			if _, ok := review[*s.LocalPort]; ok {
				add(RuleReviewPort, model.Finding{
					Summary:     fmt.Sprintf("UDP socket bound to review-listed port %d", *s.LocalPort),
					Explanation: "This UDP socket uses a port that appears in the local review list. UDP sockets are not TCP-style listeners; this finding only identifies the bound port.",
					Limitations: "A UDP socket may be bound without being actively used. The review list is local configuration, not a vulnerability database.",
					Remediation: "Review the service and its intended exposure, or remove the port from review_ports if it does not need attention.",
					SocketID:    s.ID,
					Evidence:    ev,
				})
			}
		}

		if s.Inode != nil && len(s.OwnerPIDs) == 0 {
			add(RuleOwnerUnresolved, model.Finding{
				Summary:     fmt.Sprintf("No visible process owns %s", displaySocket(s)),
				Explanation: "The socket inode could not be associated with a process visible to this user. This is common without elevated privileges, when a process has exited, or when procfs visibility is restricted.",
				Limitations: "An unresolved owner is a visibility limitation, not evidence of malicious activity. The owning process may exist but be hidden by permissions, hidepid, or namespace boundaries.",
				Remediation: "Re-run with elevated privileges only if policy allows and greater visibility is required. Do not treat this finding as a security verdict.",
				SocketID:    s.ID,
				Evidence:    ev,
			})
		}

		if s.Protocol == model.ProtocolUnix && s.UnixPath != "" &&
			!strings.HasPrefix(s.UnixPath, "@") &&
			s.UnixMetaAvailable != nil && !*s.UnixMetaAvailable {
			detail := s.UnixMetaError
			if detail == "" {
				detail = "metadata unavailable"
			}
			ev.Detail = detail
			add(RuleUnixMeta, model.Finding{
				Summary:     fmt.Sprintf("Filesystem metadata unavailable for %s", s.UnixPath),
				Explanation: "The Unix socket has a filesystem pathname, but SockHound could not read its file metadata. The kernel socket record is still valid.",
				Limitations: "This is a filesystem visibility limitation. It does not change the socket's kernel state or imply that the path is unsafe.",
				Remediation: "Check path permissions and whether the socket file still exists. Use elevated privileges only if policy allows.",
				SocketID:    s.ID,
				Evidence:    ev,
			})
		}

		if s.Protocol.IsTCP() && s.State == "UNKNOWN" {
			add(RuleUnknownState, model.Finding{
				Summary:     fmt.Sprintf("Unknown TCP state on %s", s.Endpoint()),
				Explanation: "The procfs state code could not be mapped to a known TCP state. The record was preserved rather than discarded.",
				Limitations: "A newer kernel may report a state code this version does not know. The socket's other fields are still shown as collected.",
				Remediation: "Update SockHound if this persists. No action on the socket is implied.",
				SocketID:    s.ID,
				Evidence:    ev,
			})
		}
	}

	if snap.Stats.ProcessesInaccessible > 0 || snap.Stats.FDsUnreadable > 0 {
		ev := model.Evidence{
			Detail: fmt.Sprintf("%d process directories and %d file descriptors were inaccessible",
				snap.Stats.ProcessesInaccessible, snap.Stats.FDsUnreadable),
		}
		add(RulePartialScope, model.Finding{
			Summary:     "Process ownership visibility is partial",
			Explanation: "Some process directories or file descriptors could not be read while resolving socket owners. Some sockets may show an unknown owner even though a process owns them.",
			Limitations: "Visibility depends on UID boundaries, procfs hidepid settings and security policy. Run without root is expected to be partial on multi-user systems.",
			Remediation: "Use the scan summary to judge whether unknown owners matter for your review. Elevated privileges may improve visibility but are not required.",
			Evidence:    ev,
		})
	}

	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return a.SocketID < b.SocketID
	})
	if findings == nil {
		findings = []model.Finding{}
	}
	return findings
}

// CountBySeverity returns counts for every severity, including zero values.
func CountBySeverity(findings []model.Finding) map[string]int {
	counts := map[string]int{
		string(model.SeverityHigh):   0,
		string(model.SeverityMedium): 0,
		string(model.SeverityLow):    0,
		string(model.SeverityInfo):   0,
	}
	for _, f := range findings {
		counts[string(f.Severity)]++
	}
	return counts
}

func evidenceFor(s model.Socket) model.Evidence {
	ev := model.Evidence{
		Protocol:       string(s.Protocol),
		LocalEndpoint:  s.Endpoint(),
		RemoteEndpoint: s.RemoteEndpoint(),
		State:          s.State,
		BindScope:      string(s.BindScope),
		Inode:          s.Inode,
		Process:        strings.Join(s.OwnerNames, ", "),
		User:           strings.Join(s.OwnerUsers, ", "),
	}
	if len(s.OwnerPIDs) > 0 {
		pid := s.OwnerPIDs[0]
		ev.PID = &pid
	}
	return ev
}

func displaySocket(s model.Socket) string {
	if s.Protocol == model.ProtocolUnix {
		if s.UnixPath == "" {
			return fmt.Sprintf("unix socket (inode %d)", derefInode(s.Inode))
		}
		return s.UnixPath
	}
	return fmt.Sprintf("%s %s", s.Protocol, s.Endpoint())
}

func derefInode(inode *uint64) uint64 {
	if inode == nil {
		return 0
	}
	return *inode
}

func appendNote(existing, note string) string {
	if existing == "" {
		return note
	}
	return existing + " " + note
}
