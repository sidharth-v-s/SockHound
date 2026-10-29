// Package filter implements composable, ANDed filters for sockets, processes
// and findings. It is shared by the one-shot CLI and the TUI.
package filter

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/zoro/sockhound/internal/model"
)

// Query is a parsed filter expression. Terms are ANDed.
type Query struct {
	Raw   string
	Terms []Term
	Err   string
}

// Term is one filter predicate.
type Term struct {
	Kind  string
	Value string
	Int   int
}

// Parse parses a space-separated query. Supported forms:
//
//	tcp | tcp6 | udp | udp6 | unix       protocol shorthand
//	proto:tcp, state:LISTEN, pid:123
//	port:8080, addr:127.0.0.1, proc:nginx
//	user:root, inode:123, owner:unknown
//	sev:INFO, listen
//
// Any other token is matched as a case-insensitive substring across the
// record's display fields. Invalid numeric terms simply match nothing.
func Parse(raw string) Query {
	q := Query{Raw: strings.TrimSpace(raw)}
	for _, token := range strings.Fields(q.Raw) {
		lower := strings.ToLower(token)
		kind, value, hasColon := strings.Cut(lower, ":")
		if !hasColon {
			switch lower {
			case "tcp", "tcp6", "udp", "udp6", "unix":
				q.Terms = append(q.Terms, Term{Kind: "protocol", Value: lower})
				continue
			case "listen", "listening":
				q.Terms = append(q.Terms, Term{Kind: "listen", Value: "true"})
				continue
			case "known":
				q.Terms = append(q.Terms, Term{Kind: "owner", Value: "known"})
				continue
			case "unknown":
				q.Terms = append(q.Terms, Term{Kind: "owner", Value: "unknown"})
				continue
			}
			q.Terms = append(q.Terms, Term{Kind: "text", Value: lower})
			continue
		}
		switch kind {
		case "proto", "protocol":
			q.Terms = append(q.Terms, Term{Kind: "protocol", Value: value})
		case "state":
			q.Terms = append(q.Terms, Term{Kind: "state", Value: strings.ToUpper(value)})
		case "pid":
			n, err := strconv.Atoi(value)
			if err != nil {
				q.Err = fmt.Sprintf("invalid pid %q", value)
			}
			q.Terms = append(q.Terms, Term{Kind: "pid", Int: n})
		case "port":
			n, err := strconv.Atoi(value)
			if err != nil {
				q.Err = fmt.Sprintf("invalid port %q", value)
			}
			q.Terms = append(q.Terms, Term{Kind: "port", Int: n})
		case "addr", "address":
			q.Terms = append(q.Terms, Term{Kind: "addr", Value: value})
		case "proc", "process", "name":
			q.Terms = append(q.Terms, Term{Kind: "proc", Value: value})
		case "user":
			q.Terms = append(q.Terms, Term{Kind: "user", Value: value})
		case "inode":
			n, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				q.Err = fmt.Sprintf("invalid inode %q", value)
			}
			q.Terms = append(q.Terms, Term{Kind: "inode", Value: strconv.FormatUint(n, 10)})
		case "owner":
			q.Terms = append(q.Terms, Term{Kind: "owner", Value: value})
		case "sev", "severity":
			q.Terms = append(q.Terms, Term{Kind: "sev", Value: strings.ToUpper(value)})
		default:
			q.Terms = append(q.Terms, Term{Kind: "text", Value: lower})
		}
	}
	return q
}

// MatchSocket reports whether a socket matches every term. findings is used by
// severity terms.
func (q Query) MatchSocket(s model.Socket, findings []model.Finding) bool {
	for _, t := range q.Terms {
		if !matchSocketTerm(t, s, findings) {
			return false
		}
	}
	return true
}

func matchSocketTerm(t Term, s model.Socket, findings []model.Finding) bool {
	switch t.Kind {
	case "protocol":
		return matchProtocol(t.Value, s.Protocol)
	case "state":
		return strings.EqualFold(s.State, t.Value) || strings.EqualFold(s.UnixState, t.Value)
	case "pid":
		for _, pid := range s.OwnerPIDs {
			if pid == t.Int {
				return true
			}
		}
		return false
	case "port":
		return (s.LocalPort != nil && *s.LocalPort == t.Int) || (s.RemotePort != nil && *s.RemotePort == t.Int)
	case "addr":
		return contains(s.LocalAddress, t.Value) || contains(s.RemoteAddress, t.Value) || contains(s.UnixPath, t.Value)
	case "proc":
		return contains(strings.Join(s.OwnerNames, " "), t.Value)
	case "user":
		return contains(strings.Join(s.OwnerUsers, " "), t.Value)
	case "inode":
		return s.Inode != nil && strconv.FormatUint(*s.Inode, 10) == t.Value
	case "owner":
		switch t.Value {
		case "known":
			return len(s.OwnerPIDs) > 0
		case "unknown":
			return len(s.OwnerPIDs) == 0
		default:
			return false
		}
	case "sev":
		for _, f := range findings {
			if f.SocketID == s.ID && strings.EqualFold(string(f.Severity), t.Value) {
				return true
			}
		}
		return false
	case "listen":
		return s.IsListening
	default:
		return contains(socketHaystack(s), t.Value)
	}
}

// MatchFinding reports whether a finding matches every term.
func (q Query) MatchFinding(f model.Finding) bool {
	for _, t := range q.Terms {
		if !matchFindingTerm(t, f) {
			return false
		}
	}
	return true
}

func matchFindingTerm(t Term, f model.Finding) bool {
	switch t.Kind {
	case "protocol":
		return matchProtocol(t.Value, model.Protocol(f.Evidence.Protocol))
	case "state":
		return strings.EqualFold(f.Evidence.State, t.Value)
	case "pid":
		return f.Evidence.PID != nil && *f.Evidence.PID == t.Int
	case "port":
		_, port := splitEndpointPort(f.Evidence.LocalEndpoint)
		return port == t.Int
	case "addr":
		return contains(f.Evidence.LocalEndpoint, t.Value) || contains(f.Evidence.RemoteEndpoint, t.Value)
	case "proc":
		return contains(f.Evidence.Process, t.Value)
	case "user":
		return contains(f.Evidence.User, t.Value)
	case "inode":
		return f.Evidence.Inode != nil && strconv.FormatUint(*f.Evidence.Inode, 10) == t.Value
	case "owner":
		switch t.Value {
		case "unknown":
			return f.Evidence.PID == nil
		case "known":
			return f.Evidence.PID != nil
		default:
			return false
		}
	case "sev":
		return strings.EqualFold(string(f.Severity), t.Value)
	case "listen":
		return strings.EqualFold(f.Evidence.State, "LISTEN")
	default:
		return contains(findingHaystack(f), t.Value)
	}
}

// MatchProcess reports whether a process matches every term. Protocol, port,
// state and inode terms are ignored here because they describe sockets; use
// the process view's name/PID/user filters instead.
func (q Query) MatchProcess(p model.Process) bool {
	for _, t := range q.Terms {
		switch t.Kind {
		case "pid":
			if p.PID != t.Int {
				return false
			}
		case "proc", "text":
			if !contains(p.Name+" "+p.Cmdline+" "+p.User, t.Value) {
				return false
			}
		case "user":
			if !contains(p.User, t.Value) {
				return false
			}
		case "protocol", "state", "port", "addr", "inode", "owner", "sev", "listen":
			// Socket-specific term: no process-level meaning.
		}
	}
	return true
}

func matchProtocol(want string, got model.Protocol) bool {
	switch want {
	case "tcp":
		return got == model.ProtocolTCP || got == model.ProtocolTCP6
	case "udp":
		return got == model.ProtocolUDP || got == model.ProtocolUDP6
	case "tcp6":
		return got == model.ProtocolTCP6
	case "udp6":
		return got == model.ProtocolUDP6
	case "unix":
		return got == model.ProtocolUnix
	case "all", "":
		return true
	default:
		return false
	}
}

func socketHaystack(s model.Socket) string {
	parts := []string{
		string(s.Protocol), string(s.Family), s.LocalAddress, s.RemoteAddress,
		s.State, s.UnixPath, s.UnixType, s.UnixState, s.ID,
		strings.Join(s.OwnerNames, " "), strings.Join(s.OwnerUsers, " "),
	}
	if s.LocalPort != nil {
		parts = append(parts, strconv.Itoa(*s.LocalPort))
	}
	if s.RemotePort != nil {
		parts = append(parts, strconv.Itoa(*s.RemotePort))
	}
	if s.Inode != nil {
		parts = append(parts, strconv.FormatUint(*s.Inode, 10))
	}
	return strings.ToLower(strings.Join(parts, " "))
}

func findingHaystack(f model.Finding) string {
	return strings.ToLower(strings.Join([]string{
		f.RuleID, f.RuleName, string(f.Severity), f.Summary, f.Explanation,
		f.Evidence.Protocol, f.Evidence.LocalEndpoint, f.Evidence.RemoteEndpoint,
		f.Evidence.State, f.Evidence.Process, f.Evidence.User, f.Evidence.Detail,
	}, " "))
}

func contains(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

func splitEndpointPort(endpoint string) (string, int) {
	i := strings.LastIndex(endpoint, ":")
	if i < 0 {
		return endpoint, -1
	}
	port, err := strconv.Atoi(endpoint[i+1:])
	if err != nil {
		return endpoint, -1
	}
	return endpoint[:i], port
}
