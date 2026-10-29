// Package model contains the normalized data types shared by the collector,
// analysis, output and TUI packages.
package model

import (
	"strings"
	"time"
)

// SchemaVersion is the version of the JSON snapshot schema.
const SchemaVersion = 1

// Protocol identifies the procfs table a socket record came from.
type Protocol string

const (
	ProtocolTCP  Protocol = "tcp"
	ProtocolTCP6 Protocol = "tcp6"
	ProtocolUDP  Protocol = "udp"
	ProtocolUDP6 Protocol = "udp6"
	ProtocolUnix Protocol = "unix"
)

// IsIP reports whether the protocol uses IP endpoints.
func (p Protocol) IsIP() bool { return p != ProtocolUnix }

// IsTCP reports whether the protocol is TCP or TCP6.
func (p Protocol) IsTCP() bool { return p == ProtocolTCP || p == ProtocolTCP6 }

// IsUDP reports whether the protocol is UDP or UDP6.
func (p Protocol) IsUDP() bool { return p == ProtocolUDP || p == ProtocolUDP6 }

// Family identifies the address family of a socket.
type Family string

const (
	FamilyIPv4 Family = "ipv4"
	FamilyIPv6 Family = "ipv6"
	FamilyUnix Family = "unix"
)

// BindScope describes the local bind address in neutral terms. It does not
// imply external reachability.
type BindScope string

const (
	BindScopeLoopback      BindScope = "loopback"
	BindScopeWildcard      BindScope = "wildcard"
	BindScopeSpecific      BindScope = "specific"
	BindScopeNotApplicable BindScope = "not-applicable"
	BindScopeUnknown       BindScope = "unknown"
)

// Severity is a finding severity. The textual label is always rendered next
// to the value so that color is never the only signal.
type Severity string

const (
	SeverityInfo   Severity = "INFO"
	SeverityLow    Severity = "LOW"
	SeverityMedium Severity = "MEDIUM"
	SeverityHigh   Severity = "HIGH"
)

// Rank returns a sortable rank for a severity (higher is more severe).
func (s Severity) Rank() int {
	switch s {
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// Socket is a normalized socket record.
//
// Optional values use pointers or explicit validity flags so that zero values
// are never overloaded to mean "unknown".
type Socket struct {
	ID       string   `json:"id"`
	Protocol Protocol `json:"protocol"`
	Family   Family   `json:"family"`

	LocalAddress  string `json:"local_address,omitempty"`
	LocalPort     *int   `json:"local_port"`
	RemoteAddress string `json:"remote_address,omitempty"`
	RemotePort    *int   `json:"remote_port"`

	State     string  `json:"state,omitempty"`
	Inode     *uint64 `json:"inode"`
	SocketUID *int    `json:"socket_uid,omitempty"`

	UnixPath  string `json:"unix_path,omitempty"`
	UnixType  string `json:"unix_type,omitempty"`
	UnixFlags string `json:"unix_flags,omitempty"`
	UnixState string `json:"unix_state,omitempty"`

	// Unix metadata is separate from kernel socket metadata.
	UnixMetaAvailable *bool  `json:"unix_meta_available,omitempty"`
	UnixMode          string `json:"unix_mode,omitempty"`
	UnixOwner         string `json:"unix_owner,omitempty"`
	UnixMetaError     string `json:"unix_meta_error,omitempty"`

	OwnerPIDs  []int    `json:"owner_pids"`
	OwnerNames []string `json:"owner_names"`
	OwnerUIDs  []int    `json:"owner_uids"`
	OwnerUsers []string `json:"owner_users"`

	IsListening bool      `json:"is_listening"`
	BindScope   BindScope `json:"bind_scope"`

	CollectedAt     time.Time `json:"collected_at"`
	CollectionNotes []string  `json:"collection_notes,omitempty"`

	// RawLocal and RawRemote preserve the original procfs endpoint strings for
	// troubleshooting. They are intentionally not part of the JSON schema.
	RawLocal  string `json:"-"`
	RawRemote string `json:"-"`
}

// Endpoint renders the local endpoint for display.
func (s Socket) Endpoint() string {
	if s.Protocol == ProtocolUnix {
		return s.UnixPath
	}
	return JoinEndpoint(s.LocalAddress, s.LocalPort)
}

// RemoteEndpoint renders the remote endpoint for display.
func (s Socket) RemoteEndpoint() string {
	if s.Protocol == ProtocolUnix {
		return ""
	}
	if s.RemoteAddress == "" {
		return ""
	}
	return JoinEndpoint(s.RemoteAddress, s.RemotePort)
}

// JoinEndpoint formats an address and optional port. IPv6 addresses are
// bracketed so the port is unambiguous.
func JoinEndpoint(addr string, port *int) string {
	if addr == "" {
		return ""
	}
	if port == nil {
		return addr
	}
	host := addr
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return host + ":" + itoa(*port)
}

// Process is a process with visible sockets.
type Process struct {
	PID       int      `json:"pid"`
	Name      string   `json:"name"`
	Cmdline   string   `json:"cmdline,omitempty"`
	UID       *int     `json:"uid"`
	User      string   `json:"user,omitempty"`
	SocketIDs []string `json:"socket_ids"`
	Sockets   int      `json:"sockets"`
	Listeners int      `json:"listeners"`
}

// Evidence captures the exact data a finding was based on.
type Evidence struct {
	Protocol       string  `json:"protocol,omitempty"`
	LocalEndpoint  string  `json:"local_endpoint,omitempty"`
	RemoteEndpoint string  `json:"remote_endpoint,omitempty"`
	State          string  `json:"state,omitempty"`
	BindScope      string  `json:"bind_scope,omitempty"`
	Inode          *uint64 `json:"inode"`
	PID            *int    `json:"pid"`
	Process        string  `json:"process,omitempty"`
	User           string  `json:"user,omitempty"`
	Detail         string  `json:"detail,omitempty"`
}

// Finding is an evidence-backed, explainable observation.
type Finding struct {
	RuleID           string    `json:"rule_id"`
	RuleName         string    `json:"rule_name"`
	Severity         Severity  `json:"severity"`
	Summary          string    `json:"summary"`
	Explanation      string    `json:"explanation"`
	Limitations      string    `json:"limitations,omitempty"`
	Remediation      string    `json:"remediation,omitempty"`
	SocketID         string    `json:"socket_id,omitempty"`
	Evidence         Evidence  `json:"evidence"`
	SeverityOverride bool      `json:"severity_overridden,omitempty"`
	CollectedAt      time.Time `json:"collected_at"`
}

// Stats contains aggregate counters for a snapshot.
type Stats struct {
	TotalSockets     int            `json:"total_sockets"`
	TCP              int            `json:"tcp"`
	UDP              int            `json:"udp"`
	Unix             int            `json:"unix"`
	Listeners        int            `json:"listeners"`
	UnresolvedOwners int            `json:"unresolved_owners"`
	TCPStates        map[string]int `json:"tcp_states"`
	Severities       map[string]int `json:"finding_severities"`

	ProcessesScanned      int `json:"processes_scanned"`
	ProcessesInaccessible int `json:"processes_inaccessible"`
	FDsScanned            int `json:"fds_scanned"`
	FDsUnreadable         int `json:"fds_unreadable"`
}

// Visibility describes how complete a snapshot is.
type Visibility struct {
	Partial               bool     `json:"partial"`
	Warnings              []string `json:"warnings"`
	ProcessesInaccessible int      `json:"processes_inaccessible"`
	FDsUnreadable         int      `json:"fds_unreadable"`
}

// Snapshot is an immutable point-in-time view of local sockets.
type Snapshot struct {
	SchemaVersion    int        `json:"schema_version"`
	ToolVersion      string     `json:"tool_version"`
	CollectedAt      time.Time  `json:"collected_at"`
	DurationMS       int64      `json:"duration_ms"`
	NetworkNamespace string     `json:"network_namespace,omitempty"`
	Scope            string     `json:"scope"`
	Visibility       Visibility `json:"visibility"`
	Stats            Stats      `json:"stats"`
	Sockets          []Socket   `json:"sockets"`
	Processes        []Process  `json:"processes"`
	Findings         []Finding  `json:"findings"`
}

// itoa avoids importing strconv in a hot display helper.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
