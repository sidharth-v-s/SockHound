// Package procfs parses Linux procfs network tables into normalized socket
// records. Parsing is pure: callers supply an io.Reader, which keeps tests
// independent of live system state.
package procfs

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/zoro/sockhound/internal/model"
)

// TCPStates maps Linux TCP state codes to names.
var TCPStates = map[string]string{
	"01": "ESTABLISHED",
	"02": "SYN_SENT",
	"03": "SYN_RECV",
	"04": "FIN_WAIT1",
	"05": "FIN_WAIT2",
	"06": "TIME_WAIT",
	"07": "CLOSE",
	"08": "CLOSE_WAIT",
	"09": "LAST_ACK",
	"0A": "LISTEN",
	"0B": "CLOSING",
	"0C": "NEW_SYN_RECV",
}

// UDPStates maps the small set of states reported for UDP sockets. A bound but
// unconnected UDP socket is not a TCP-style listener.
var UDPStates = map[string]string{
	"07": "UNCONN",
	"01": "CONNECTED",
}

// TCPStateName maps a procfs TCP state code to a normalized name.
func TCPStateName(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if name, ok := TCPStates[code]; ok {
		return name
	}
	return "UNKNOWN"
}

// UDPStateName maps a procfs UDP state code to a normalized name.
func UDPStateName(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if name, ok := UDPStates[code]; ok {
		return name
	}
	return "UNKNOWN"
}

// ParseEndpoint decodes a procfs "HEXADDR:HEXPORT" endpoint.
//
// IPv4 addresses are stored as one little-endian 32-bit word. IPv6 addresses
// are stored as four little-endian 32-bit words. The returned port is nil only
// when the raw port is malformed, which is reported as an error.
func ParseEndpoint(raw string, family model.Family) (string, *int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil, fmt.Errorf("empty endpoint")
	}
	addrHex, portHex, ok := strings.Cut(raw, ":")
	if !ok || addrHex == "" || portHex == "" {
		return "", nil, fmt.Errorf("endpoint %q is missing address or port", raw)
	}

	port64, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return "", nil, fmt.Errorf("invalid port %q: %w", portHex, err)
	}
	port := int(port64)

	ip, err := decodeAddress(addrHex, family)
	if err != nil {
		return "", nil, err
	}
	return ip, &port, nil
}

func decodeAddress(addrHex string, family model.Family) (string, error) {
	switch family {
	case model.FamilyIPv4:
		if len(addrHex) != 8 {
			return "", fmt.Errorf("IPv4 address %q must be 8 hex characters", addrHex)
		}
		word, err := strconv.ParseUint(addrHex, 16, 32)
		if err != nil {
			return "", fmt.Errorf("invalid IPv4 address %q: %w", addrHex, err)
		}
		// procfs prints the 32-bit word in host (little-endian) byte order.
		ip := net.IPv4(byte(word), byte(word>>8), byte(word>>16), byte(word>>24))
		return ip.String(), nil

	case model.FamilyIPv6:
		if len(addrHex) != 32 {
			return "", fmt.Errorf("IPv6 address %q must be 32 hex characters", addrHex)
		}
		raw, err := hex.DecodeString(addrHex)
		if err != nil {
			return "", fmt.Errorf("invalid IPv6 address %q: %w", addrHex, err)
		}
		// Four 32-bit words, each printed in host (little-endian) byte order.
		out := make(net.IP, net.IPv6len)
		for word := 0; word < 4; word++ {
			base := word * 4
			out[base+0] = raw[base+3]
			out[base+1] = raw[base+2]
			out[base+2] = raw[base+1]
			out[base+3] = raw[base+0]
		}
		return out.String(), nil

	default:
		return "", fmt.Errorf("unsupported address family %q", family)
	}
}

// BindScope classifies a local address without making reachability claims.
func BindScope(addr string) model.BindScope {
	ip := net.ParseIP(strings.Trim(addr, "[]"))
	if ip == nil {
		return model.BindScopeUnknown
	}
	if ip.IsUnspecified() {
		return model.BindScopeWildcard
	}
	if ip.IsLoopback() {
		return model.BindScopeLoopback
	}
	return model.BindScopeSpecific
}

// ParseTCPTable parses /proc/net/tcp or /proc/net/tcp6.
func ParseTCPTable(r io.Reader, protocol model.Protocol, collectedAt time.Time) ([]model.Socket, []string, error) {
	return parseIPTables(r, protocol, collectedAt, true)
}

// ParseUDPTable parses /proc/net/udp or /proc/net/udp6.
func ParseUDPTable(r io.Reader, protocol model.Protocol, collectedAt time.Time) ([]model.Socket, []string, error) {
	return parseIPTables(r, protocol, collectedAt, false)
}

func parseIPTables(r io.Reader, protocol model.Protocol, collectedAt time.Time, tcp bool) ([]model.Socket, []string, error) {
	if !protocol.IsIP() {
		return nil, nil, fmt.Errorf("protocol %q is not an IP protocol", protocol)
	}
	family := model.FamilyIPv4
	if protocol == model.ProtocolTCP6 || protocol == model.ProtocolUDP6 {
		family = model.FamilyIPv6
	}

	var (
		sockets  []model.Socket
		warnings []string
		lineNo   int
	)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || lineNo == 1 || strings.HasPrefix(strings.ToLower(line), "sl ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			warnings = append(warnings, fmt.Sprintf("%s line %d: expected at least 10 fields, got %d", protocol, lineNo, len(fields)))
			continue
		}

		localAddr, localPort, err := ParseEndpoint(fields[1], family)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s line %d: local endpoint: %v", protocol, lineNo, err))
			continue
		}
		remoteAddr, remotePort, err := ParseEndpoint(fields[2], family)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s line %d: remote endpoint: %v", protocol, lineNo, err))
			continue
		}
		// A zero remote port means no peer is recorded.
		if remotePort != nil && *remotePort == 0 {
			remoteAddr = ""
			remotePort = nil
		}

		state := "UNKNOWN"
		if tcp {
			state = TCPStateName(fields[3])
		} else {
			state = UDPStateName(fields[3])
		}

		socket := model.Socket{
			Protocol:      protocol,
			Family:        family,
			LocalAddress:  localAddr,
			LocalPort:     localPort,
			RemoteAddress: remoteAddr,
			RemotePort:    remotePort,
			State:         state,
			IsListening:   tcp && state == "LISTEN",
			BindScope:     BindScope(localAddr),
			CollectedAt:   collectedAt,
			RawLocal:      fields[1],
			RawRemote:     fields[2],
			OwnerPIDs:     []int{},
			OwnerNames:    []string{},
			OwnerUIDs:     []int{},
			OwnerUsers:    []string{},
		}

		if uid, err := strconv.Atoi(fields[7]); err == nil {
			socket.SocketUID = &uid
		} else {
			warnings = append(warnings, fmt.Sprintf("%s line %d: invalid uid %q", protocol, lineNo, fields[7]))
		}
		if inode, ok := parseInode(fields[9]); ok {
			socket.Inode = inode
		}

		sockets = append(sockets, socket)
	}
	if err := sc.Err(); err != nil {
		return sockets, warnings, fmt.Errorf("reading %s table: %w", protocol, err)
	}
	return sockets, warnings, nil
}

// ParseUnixTable parses /proc/net/unix.
func ParseUnixTable(r io.Reader, collectedAt time.Time) ([]model.Socket, []string, error) {
	var (
		sockets  []model.Socket
		warnings []string
		lineNo   int
	)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(strings.ToLower(line), "num ") {
			continue
		}
		// The pathname is the final field and may contain spaces, so locate the
		// first seven whitespace-delimited fields sequentially and preserve
		// the remaining text exactly.
		fields := strings.Fields(line)
		if len(fields) < 7 {
			warnings = append(warnings, fmt.Sprintf("unix line %d: expected at least 7 fields, got %d", lineNo, len(fields)))
			continue
		}
		pos := 0
		okFields := true
		for i := 0; i < 7; i++ {
			idx := strings.Index(line[pos:], fields[i])
			if idx < 0 {
				okFields = false
				break
			}
			pos += idx + len(fields[i])
		}
		if !okFields {
			warnings = append(warnings, fmt.Sprintf("unix line %d: malformed record", lineNo))
			continue
		}
		path := strings.TrimSpace(line[pos:])

		inode, ok := parseInode(fields[6])
		if !ok {
			warnings = append(warnings, fmt.Sprintf("unix line %d: invalid inode %q", lineNo, fields[6]))
			continue
		}

		state := unixStateName(fields[5])
		socket := model.Socket{
			Protocol:    model.ProtocolUnix,
			Family:      model.FamilyUnix,
			State:       state,
			UnixState:   state,
			UnixPath:    path,
			UnixType:    unixTypeName(fields[4]),
			UnixFlags:   fields[3],
			Inode:       inode,
			BindScope:   model.BindScopeNotApplicable,
			CollectedAt: collectedAt,
			OwnerPIDs:   []int{},
			OwnerNames:  []string{},
			OwnerUIDs:   []int{},
			OwnerUsers:  []string{},
		}
		sockets = append(sockets, socket)
	}
	if err := sc.Err(); err != nil {
		return sockets, warnings, fmt.Errorf("reading unix table: %w", err)
	}
	return sockets, warnings, nil
}

func unixTypeName(code string) string {
	switch strings.ToUpper(code) {
	case "0001":
		return "STREAM"
	case "0002":
		return "DGRAM"
	case "0005":
		return "SEQPACKET"
	default:
		return "TYPE_" + strings.ToUpper(code)
	}
}

func unixStateName(code string) string {
	switch strings.ToUpper(code) {
	case "01":
		return "UNCONNECTED"
	case "02":
		return "CONNECTING"
	case "03":
		return "CONNECTED"
	case "04":
		return "DISCONNECTING"
	default:
		return "UNKNOWN"
	}
}

func parseInode(raw string) (*uint64, bool) {
	v, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
	if err != nil || v == 0 {
		return nil, false
	}
	return &v, true
}
