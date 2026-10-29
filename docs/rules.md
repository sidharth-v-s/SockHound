# Rules and findings

SockHound findings are explainable observations, not vulnerability verdicts. Every finding carries the exact evidence used to produce it, a plain-language explanation, its limitations, and optional review guidance. All rules default to `INFO`.

## Rule catalog

### `SH-WILD-001` — Wildcard-bound TCP listener

**Trigger:** a TCP or TCP6 socket in `LISTEN` state whose local address is `0.0.0.0` or `::`.

**Evidence:** protocol, local endpoint, remote endpoint, state, bind scope, inode, first owner PID, process names and users.

**Interpretation:** the socket accepts connections addressed to any local interface. This does **not** prove internet reachability. Firewall policy, routing, host/container networking and other controls determine exposure, and SockHound does not test external reachability.

**Review guidance:** confirm the service is intended to listen on all interfaces. If not, bind to loopback or a specific address, or restrict access with firewall policy.

### `SH-PORT-001` — Socket on review-listed port

**Trigger:** a TCP listener or a UDP/UDP6 socket whose local port appears in the local `review_ports` list.

**Evidence:** protocol, local endpoint, state, bind scope, inode and owner metadata.

**Interpretation:** the list is user-controlled configuration, not a vulnerability database. A port number alone does not indicate a vulnerability. A bound UDP socket may not be actively used.

**Review guidance:** review the service and its intended exposure, or remove the port from `review_ports` if it does not need attention.

### `SH-OWNER-001` — Owner unresolved

**Trigger:** a socket has an inode but no visible owning process.

**Evidence:** protocol, endpoint/path, state, inode and the owner fields that were available.

**Interpretation:** this is a visibility limitation. Common causes include UID boundaries, `hidepid`, security policy, process exit, descriptor churn, inherited/shared descriptors, or namespace differences. It is not evidence of malicious activity.

**Review guidance:** re-run with elevated privileges only if policy allows and greater visibility is required. Do not treat an unresolved owner as a security verdict.

### `SH-UNIX-001` — Unix socket path metadata unavailable

**Trigger:** a Unix socket has a non-abstract filesystem pathname, but `stat` metadata could not be read.

**Evidence:** the Unix path, state, inode and the metadata error detail.

**Interpretation:** the kernel socket record is still valid; only filesystem metadata is missing. The path may have been removed or may be inaccessible.

**Review guidance:** check path permissions and whether the socket file still exists. Use elevated privileges only if policy allows.

### `SH-SCOPE-001` — Partial process visibility

**Trigger:** at least one process directory or file descriptor was inaccessible during ownership resolution. Emitted once per snapshot.

**Evidence:** counts of inaccessible process directories and unreadable file descriptors.

**Interpretation:** some sockets may show an unknown owner even though a process owns them. Non-root scans on multi-user systems are commonly partial. This finding describes the collection, not a target process.

**Review guidance:** use the scan summary and warnings to judge whether unknown owners matter for the review.

### `SH-STATE-001` — Unexpected/unknown TCP state

**Trigger:** a TCP/TCP6 record whose procfs state code does not map to a known state.

**Evidence:** protocol, endpoint, raw normalized state (`UNKNOWN`), inode and owner metadata.

**Interpretation:** a newer kernel may report a state this version does not know. The record is preserved rather than discarded. No action on the socket is implied.

**Review guidance:** update SockHound if this persists.

## Evidence fields

| Field | Meaning |
| --- | --- |
| `protocol` | `tcp`, `tcp6`, `udp`, `udp6` or `unix` |
| `local_endpoint` | Local address:port, or Unix path |
| `remote_endpoint` | Peer endpoint when recorded |
| `state` | Normalized TCP/UDP/Unix state |
| `bind_scope` | `loopback`, `wildcard`, `specific`, `not-applicable` or `unknown` |
| `inode` | Socket inode when available |
| `pid` | First visible owner PID when available |
| `process` | Visible owner process names |
| `user` | Visible owner usernames |
| `detail` | Extra context, such as a metadata error or visibility counts |

## Severity overrides and disabling rules

Rules can be tuned in the JSON configuration:

```json
{
  "schema_version": 1,
  "review_ports": [22, 8080],
  "rules": {
    "SH-WILD-001": { "enabled": true, "severity": "LOW" },
    "SH-OWNER-001": { "enabled": false },
    "SH-PORT-001": { "severity": "MEDIUM" }
  }
}
```

- `enabled: false` suppresses that rule's findings.
- `severity` accepts `INFO`, `LOW`, `MEDIUM` or `HIGH`.
- A severity override sets `severity_overridden: true` and appends a note to the finding's limitations so the override is visible in reports.
- Unknown rule IDs are accepted by the config loader but have no effect because the rule catalog is fixed. Prefer the IDs listed above.

## Design constraints

- Do not create a finding when the underlying data is too incomplete to support the rule.
- Do not claim a listener is publicly reachable based only on a wildcard bind.
- Do not label a process malicious based on a port number or bind address.
- Keep the evidence tied to the exact endpoint, state and inode used.
- State uncertainty explicitly in the finding's limitations.
- Findings remain informational by default; the CLI exit code is not driven by findings.
