# JSON schema, version 1

`sockhound scan --json` writes one JSON object with `schema_version: 1`. The format is intended for scripts and later analysis; field names are stable within a schema version, and breaking changes require a new version.

Optional numeric values are `null` when unknown. They are not overloaded with `0`, and optional strings are omitted rather than using an empty sentinel. Timestamps are RFC 3339 strings.

## Top level

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | integer | JSON schema version; currently `1` |
| `tool_version` | string | SockHound build version |
| `collected_at` | timestamp | Snapshot collection start |
| `duration_ms` | integer | Collection duration in milliseconds |
| `network_namespace` | string, optional | Current network namespace identifier when readable |
| `scope` | string | Human-readable collection scope |
| `visibility` | object | Partial-visibility status and warnings |
| `stats` | object | Aggregate counts |
| `sockets` | array | Normalized socket records |
| `processes` | array | Processes with at least one visible socket |
| `findings` | array | Evidence-backed rule results |

Example skeleton:

```json
{
  "schema_version": 1,
  "tool_version": "0.1.0-dev",
  "collected_at": "2026-10-29T12:00:00Z",
  "duration_ms": 8,
  "network_namespace": "net:[4026531833]",
  "scope": "current network namespace net:[4026531833]",
  "visibility": {
    "partial": true,
    "warnings": ["process visibility limited: 12 process directories could not be read (permissions or races)"],
    "processes_inaccessible": 12,
    "fds_unreadable": 4
  },
  "stats": {},
  "sockets": [],
  "processes": [],
  "findings": []
}
```

## Socket record

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | string | Snapshot-local identifier, for example `tcp:12345`; not stable across scans |
| `protocol` | string | `tcp`, `tcp6`, `udp`, `udp6` or `unix` |
| `family` | string | `ipv4`, `ipv6` or `unix` |
| `local_address` | string, optional | Local IP address |
| `local_port` | integer or null | Local port |
| `remote_address` | string, optional | Peer IP address when recorded |
| `remote_port` | integer or null | Peer port |
| `state` | string, optional | Normalized TCP/UDP/Unix state |
| `inode` | integer or null | Socket inode |
| `socket_uid` | integer, optional | UID reported by the procfs socket table |
| `unix_path` | string, optional | Unix pathname or abstract name |
| `unix_type` | string, optional | `STREAM`, `DGRAM`, `SEQPACKET` or `TYPE_<code>` |
| `unix_flags` | string, optional | Raw Unix flags field from procfs |
| `unix_state` | string, optional | Unix state (also reflected in `state`) |
| `unix_meta_available` | boolean, optional | Whether filesystem metadata was read |
| `unix_mode` | string, optional | Filesystem mode when available |
| `unix_owner` | string, optional | Filesystem owner when available |
| `unix_meta_error` | string, optional | Why metadata was unavailable |
| `owner_pids` | array of integers | Visible owner PIDs |
| `owner_names` | array of strings | Visible owner process names |
| `owner_uids` | array of integers | Visible owner UIDs |
| `owner_users` | array of strings | Visible owner usernames |
| `is_listening` | boolean | True only for TCP `LISTEN` records |
| `bind_scope` | string | `loopback`, `wildcard`, `specific`, `not-applicable` or `unknown` |
| `collected_at` | timestamp | Socket record time |
| `collection_notes` | array of strings, optional | Per-socket notes |

Raw procfs endpoint strings are retained internally for troubleshooting but are intentionally excluded from JSON.

## Process record

| Field | Type | Meaning |
| --- | --- | --- |
| `pid` | integer | Process ID |
| `name` | string | Process name from `comm`, or a fallback |
| `cmdline` | string, optional | `argv0 [N args hidden]` by default; full command line only with `reveal_cmdline` |
| `uid` | integer or null | Process UID |
| `user` | string, optional | Resolved username |
| `socket_ids` | array of strings | Snapshot socket IDs owned by the process |
| `sockets` | integer | Number of owned sockets in this snapshot |
| `listeners` | integer | Number of owned TCP listeners |

Only processes with at least one visible socket are included. Processes that could not be inspected are represented by counters and warnings, not invented records.

## Finding record

| Field | Type | Meaning |
| --- | --- | --- |
| `rule_id` | string | Stable rule identifier |
| `rule_name` | string | Human-readable rule name |
| `severity` | string | `INFO`, `LOW`, `MEDIUM` or `HIGH` |
| `summary` | string | One-line observation |
| `explanation` | string | Why the rule fired |
| `limitations` | string, optional | Context needed to interpret the finding |
| `remediation` | string, optional | Review guidance, not an automatic fix |
| `socket_id` | string, optional | Related socket; omitted for snapshot-level findings |
| `evidence` | object | Exact data used by the rule |
| `severity_overridden` | boolean, optional | True when local configuration changed the severity |
| `collected_at` | timestamp | Snapshot time |

### Evidence

| Field | Type | Meaning |
| --- | --- | --- |
| `protocol` | string, optional | Protocol from the socket record |
| `local_endpoint` | string, optional | Local endpoint or Unix path |
| `remote_endpoint` | string, optional | Peer endpoint |
| `state` | string, optional | State used by the rule |
| `bind_scope` | string, optional | Bind classification |
| `inode` | integer or null | Socket inode |
| `pid` | integer or null | First visible owner PID |
| `process` | string, optional | Visible owner names |
| `user` | string, optional | Visible owner usernames |
| `detail` | string, optional | Extra context, such as metadata errors or visibility counts |

## Stats

| Field | Type | Meaning |
| --- | --- | --- |
| `total_sockets` | integer | Total socket records |
| `tcp` | integer | TCP + TCP6 records |
| `udp` | integer | UDP + UDP6 records |
| `unix` | integer | Unix-domain records |
| `listeners` | integer | TCP `LISTEN` records |
| `unresolved_owners` | integer | Sockets with an inode but no visible owner |
| `tcp_states` | object | State name → count |
| `finding_severities` | object | `HIGH`/`MEDIUM`/`LOW`/`INFO` → count, including zeros |
| `processes_scanned` | integer | Process directories whose `fd` directory was readable |
| `processes_inaccessible` | integer | Process directories that could not be read |
| `fds_scanned` | integer | File descriptors examined |
| `fds_unreadable` | integer | File descriptors that could not be resolved |

## Visibility

| Field | Type | Meaning |
| --- | --- | --- |
| `partial` | boolean | True when any warning or visibility limit exists |
| `warnings` | array of strings | Human-readable collection warnings |
| `processes_inaccessible` | integer | Inaccessible process directories |
| `fds_unreadable` | integer | Unreadable file descriptors |

A report is still valid when `partial` is true. The CLI returns exit code `3` after writing it.

## Schema evolution

- Additive optional fields may be added within version 1.
- Removing fields, changing meanings, or changing types requires a new `schema_version`.
- Consumers should check `schema_version` before interpreting a report.
- The report is a point-in-time view; IDs are not promised to remain stable across scans.
