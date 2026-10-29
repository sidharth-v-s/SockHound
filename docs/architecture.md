# Architecture

SockHound is a single-process, read-only inspector. Collection produces one immutable snapshot; rendering and analysis never re-read procfs.

## Data flow

```text
/proc/net/{tcp,tcp6,udp,udp6,unix}
        │
        ▼
internal/procfs        parse records, decode endpoints, normalize states
        │
        ▼
internal/scanner       assign snapshot IDs, sort, coordinate enrichment
        │
        ├──► internal/process   /proc/PID/fd inode → PID/owner metadata
        ├──► Unix path stat     filesystem metadata kept separate
        ├──► internal/analysis  evidence-backed findings
        └──► stats/visibility   counts, warnings, partial flag
        │
        ▼
internal/output        text or versioned JSON
internal/tui           Bubble Tea dashboard over the same snapshot
```

The TUI receives a `Scan` function in `tui.Options`. Rendering only reads the in-memory snapshot; a refresh runs a new scan in a command and replaces the snapshot when it completes. Tests inject fixture snapshots and scan functions, so the UI never depends on live procfs.

## Packages

| Package | Responsibility |
| --- | --- |
| `cmd/sockhound` | Calls `app.Run` and exits with its code |
| `internal/app` | Argument parsing, mode dispatch, filter composition, exit codes |
| `internal/scanner` | Orchestrates collection, ownership, Unix metadata, rules and stats |
| `internal/procfs` | Pure parsers plus the procfs collector |
| `internal/process` | Single-pass `/proc/PID/fd` walk and process metadata |
| `internal/analysis` | Rule catalog and finding construction |
| `internal/filter` | ANDed query parser and matchers shared by CLI and TUI |
| `internal/model` | Typed snapshot/socket/process/finding models and JSON tags |
| `internal/output` | Plain-text summary, JSON encoding and safe file export |
| `internal/tui` | Bubble Tea model, update loop, layout, tables, details, styles |
| `internal/config` | Strict JSON configuration loading and rule overrides |
| `internal/version` | Build-time version string |

## Collection

`procfs.Collector` reads the five tables in a fixed order and appends parser warnings rather than failing the whole scan. A table that cannot be opened becomes a warning; collection fails only when every source fails. A malformed line is a warning and the line is skipped.

### Endpoint decoding

- IPv4 endpoints are one 32-bit word printed in host (little-endian) byte order.
- IPv6 endpoints are four 32-bit words, each printed in host byte order. The parser reverses each four-byte group before formatting with `net.IP.String()`.
- Ports are hexadecimal. A remote port of zero means no peer was recorded, so the remote address and port are cleared.
- IPv6 display endpoints are bracketed when a port is present so the port is unambiguous.

### States

TCP state codes map to `ESTABLISHED`, `SYN_SENT`, `SYN_RECV`, `FIN_WAIT1`, `FIN_WAIT2`, `TIME_WAIT`, `CLOSE`, `CLOSE_WAIT`, `LAST_ACK`, `LISTEN`, `CLOSING`, `NEW_SYN_RECV`, or `UNKNOWN`.

UDP uses `UNCONN` for bound/unconnected records and `CONNECTED` for connected records. UDP sockets are never marked `is_listening`; only TCP `LISTEN` records are listeners.

Unix state codes map to `UNCONNECTED`, `CONNECTING`, `CONNECTED`, `DISCONNECTING`, or `UNKNOWN`. Unix type codes map to `STREAM`, `DGRAM`, `SEQPACKET`, or `TYPE_<code>`.

### Unix paths

The pathname is the last field in `/proc/net/unix` and may contain spaces. The parser locates the first seven whitespace-delimited fields sequentially, then preserves the remainder as the pathname. Abstract names (often presented with a leading `@`) are kept as socket names, not treated as filesystem paths.

## Identity and sorting

Socket IDs are stable only within a snapshot. They are built from the protocol and inode, for example `tcp:12345`. If an inode is missing, an index-based anonymous ID is used; duplicate bases receive a `#N` suffix.

Sockets are sorted by protocol (TCP, TCP6, UDP, UDP6, Unix), then local address/path and port, then inode. The TUI applies its own view-level sort without mutating the snapshot.

## Ownership resolution

`process.Resolve` makes one pass over numeric `/proc/PID` directories:

1. Open `/proc/PID/fd`. A missing directory usually means the process exited; it is skipped. Other errors increment the inaccessible-process counter.
2. `readlink` each descriptor. Missing entries are treated as churn; other errors increment the unreadable-descriptor counter.
3. Parse `socket:[inode]` links and keep only inodes present in the socket snapshot.
4. Read `comm`, `status` (UID) and `cmdline` only for processes that own at least one wanted socket.
5. Build an inode → owners map and a process → inode map.

Multiple PIDs can own the same socket (inherited or shared descriptors). Owner lists are deduplicated and sorted by PID.

### Command-line redaction

Unless `reveal_cmdline` is enabled, `argv[0]` is kept and all following arguments are replaced with `[N args hidden]`. This is the default because arguments may contain credentials or tokens. Process names fall back to the basename of `argv[0]`, then `?`.

### Races and visibility

The resolver tolerates processes disappearing between listing, opening `fd`, and reading metadata. It does not retry aggressively; a scan is a point-in-time view. Warnings are recorded when process directories or descriptors were inaccessible.

## Unix metadata

For Unix sockets with a non-abstract filesystem path, SockHound attempts `stat` and stores mode and owner separately from kernel socket fields. Failure sets `unix_meta_available` to false and records an error string; `SH-UNIX-001` may then report it. Kernel state and filesystem metadata are never conflated.

## Analysis

`analysis.Analyze` runs after collection and enrichment. Each rule receives a copy of the socket's evidence fields. Findings are sorted by severity, rule ID and socket ID. Every rule can be disabled or have its severity overridden by configuration; overrides are marked on the finding.

Rules are heuristics and must state their limitations. In particular, wildcard binding is not treated as proof of external reachability, and an unresolved owner is treated as a visibility limitation rather than malicious behavior.

## Visibility and exit codes

A snapshot is partial when any collection warning exists, any process directory was inaccessible, any descriptor was unreadable, or Unix metadata was unavailable. The scanner records:

- `visibility.partial`
- `visibility.warnings`
- `visibility.processes_inaccessible`
- `visibility.fds_unreadable`
- corresponding counters in `stats`

The CLI writes the report first, then returns `3` if the snapshot is partial. Collection failure returns `2`; usage/configuration errors return `1`; a fully accessible scan returns `0`.

## Filtering

`filter.Parse` turns a whitespace-separated query into terms. Terms are ANDed. Numeric terms (`pid`, `port`, `inode`) produce an error for invalid values; unknown `key:value` tokens fall back to substring matching so free-text searches remain useful.

The CLI applies the query to sockets, findings and processes after collection, then recomputes stats. The TUI applies the same matcher during rebuilds, so both interfaces agree on filter semantics.

## Output

- `output.WriteText` renders a bounded plain-text table, finding counts, warnings and a privacy note. Control characters are sanitized.
- `output.WriteJSON` emits indented JSON with `schema_version`.
- `output.WriteFile` writes to a temporary file in the destination directory and renames it. It checks for an existing path before and after writing; overwrite requires `force`.

The TUI's export dialog uses the same `WriteFile` path and requires a second Enter to overwrite an existing file.

## TUI rendering

The root model owns the snapshot, current tab, filters, table state and overlays (detail, help, export). `View` computes a header, status line, body and footer within the terminal size. Wide terminals show a table plus selected-item panel; narrow terminals show only the table. Below 80×24 the view is replaced with a resize hint.

The Bubbles table requires columns before rows. Row rebuilds are therefore deferred until the first sized render, and tab switches clear stale rows before new columns are installed.
