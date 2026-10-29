# SockHound — Linux Socket Inspector

SockHound is a read-only Linux socket inspector with a full-screen terminal UI and a scriptable one-shot CLI. It reads the kernel's procfs socket tables, associates socket inodes with processes where permissions allow, and produces evidence-backed findings that are informational by default.

SockHound answers local questions such as:

- Which TCP, UDP and Unix-domain sockets exist in the current network namespace?
- Which process and user own a socket, when that can be determined?
- Which TCP sockets are listening, and are they bound to loopback, a wildcard address, or a specific address?
- Which Unix sockets have filesystem paths, and was their metadata readable?
- What could not be inspected because of permissions or process churn?

SockHound does **not** capture packets, scan remote hosts, close sockets, terminate processes, or modify firewall or network configuration. A wildcard bind is a reason to review a service, not proof that it is reachable from the internet.

## Status

This repository implements the v1 MVP described in [`SOCKHOUND_SPEC.md`](SOCKHOUND_SPEC.md). The JSON schema is versioned (`schema_version: 1`).

## Features

- Dashboard, TCP/UDP, Unix, Processes, Findings and Help views.
- Parsing for `/proc/net/tcp`, `tcp6`, `udp`, `udp6` and `unix`.
- Inode-to-PID resolution through `/proc/PID/fd`, with partial-visibility reporting.
- Owner enrichment from `comm`, `status` and `cmdline`; command-line arguments are redacted by default.
- Composable, ANDed filters shared by the TUI and CLI.
- Six evidence-backed rules: wildcard listener, review-listed port, unresolved owner, unavailable Unix metadata, partial process visibility and unknown TCP state.
- Versioned JSON export to stdout or a file, with overwrite protection.
- Optional automatic refresh at a configurable interval, with overlap protection.
- Responsive TUI with an explicit fallback below 80×24.
- No root requirement; no packet capture, remote scanning or state changes.

## Requirements

- Linux with procfs mounted (normally at `/proc`).
- Go 1.26 or newer to build from source.
- A terminal for the TUI. `sockhound scan` works in scripts and pipes.
- No root privileges required. Running with elevated privileges can improve owner visibility, but SockHound still only reads procfs.

## Build

```bash
go mod tidy
make check          # go fmt, go vet, go test, build
make build
./bin/sockhound version
```

Equivalent raw commands:

```bash
go test ./...
go vet ./...
go build -o bin/sockhound ./cmd/sockhound
```

A release-style build with a version stamp:

```bash
make release VERSION=0.1.0
# or
go build -trimpath -ldflags="-s -w -X github.com/zoro/sockhound/internal/version.Version=0.1.0" \
  -o dist/sockhound ./cmd/sockhound
```

`make clean` removes only `./bin` and `./dist`.

## Quick start

```bash
# Interactive TUI
./bin/sockhound

# TUI with automatic refresh every 5 seconds
./bin/sockhound --refresh-interval 5s

# One-shot text summary
./bin/sockhound scan

# Only TCP listeners
./bin/sockhound scan --listening --protocol tcp

# Versioned JSON to stdout
./bin/sockhound scan --json > snapshot.json

# Write JSON atomically to a file (stdout stays empty)
./bin/sockhound scan --json --output report.json

# Overwrite an existing report
./bin/sockhound scan --json --output report.json --force
```

When stdin/stdout are not a terminal, running `sockhound` with no arguments exits with a usage message instead of starting the TUI. Use `sockhound scan` or `sockhound scan --json`.

> A normal non-root scan often returns exit code `3` because some processes or file descriptors are not readable. That is expected partial visibility, not a scan failure. See [Exit codes](#exit-codes).

## TUI

The TUI starts on the Dashboard. The selected row is shown in the detail panel on wide terminals; press Enter for a full detail view.

| Tab | Key | Contents |
| --- | --- | --- |
| Dashboard | `1` | Socket counts, TCP states, findings and the socket inventory |
| TCP/UDP | `2` | TCP, TCP6, UDP and UDP6 sockets |
| Unix | `3` | Unix-domain sockets, paths, types and states |
| Processes | `4` | Processes with visible sockets, socket/listener counts |
| Findings | `5` | Rule, severity, subject, summary and evidence |
| Help | `?` | Keybindings, filter syntax, data notes and rule list |

### Keys

| Key | Action |
| --- | --- |
| `1`–`5` | Switch tab |
| `Tab` / `Shift+Tab` | Next / previous tab |
| `↑`/`k`, `↓`/`j` | Move selection |
| `PgUp`/`PgDn` | Move by page |
| `g` / `G`, `Home` / `End` | Jump to top / bottom |
| `Enter` | Open detail for the selected row |
| `Esc` | Close detail/help, or clear the active filter |
| `/` | Edit the live filter |
| `s` | Cycle sort order for the current tab |
| `r` | Refresh the snapshot |
| `e` | Export the current snapshot as JSON |
| `f` | Cycle owner filter; on Findings, cycle severity |
| `?` | Toggle help |
| `q`, `Ctrl+C` | Quit cleanly |

On Findings, `f` cycles `HIGH → MEDIUM → LOW → INFO → all`. On socket tabs it cycles `all owners → owner unknown → owner known`.

The export dialog asks for a path. If the file already exists, the first Enter shows a confirmation message and the second Enter overwrites it. `Esc` cancels.

Automatic refresh is off by default. Enable it with `--refresh-interval 5s` or `"refresh_interval": "5s"` in config. The status line shows `auto: 5s` while it is enabled. SockHound never runs overlapping scans: if a scan is still running when the next interval elapses, that tick is skipped. Automatic refresh pauses while the export dialog is open.

The layout adapts to terminal size. Below 80×24 the TUI shows a resize hint instead of a broken layout.

## CLI reference

```text
sockhound                 Launch the interactive TUI (requires a terminal)
sockhound tui [flags]     Launch the interactive TUI
sockhound scan [flags]    One-shot scan, text or JSON
sockhound version         Print the version
sockhound help            Show general help
```

### `tui` flags

| Flag | Meaning |
| --- | --- |
| `--config PATH` | Load a JSON rules/configuration file |
| `--refresh-interval DUR` | Automatic refresh interval, for example `5s`; `0s` disables |
| `--no-color` | Disable colors |
| `--debug` | Write diagnostics to stderr |
| `--proc-root PATH` | Alternate procfs mount point (advanced/testing) |
| `--no-owner-resolution` | Skip the `/proc/PID/fd` ownership pass |

### `scan` flags

| Flag | Meaning |
| --- | --- |
| `--json` | Write a versioned JSON snapshot to stdout |
| `--output PATH` | Write JSON to a file; implies `--json` and leaves stdout empty |
| `--force` | Overwrite an existing `--output` file |
| `--listening` | Only TCP listeners |
| `--protocol NAME` | `tcp`, `tcp6`, `udp`, `udp6`, `unix` or `all` |
| `--pid N` | Only sockets owned by PID N |
| `--port N` | Only sockets using local or remote port N |
| `--address TEXT` | Match local/remote address or Unix path |
| `--process TEXT` | Match owner process name (case-insensitive substring) |
| `--state NAME` | Match a normalized state, for example `LISTEN` |
| `--owner known\|unknown` | Filter by owner visibility |
| `--severity LEVEL` | `INFO`, `LOW`, `MEDIUM` or `HIGH` |
| `--filter EXPR` | Composable ANDed query, for example `"tcp port:8080 owner:unknown"` |
| `--config PATH` | Load a JSON rules/configuration file |
| `--debug` | Write diagnostics and warnings to stderr, never to JSON stdout |
| `--proc-root PATH` | Alternate procfs mount point (advanced/testing) |
| `--no-owner-resolution` | Skip the `/proc/PID/fd` ownership pass |
| `--no-color` | Accepted for compatibility; text output is already plain |

### Filter syntax

Filters are **ANDed**. Bare protocol names and `listen` are shorthands; other bare tokens are case-insensitive substring matches across the record's display fields.

| Term | Matches |
| --- | --- |
| `tcp`, `tcp6`, `udp`, `udp6`, `unix` | Protocol; `tcp` includes TCP6 and `udp` includes UDP6 |
| `listen` / `listening` | TCP sockets in `LISTEN` |
| `pid:123` | A socket owner PID |
| `port:8080` | Local or remote port |
| `addr:127.0.0.1` | Local address, remote address or Unix path substring |
| `proc:nginx` | Owner process name substring |
| `user:root` | Owner username substring |
| `inode:12345` | Socket inode |
| `state:LISTEN` | Normalized state |
| `owner:known`, `owner:unknown` | Owner visibility |
| `sev:INFO` | Findings at that severity (socket rows match if any finding matches) |
| `proto:tcp` | Same as the `tcp` shorthand |

Example:

```bash
sockhound scan --filter "tcp listen owner:known"
sockhound scan --filter "port:5432 proc:postgres"
sockhound scan --filter "unix addr:/run"
```

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan completed with no partial-visibility warnings |
| `1` | Usage or configuration error |
| `2` | Collection failed entirely, or the report could not be written |
| `3` | Report was produced, but collection was partial |

Findings do not change the exit code. There is intentionally no “fail on findings” behavior in v1.

## Configuration

Configuration is optional JSON loaded with `--config PATH`. Unknown fields are rejected so typos are visible.

```json
{
  "schema_version": 1,
  "review_ports": [22, 2375, 8080],
  "reveal_cmdline": false,
  "refresh_interval": "10s",
  "rules": {
    "SH-WILD-001": { "enabled": true, "severity": "INFO" },
    "SH-PORT-001": { "enabled": true, "severity": "LOW" },
    "SH-OWNER-001": { "enabled": false }
  }
}
```

- `review_ports` drives `SH-PORT-001` for TCP listeners and bound UDP sockets. The list is local configuration, not a vulnerability database.
- `reveal_cmdline` defaults to `false`. When false, arguments after `argv[0]` are replaced with `[N args hidden]`. When true, full command lines may contain sensitive values.
- `refresh_interval` enables automatic TUI refresh using a Go duration such as `"5s"`, `"30s"` or `"1m"`. The minimum is `1s`; omit it, use `"0s"`, or pass `--refresh-interval 0s` to disable. The CLI flag overrides the config value.
- `rules.<ID>.enabled` disables a rule.
- `rules.<ID>.severity` overrides a rule's severity. Overrides are recorded in the finding (`severity_overridden`) and called out in its limitations.
- `schema_version` defaults to `1` when omitted; other values are rejected.

## Rules

All rules are informational by default. Every finding includes the evidence used to produce it and explicit limitations.

| Rule | Name | Trigger |
| --- | --- | --- |
| `SH-WILD-001` | Wildcard-bound TCP listener | TCP `LISTEN` on `0.0.0.0` or `::` |
| `SH-PORT-001` | Socket on review-listed port | TCP listener or UDP socket on a configured `review_ports` entry |
| `SH-OWNER-001` | Owner unresolved | Socket inode has no visible owning process |
| `SH-UNIX-001` | Unix socket path metadata unavailable | Filesystem pathname exists but `stat` metadata could not be read |
| `SH-SCOPE-001` | Partial process visibility | Some process directories or file descriptors were inaccessible |
| `SH-STATE-001` | Unexpected/unknown TCP state | A TCP state code could not be mapped |

See [`docs/rules.md`](docs/rules.md) for evidence fields, interpretation guidance and configuration details. SockHound never declares a process malicious based only on a port number or bind address.

## JSON output

`--json` writes an indented, versioned snapshot. The top level includes `schema_version`, `tool_version`, `collected_at`, `duration_ms`, `network_namespace`, `scope`, `visibility`, `stats`, `sockets`, `processes` and `findings`.

```json
{
  "schema_version": 1,
  "tool_version": "0.1.0-dev",
  "collected_at": "2026-10-29T12:00:00Z",
  "scope": "current network namespace net:[4026531833]",
  "visibility": {
    "partial": true,
    "warnings": ["process visibility limited: ..."],
    "processes_inaccessible": 12,
    "fds_unreadable": 4
  },
  "stats": {
    "total_sockets": 938,
    "tcp": 30,
    "udp": 22,
    "unix": 886,
    "listeners": 11,
    "unresolved_owners": 120,
    "tcp_states": { "LISTEN": 11, "ESTABLISHED": 19 },
    "finding_severities": { "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 314 }
  },
  "sockets": [],
  "processes": [],
  "findings": []
}
```

Optional numeric fields such as `local_port`, `remote_port`, `inode` and `pid` are `null` when unknown rather than overloading zero. See [`docs/json-schema.md`](docs/json-schema.md) for the complete field reference.

The JSON file is written through a temporary file in the destination directory and then renamed. Existing files are refused unless `--force` (CLI) or the second Enter (TUI) is used.

## Permissions and partial visibility

SockHound works without root, but it cannot see everything a root process can see:

- `/proc/net/*` socket tables are generally readable, but `/proc/PID/fd` access is restricted by UID, `hidepid`, dumpability, security modules and container boundaries.
- Processes can exit or close file descriptors between directory listing and `readlink`; these races are skipped rather than treated as fatal.
- Some Unix socket paths cannot be `stat`ed because the file was removed, the path is inaccessible, or the socket uses an abstract name.
- Sockets with no visible owner are **preserved**, counted as unresolved owners, and optionally reported by `SH-OWNER-001`.
- Any warning, inaccessible process, unreadable file descriptor or unavailable Unix metadata marks the snapshot `visibility.partial` and makes the CLI exit `3`.

Typical non-root output includes warnings such as:

```text
process visibility limited: 262 process directories could not be read (permissions or races)
file descriptor visibility limited: 129 entries could not be resolved
```

This is a statement about what this user could read, not about what exists on the host. Elevated privileges may improve coverage but are not required and do not change SockHound's read-only behavior.

## Network namespace scope

SockHound inspects the **current network namespace** visible through procfs (normally `/proc/net/*`). It does not enumerate every namespace on the machine.

- A container normally has its own network namespace; sockets in other containers are not in this view.
- A socket held by a process in another network namespace may not have a record in the current namespace's socket table.
- The dashboard and text output show the current namespace identifier when it can be read.
- Unknown or unassociated sockets are not silently discarded.
- Cross-namespace enumeration is out of scope for v1.

“Complete” in SockHound output means complete for accessible procfs sources in the current namespace. It never means host-wide visibility across containers or namespaces.

## Privacy and safety

SockHound is read-only and makes no network connections. It does not capture packets, perform remote scans, execute discovered names or paths, close sockets, terminate processes, or alter firewall/network configuration.

Rendering and export handle sensitive metadata as follows:

- Control characters in process names, endpoints and Unix paths are sanitized before text/TUI rendering. JSON encodes control characters as JSON escapes; it does not emit terminal escape sequences.
- Command-line arguments are hidden by default (`argv0 [N args hidden]`) because they may contain tokens or passwords. Set `reveal_cmdline` only when needed.
- JSON exports may contain process names, usernames, UIDs, endpoints, inodes and Unix socket paths. Review the file before sharing it.
- Export refuses to overwrite silently: the CLI requires `--force`, and the TUI requires a second confirmation.
- Wildcard binds are reported with the caveat that firewall, routing, host/container networking and other controls determine reachability. SockHound does not test external reachability.

## Limitations

- v1 is Linux/procfs only; no eBPF or kernel modules.
- No packet capture, payload inspection, latency/throughput measurement or remote scanning.
- Automatic refresh is opt-in; the default is manual refresh with `r`.
- Findings are heuristics, not a vulnerability verdict.
- Process ownership is best-effort and subject to the permissions described above.
- The snapshot is a point-in-time view; sockets and owners can change immediately after collection.

## Development

```bash
make fmt      # go fmt ./...
make vet      # go vet ./...
make test     # go test ./...
make check    # fmt, vet, test and build
make build    # bin/sockhound
make release  # dist/sockhound (trimpath, stripped)
```

Tests use fixtures under `testdata/` and do not require root. Parser tests cover IPv4/IPv6 decoding, TCP/UDP states, Unix paths with spaces and malformed records; resolver tests cover redaction, unreadable processes and file-descriptor races; TUI tests cover tabs, filtering, sorting, details, resizing, export, refresh and auto-refresh scheduling.

### Project layout

```text
cmd/sockhound/        CLI entry point
internal/app/         mode dispatch, flags, filters, exit codes
internal/scanner/     collection/analysis orchestration
internal/procfs/      procfs parsing and collection
internal/process/     inode-to-PID resolution and metadata
internal/analysis/    evidence-backed rules
internal/model/       shared typed models and JSON schema
internal/output/      text and JSON rendering/export
internal/tui/         Bubble Tea model, update, view, tables, details
testdata/             procfs fixtures
docs/                 architecture, rules and JSON schema notes
```

See [`docs/architecture.md`](docs/architecture.md) for the data flow and implementation notes.

## License

MIT. See [`LICENSE`](LICENSE).
