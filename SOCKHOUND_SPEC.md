# SockHound — Linux Socket Inspector

**Document type:** Product and technical specification  
**Version:** 1.0  
**Status:** Proposed MVP  
**Target platform:** Linux (first-class support for common procfs-enabled distributions)  
**Language:** Go  
**Primary interface:** Full-screen terminal UI (TUI)  
**Secondary interface:** Non-interactive CLI and JSON output  
**License suggestion:** MIT  

---

## 1. Executive summary

SockHound is a lightweight Linux utility that inventories local network sockets, identifies their owning processes where permissions allow, and highlights sockets that deserve review. Its main interface is a keyboard-driven, full-screen terminal dashboard inspired by the attached NetWatch reference: a compact header with tab navigation, bordered panels, a live inventory table, summary metrics, findings, and a bottom help bar.

SockHound is intentionally a *socket inspector*, not a general network monitor. It does not capture packets, measure latency, calculate throughput, or perform remote port scanning. It answers local system questions such as:

- Which TCP and UDP sockets exist in the current network namespace?
- Which TCP sockets are listening, established, or in another state?
- Which process and user own a socket, when that can be determined?
- Which Unix-domain sockets exist, and what path or abstract name do they use?
- Which listeners are bound to wildcard addresses rather than loopback?
- What information was inaccessible or changed during collection?

### Product principle

> Show what the system reports, identify what is uncertain, and make every finding explainable.

A wildcard-bound listener is not automatically a vulnerability. It is a reason to review the service, its firewall rules, and intended exposure.

---

## 2. Goals and non-goals

### 2.1 Goals

- Provide a polished full-screen TUI for interactive socket inspection.
- Enumerate TCP, TCP6, UDP, UDP6, and Unix-domain socket records visible through procfs.
- Associate socket inodes with process file descriptors and process metadata where permissions allow.
- Show local and remote endpoints, protocol, state, PID, process name, user, and socket type when available.
- Filter and sort the socket inventory interactively.
- Display findings with severity, evidence, and a plain-language explanation.
- Refresh on demand and optionally at a configurable interval.
- Export a point-in-time snapshot as JSON.
- Provide a non-interactive CLI mode for scripts and shell workflows.
- Work without root privileges while reporting partial visibility honestly.
- Avoid modifying sockets, processes, firewall configuration, or system state.

### 2.2 Non-goals for v1

- Packet capture, payload inspection, or protocol decoding.
- Measuring bandwidth, latency, packet loss, or connection quality.
- Remote host or port scanning.
- Terminating processes or closing sockets.
- Modifying firewall rules or network configuration.
- Automatically declaring a process malicious based on a port number or bind address.
- Monitoring every network namespace in the system.
- A web dashboard, long-running daemon, or central management server.
- Kernel modules or eBPF in the initial release.

---

## 3. User stories

1. As a user, I can launch `sockhound` and immediately see a high-level summary of local sockets.
2. As a user, I can switch to TCP/UDP, Unix sockets, process ownership, or findings with keyboard shortcuts.
3. As an analyst, I can select a socket to inspect its endpoints, state, inode, owning process, and collection limitations.
4. As an analyst, I can find listeners bound to all IPv4 or IPv6 interfaces and review whether the exposure is expected.
5. As a user without root access, I can still inspect visible sockets and see why some process owners are unknown.
6. As a script author, I can run a one-shot scan and obtain JSON without starting the TUI.
7. As a user, I can refresh the inventory and see when the snapshot was collected.
8. As a user, I can filter by protocol, state, PID, process name, local port, or address.

---

## 4. Technology choices

| Area | Choice | Rationale |
|---|---|---|
| Language | Go | Good standard library, easy distribution, suitable for procfs parsing and CLI tools |
| TUI runtime | `charm.land/bubbletea/v2` | Keyboard-driven, stateful terminal application framework |
| Layout and styles | `charm.land/lipgloss/v2` | Borders, alignment, spacing, and terminal styling |
| TUI components | `charm.land/bubbles/v2` | Table, viewport, help, and other reusable components |
| Socket collection | Linux procfs | `/proc/net/*` and `/proc/PID/fd` are available without shelling out |
| Process metadata | Go standard library + procfs | Keep core dependencies small |
| Serialization | `encoding/json` | Machine-readable reports |
| Testing | `testing` and test fixtures | Parser tests should not require live network state |
| Build | Go toolchain | `go build`, `go test`, `go vet` |

Use the current compatible versions when initializing the repository, then commit `go.mod` and `go.sum` so builds remain reproducible. Keep the TUI dependencies separate from the collection and analysis packages so `sockhound scan --json` can work without invoking the TUI.

### Proposed initial platform baseline

- Linux with procfs mounted.
- A 64-bit system is the primary development target, while parsers should not assume fixed pointer widths where avoidable.
- Go version should be selected to satisfy the chosen Bubble Tea v2 release and recorded in `go.mod`.
- Root is not required for a basic scan. Running with elevated permissions may improve process visibility, but must not be required for normal operation.

---

## 5. UX and visual design

### 5.1 Visual direction

Use the screenshot as a *layout and interaction reference*:

- Dark background and restrained monochrome/gray borders.
- A compact top navigation strip with numbered tabs.
- Two or three columns of bordered panels when terminal dimensions allow.
- A wide primary table with a selected-row highlight.
- A findings/health panel on the right.
- A fixed footer with keybindings and status text.
- Dense but readable information; avoid unnecessary colors and decorative charts.

Use color sparingly and never rely on color alone to convey severity. In monochrome terminals, use textual labels such as `INFO`, `WARN`, and `HIGH`.

### 5.2 Dashboard mockup

The following is an illustrative wireframe, not a rendered screenshot. Exact panel widths adapt to terminal dimensions.

```text
┌─ SockHound  [1] Dashboard  [2] TCP/UDP  [3] Unix  [4] Processes  [5] Findings ─────┐
│ Snapshot 14:51:34  | Current netns | Refresh: manual | Visibility: partial/complete │
├────────────────────────────────────────────────────────────────────────────────────┤
│ ┌─ SOCKET SUMMARY ──────────────┐ ┌─ TCP STATES ─────────────────┐ ┌─ FINDINGS ───┐ │
│ │ Total sockets             126 │ │ LISTEN             12        │ │ WARN       2 │ │
│ │ TCP                       48  │ │ ESTABLISHED        31        │ │ INFO       5 │ │
│ │ UDP                       29  │ │ TIME_WAIT           4        │ │ UNKNOWN    3 │ │
│ │ Unix                      49  │ │ Other               1        │ │             │ │
│ └───────────────────────────────┘ └───────────────────────────────┘ └─────────────┘ │
│ ┌─ SOCKET INVENTORY ─────────────────────────────────────────────┐ ┌─ SELECTED ──┐ │
│ │ PROTO LOCAL             REMOTE            STATE       PID  PROC │ │ TCP LISTEN  │ │
│ │ TCP   0.0.0.0:8080      -                 LISTEN      1248 api  │ │ Local ...  │ │
│ │ TCP   127.0.0.1:5432    -                 LISTEN       892 db   │ │ PID ...    │ │
│ │ UDP   0.0.0.0:5353      -                 UNCONN       641 avahi│ │ User ...   │ │
│ │ UNIX  /run/demo.sock    -                 STREAM      1901 app  │ │ Inode ...  │ │
│ └────────────────────────────────────────────────────────────────┘ │ Evidence... │ │
│                                                                     └─────────────┘ │
├────────────────────────────────────────────────────────────────────────────────────┤
│ ↑/↓ Select  Enter Details  / Filter  s Sort  r Refresh  e Export  ? Help  q Quit   │
└────────────────────────────────────────────────────────────────────────────────────┘
```

### 5.3 Responsive behavior

The UI must adapt rather than breaking when the terminal is small.

- **Wide layout:** summary panels across the top, inventory table on the left, selected-item details and findings on the right.
- **Medium layout:** summary panels wrap to two rows; detail pane moves below or can be toggled.
- **Small layout:** switch to a compact single-column view with a smaller table and a dedicated detail screen.
- **Minimum supported size:** target approximately 80 columns by 24 rows; below this, display a resize/minimum-terminal hint rather than corrupting the layout.
- Handle terminal resize events, long process names, IPv6 endpoints, long Unix socket paths, and clipped text safely.

### 5.4 Tabs / screens

| Key | Screen | Purpose |
|---|---|---|
| `1` | Dashboard | Summary, recent findings, top-level socket inventory |
| `2` | TCP/UDP | TCP and UDP sockets with protocol, endpoints, state, owner, and inode |
| `3` | Unix sockets | Unix-domain sockets, path/abstract name, type, state/flags where available, owner |
| `4` | Processes | Processes with visible sockets; socket counts grouped by PID and name |
| `5` | Findings | Rule-based findings with severity, reason, evidence, and remediation guidance |
| `?` | Help | Keybindings and explanations |

An export dialog may be implemented as a modal instead of a permanent tab. Timeline/history is not required for v1; this project is a snapshot inspector, not a long-term monitor.

### 5.5 Main dashboard panels

1. **Socket Summary:** total records, TCP, UDP, Unix sockets, listeners, and unresolved owners.
2. **TCP State Summary:** LISTEN, ESTABLISHED, TIME_WAIT, and other TCP states.
3. **Findings:** counts by severity and a short list of the most relevant findings.
4. **Socket Inventory:** a sortable, scrollable table of collected records.
5. **Selected Socket:** detailed information for the currently highlighted row.
6. **Snapshot Status:** collection time, refresh mode, namespace scope, scan duration, and visibility warnings.

Do not add throughput graphs, gateway RTT, packet counters, topology graphs, or interface health metrics. Those belong in a different application.

### 5.6 Keyboard interaction

| Key | Behavior |
|---|---|
| `1`–`5` | Switch tabs |
| `↑` / `k` | Move selection up |
| `↓` / `j` | Move selection down |
| `PgUp` / `PgDn` | Move by page |
| `Enter` | Open detail view for selected socket |
| `Esc` | Close detail/modal or clear filter |
| `/` | Start filtering visible rows |
| `s` | Cycle through sort options |
| `r` | Refresh the snapshot |
| `e` | Open JSON export prompt |
| `f` | Cycle findings/visibility filter where applicable |
| `?` | Help |
| `q` / `Ctrl+C` | Quit cleanly |

If a key has a different meaning in a modal, display its modal-specific help. The footer should always show the most useful keys for the current screen.

---

## 6. Collection scope and data sources

### 6.1 Initial socket sources

The initial collector reads procfs files for the current network namespace:

- `/proc/net/tcp`
- `/proc/net/tcp6`
- `/proc/net/udp`
- `/proc/net/udp6`
- `/proc/net/unix`

The implementation may access equivalent `/proc/self/net/*` paths where that makes namespace semantics clearer. The collector must not assume that these tables enumerate sockets from every network namespace on the machine.

### 6.2 Process ownership resolution

Process association is a separate enrichment phase:

1. Read socket records and retain their inode numbers where the source provides them.
2. Enumerate numeric `/proc/PID` entries.
3. Inspect each process's `/proc/PID/fd` entries where permitted.
4. Resolve symbolic links such as `socket:[123456]` into socket inode numbers.
5. Associate matching inodes with PID(s).
6. Enrich PID with `/proc/PID/comm`, `/proc/PID/cmdline`, and UID information from `/proc/PID/status` where accessible.

Do not assume every socket has a visible owning process. Permissions, process exit, file descriptor churn, inherited/shared descriptors, and namespace differences can create missing or ambiguous owner results.

### 6.3 Unix-domain sockets

Parse `/proc/net/unix` for available fields including inode, flags, type, state, and pathname. Some sockets use abstract names beginning with `@` in presentation or have no ordinary filesystem pathname. Do not treat all Unix sockets as regular filesystem socket files.

Where the pathname identifies a filesystem socket and `stat` succeeds, optionally enrich with file mode and owner. Keep filesystem metadata separate from kernel socket metadata, and show an explicit unknown/unavailable marker on failure.

### 6.4 Protocol and state parsing

TCP state codes must be converted to named states, including LISTEN, ESTABLISHED, SYN_SENT, SYN_RECV, FIN_WAIT1, FIN_WAIT2, TIME_WAIT, CLOSE, CLOSE_WAIT, LAST_ACK, CLOSING, and UNKNOWN where applicable.

UDP records do not have TCP-style listening states. Use labels such as `BOUND/UNCONN` or `CONNECTED` only when supported by the source data; do not label every bound UDP socket as a listener.

Decode IPv4/IPv6 endpoint fields carefully and validate parsing with fixtures. Keep a normalized endpoint in the data model while preserving raw values for troubleshooting if useful.

### 6.5 Network namespace limitations

The default collector describes the network namespace visible through the current process's procfs view. A socket held by a process in another network namespace may not have a corresponding record in the current namespace's socket table. Therefore:

- The dashboard must display the namespace scope.
- Unknown or unassociated sockets must not be silently discarded.
- Initial release must not claim complete host-wide visibility across container namespaces.
- Cross-namespace enumeration is out of scope for v1.

---

## 7. Detection and classification rules

Findings are heuristics and must include the evidence supporting them. Do not label a socket or process as malicious based only on its port or bind address.

### 7.1 Initial rules

| Rule ID | Name | Initial severity | Trigger |
|---|---|---|---|
| `SH-WILD-001` | Wildcard-bound TCP listener | INFO by default | TCP socket is LISTEN and local address is `0.0.0.0` or `::` |
| `SH-PORT-001` | Listener on review-listed port | INFO | Listener uses a port present in an editable local review list |
| `SH-OWNER-001` | Owner unresolved | INFO | Socket inode could not be associated with a visible process |
| `SH-UNIX-001` | Unix socket path metadata unavailable | INFO | Filesystem pathname exists in source data, but metadata could not be read |
| `SH-SCOPE-001` | Partial process visibility | INFO | Some processes or file descriptors were inaccessible during owner resolution |
| `SH-STATE-001` | Unexpected/unknown TCP state | INFO | State could not be mapped to a known TCP state |

These are initial rules, not an exhaustive vulnerability detector. Severity may be adjusted by configuration, but every override must be visible in the report.

### 7.2 Wildcard binding interpretation

A bind address of `0.0.0.0` or `::` indicates a wildcard bind. It does **not** prove that the service is reachable from the internet: reachability may depend on firewall policy, routing, host/container networking, and other controls. Report the bind address and explain the distinction.

Loopback binds (`127.0.0.1` and `::1`) should be labelled as loopback. A specific local IP should be labelled as bound to that address. Avoid claims about external reachability unless the program has evidence for them; v1 does not test external reachability.

### 7.3 Review-listed ports

Provide an optional user-controlled list of ports for review. Default list entries, if any, should generate informational findings only. The report must not imply that a port is vulnerable because of its number. Users must be able to edit or disable this rule.

### 7.4 Finding structure

Every finding should include:

- Rule ID and rule name.
- Severity (`INFO`, `LOW`, `MEDIUM`, `HIGH`).
- Short summary.
- Explanation.
- Evidence fields: protocol, local endpoint, state, inode, PID/process/user when known.
- Limitations or context that could affect interpretation.
- Optional remediation/review guidance.

A finding should not be created if the underlying data is too incomplete to support the rule. If data is uncertain, state that uncertainty explicitly.

---

## 8. Command-line interface

SockHound has two primary modes: interactive TUI and one-shot scan.

### 8.1 Launch TUI

```bash
sockhound
sockhound tui
```

If stdin/stdout are not terminals, SockHound must not unexpectedly enter the TUI. It should explain how to use `scan` or require an explicit command.

### 8.2 One-shot scan

```bash
sockhound scan
sockhound scan --listening
sockhound scan --protocol tcp
sockhound scan --protocol udp
sockhound scan --protocol unix
sockhound scan --pid 1234
sockhound scan --port 8080
sockhound scan --address 127.0.0.1
sockhound scan --json
sockhound scan --json --output sockhound-report.json
```

The exact flag spelling is finalized during implementation, but the semantics must remain consistent.

### 8.3 Proposed global flags

- `--version`: print version and exit.
- `--help`: show usage.
- `--no-color`: disable styling for output modes that support color.
- `--config PATH`: load optional local rules/configuration.
- `--debug`: write diagnostic details to stderr without contaminating JSON stdout.

### 8.4 Filtering and sorting

The TUI and one-shot scan should support filtering by:

- Protocol.
- TCP state.
- PID.
- Process name (case-insensitive substring match is sufficient initially).
- Local port.
- Local address.
- Finding severity.
- Owner-known / owner-unknown status.

Filtering should be composable. The implementation must define whether filters are ANDed (default) and document that behavior.

### 8.5 Exit codes for scripts

Suggested initial behavior:

- `0`: scan completed; no fatal errors (findings may still exist).
- `1`: usage or configuration error.
- `2`: collection failed entirely.
- `3`: report exported but collection was partial.

If a separate “fail on findings” mode is added later, it must use an explicit flag rather than changing the default exit behavior.

---

## 9. Data model

The collector should return typed data, and rendering should not parse raw procfs strings.

### 9.1 Socket record

A normalized socket record should include, where available:

- `id`: stable-for-snapshot identifier (do not promise stability across scans).
- `protocol`: `tcp`, `tcp6`, `udp`, `udp6`, or `unix`.
- `family`: IPv4, IPv6, or Unix.
- `local_address` and `local_port` for IP sockets.
- `remote_address` and `remote_port` when present.
- `state`: normalized TCP state or applicable Unix socket state.
- `inode`: inode identifier when provided by procfs.
- `unix_path`: pathname or abstract socket name when present.
- `unix_type` / `unix_flags` if parseable.
- `owner_pids`: zero or more associated PIDs.
- `owner_names`: process names where readable.
- `owner_uids` / usernames where readable.
- `is_listening`: true only for TCP LISTEN records.
- `bind_scope`: `loopback`, `wildcard`, `specific`, `not-applicable`, or `unknown`.
- `collected_at`: snapshot time.
- `collection_notes`: optional warnings or partial-visibility information.

Use pointers or explicit validity fields for optional values. Do not overload port `0`, empty strings, or PID `0` to mean “unknown” unless that meaning is clearly documented.

### 9.2 Process summary

A process entry can include PID, command name, truncated command line, UID, number of associated sockets, and the list of visible socket IDs. Be mindful that command lines may include sensitive information. The default TUI should not reveal full command-line arguments unless the user opens details or enables a configuration option.

### 9.3 Snapshot model

A scan snapshot should contain:

- Collection timestamp and duration.
- Current network namespace identifier if safely obtainable.
- Protocol counts and state counts.
- Socket records.
- Findings.
- Collection warnings and partial-visibility status.
- SockHound version.

JSON should be versioned, for example with a `schema_version` field, so later report formats can evolve.

---

## 10. Proposed repository structure

```text
sockhound/
├── cmd/
│   └── sockhound/
│       └── main.go
├── internal/
│   ├── app/                 # mode selection and orchestration
│   ├── scanner/             # scan coordinator
│   ├── procfs/
│   │   ├── tcp.go           # /proc/net/tcp and tcp6 parsing
│   │   ├── udp.go           # /proc/net/udp and udp6 parsing
│   │   ├── unix.go          # /proc/net/unix parsing
│   │   ├── parse.go         # endpoint, state and inode helpers
│   │   └── fixtures_test.go
│   ├── process/
│   │   ├── resolver.go      # inode-to-PID association
│   │   └── metadata.go      # comm, status, cmdline enrichment
│   ├── analysis/
│   │   ├── findings.go      # finding types and rule runner
│   │   └── rules.go         # initial detection rules
│   ├── model/               # shared typed models
│   ├── output/
│   │   ├── text.go          # non-interactive output
│   │   └── json.go          # JSON output
│   └── tui/
│       ├── model.go         # TUI state and selected tab
│       ├── update.go        # key events and state transitions
│       ├── view.go          # root rendering/layout
│       ├── dashboard.go     # dashboard screen
│       ├── sockets.go       # TCP/UDP table
│       ├── unix.go          # Unix socket table
│       ├── processes.go     # process summary table
│       ├── findings.go      # findings view
│       ├── details.go       # selected item details
│       ├── styles.go        # centralized styles
│       └── keymap.go        # keyboard bindings
├── testdata/
│   ├── proc-net-tcp.txt
│   ├── proc-net-tcp6.txt
│   ├── proc-net-udp.txt
│   ├── proc-net-udp6.txt
│   └── proc-net-unix.txt
├── docs/
├── go.mod
├── go.sum
├── Makefile
├── README.md
├── LICENSE
└── SOCKHOUND_SPEC.md
```

This is a proposed layout, not a requirement to create every file up front. Start with the smallest vertical slice and add packages when their responsibilities are real.

---

## 11. Architecture and data flow

```text
                        ┌────────────────────┐
                        │ CLI / TUI front end │
                        └─────────┬──────────┘
                                  │
                        ┌─────────▼──────────┐
                        │ Scan coordinator   │
                        └─────────┬──────────┘
                                  │
             ┌────────────────────┼────────────────────┐
             │                    │                    │
    ┌────────▼────────┐  ┌────────▼─────────┐  ┌───────▼────────┐
    │ TCP/UDP procfs   │  │ Unix procfs      │  │ Process resolver│
    │ collector/parser│  │ collector/parser│  │ /proc/PID/fd    │
    └────────┬────────┘  └────────┬─────────┘  └───────┬────────┘
             └────────────────────┼────────────────────┘
                                  │
                        ┌─────────▼──────────┐
                        │ Normalized snapshot│
                        └─────────┬──────────┘
                                  │
                        ┌─────────▼──────────┐
                        │ Rule-based analysis│
                        └─────────┬──────────┘
                                  │
                 ┌────────────────┴────────────────┐
                 │                                 │
        ┌────────▼────────┐               ┌────────▼────────┐
        │ TUI renderer    │               │ Text / JSON     │
        └─────────────────┘               └─────────────────┘
```

### Design requirements

- Collection and parsing are independent of the TUI.
- The TUI consumes immutable snapshots; it should not read procfs directly during rendering.
- A refresh produces a new snapshot, then swaps it into the UI state.
- Long-running process-resolution work must not block keyboard input or screen redraws.
- A failed source should produce a collection warning, not crash the entire scan if other sources succeeded.
- All rendering must use normalized data and be testable separately from procfs parsing.

---

## 12. TUI implementation details

### 12.1 Library choices

Use Bubble Tea v2 for the event loop, Lip Gloss v2 for styles and layout, and Bubbles v2 for table/list/viewport/help components. Use their compatible v2 module paths and pin resolved versions in `go.mod`/`go.sum`.

Suggested initialization after the Go module has been created:

```bash
go mod init github.com/<your-user>/sockhound
go get charm.land/bubbletea/v2@latest
go get charm.land/bubbles/v2@latest
go get charm.land/lipgloss/v2@latest
go mod tidy
```

Replace `<your-user>` with the intended repository owner. Inspect the current library examples before implementing components because major-version APIs can change.

### 12.2 TUI model state

The root TUI model should track:

- Current tab.
- Current immutable snapshot.
- Selected socket row and selected finding.
- Active filter query and filter scope.
- Current sort column and sort direction.
- Loading/refresh state.
- Export modal state and destination path.
- Current terminal width and height.
- Any visible collection warnings.

### 12.3 Refresh behavior

- `r` triggers a fresh scan.
- Show a small status indicator during collection.
- Keep the old snapshot visible until the new snapshot is ready.
- When a scan completes, replace the snapshot atomically and reset an invalid selection to a valid row.
- Report the scan's timestamp and duration.
- Do not run concurrent refreshes unless there is an explicit cancellation/queue design.
- A configurable auto-refresh interval may be added after manual refresh is stable; manual refresh is sufficient for the MVP.

### 12.4 Styling

- Default to a dark, neutral terminal appearance with thin borders and a restrained accent color.
- Support terminals without true color and a `--no-color` mode for non-interactive output.
- Keep high/medium/low informational labels readable in monochrome.
- Do not hard-code fixed panel sizes; derive layout from terminal dimensions.
- Clip long paths and command names while preserving the full value in the details pane and JSON output.
- Escape or sanitize control characters in process names and socket paths before rendering.

---

## 13. Filtering, sorting, and selection

### Initial filters

- Protocol: TCP, UDP, Unix, or all.
- TCP state: LISTEN, ESTABLISHED, and other states.
- PID or process name.
- Local port.
- Local address or Unix socket path.
- Finding severity.
- Owner-known versus owner-unknown.

### Initial sort options

- Protocol.
- Local address/port.
- TCP state.
- PID.
- Process name.
- Finding severity.

The selected row must remain visible after filtering and refreshing whenever the selected socket can be identified in the new snapshot. Socket identities are only guaranteed within a snapshot; do not promise stable IDs across process or socket lifetimes.

---

## 14. Performance expectations

These are starting targets and must be verified on a real Linux system rather than treated as guarantees.

- Typical scans should complete in a few seconds on a desktop with a moderate process count.
- TUI input and rendering should remain responsive while collecting data.
- Process association should avoid repeatedly scanning all file descriptors for each socket. Prefer building an inode-to-process index in one pass.
- Bound output size and handle large socket inventories with pagination/virtualized table rendering.
- Do not spawn one goroutine per file descriptor without limits.
- Support cancellation on quit and report partial results if the user explicitly cancels a scan, where practical.
- Avoid unbounded buffering of command lines or procfs content.

---

## 15. Error handling and partial visibility

SockHound must tolerate normal procfs races and permission restrictions.

Examples:

- A process exits while its `/proc/PID/fd` directory is being read.
- A file descriptor disappears between directory listing and symlink resolution.
- A process has exited and a PID has been reused.
- A user cannot read another process's metadata due to UID boundaries, procfs `hidepid`, or security policy.
- An inode cannot be associated with a process because the file descriptor is hidden or changed.
- A procfs file is missing or malformed on a kernel/system variant.
- A terminal is resized during rendering.

Rules:

- Treat `ENOENT` during process scanning as a likely race and continue.
- Treat `EACCES`/`EPERM` as visibility limitations, not fatal errors for the whole scan.
- Add useful diagnostic counts to the snapshot.
- Keep detailed errors on stderr or the diagnostics panel; do not silently discard all errors.
- Avoid including sensitive command-line arguments in error messages by default.
- A completely failed collection should return a non-zero exit code in CLI mode.

---

## 16. Security and privacy requirements

- SockHound is read-only. It must not terminate processes, close sockets, alter firewall rules, or change network configuration.
- No automatic network connections are made by the tool.
- No remote scanning or packet capture is included.
- Do not execute discovered process names, paths, or socket paths.
- Sanitize control characters before rendering process metadata and Unix socket paths.
- Avoid printing full command lines by default; they may contain tokens or passwords.
- JSON export may contain process names, UIDs, endpoints, and socket paths. Warn users to review the output before sharing it.
- Export should not overwrite a file silently; require a clear overwrite flag or confirmation.
- Do not require root. If run elevated, the tool should still only read the relevant system information.
- Never state that a listener is publicly reachable based only on a wildcard bind.

---

## 17. Testing strategy

### 17.1 Parser unit tests

Use fixed fixture files under `testdata/`.

Cover:

- Standard IPv4 TCP records.
- IPv6 TCP records.
- UDP records and connected/bound distinctions where represented.
- Every known TCP state code and unknown state codes.
- Valid and malformed endpoint fields.
- Endianness of IPv4/IPv6 addresses as represented in procfs.
- Missing optional fields and truncated lines.
- Unix sockets with ordinary paths, abstract names, and no path.
- Duplicate inode associations and multiple PIDs sharing a socket.

### 17.2 Process resolver tests

- Socket inode association from fixture symlinks.
- Process with no visible file descriptors.
- Unreadable process directory.
- Process disappearing during collection.
- Malformed PID entry.
- Missing `comm`, `cmdline`, or `status` fields.
- Sensitive command-line redaction in default output.

### 17.3 Analysis tests

- Wildcard-bound TCP listener gets an informational finding.
- Loopback listener does not get a wildcard-bind finding.
- UDP socket is not mislabeled as a TCP listener.
- Unknown owner creates a visibility finding only when the rule's conditions are met.
- Review-list port findings remain informational by default.
- Rule evidence includes the exact endpoint/state used for the finding.
- Configuration can disable or tune a rule.

### 17.4 TUI tests

- Correct default tab.
- Tab switching and keybinding behavior.
- Filtering and sorting.
- Selection/detail interaction.
- Empty-data view.
- Partial-visibility view.
- Terminal resize and small-terminal fallback.
- Long IPv6 endpoint and Unix path clipping.
- JSON export modal and error path.
- Quit during refresh.

### 17.5 Integration/manual tests

Run on a Linux host or VM with multiple processes, including a local TCP listener, a bound UDP socket, and a Unix-domain socket. Verify that output matches independent reference information such as `/proc/net/*` and process file descriptors, while treating the reference command output as test aids rather than runtime dependencies.

Do not require root for the normal test suite. Root-only visibility scenarios may be optional tests that skip when permissions are unavailable.

---

## 18. Build and development workflow

### Prerequisites

- A recent Go toolchain compatible with the selected TUI dependencies.
- Linux with procfs mounted.
- Git.
- Optional: `make` for convenience targets.

### Build commands

```bash
go mod tidy
go fmt ./...
go vet ./...
go test ./...
go build -o bin/sockhound ./cmd/sockhound
```

### Suggested Makefile targets

```makefile
.PHONY: build test vet fmt check clean

build:
	go build -o bin/sockhound ./cmd/sockhound

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w $$(find . -name '*.go' -type f)

check: fmt vet test build

clean:
	rm -rf bin
```

Review the Makefile in the final repository; avoid destructive wildcard patterns and ensure `clean` only removes generated output under the repository's `bin/` directory.

### Release build

```bash
go build -trimpath -ldflags="-s -w" -o dist/sockhound ./cmd/sockhound
```

Do not claim the binary is fully statically linked unless the actual build configuration proves that. Record Go version, target architecture, version, and commit in release metadata where practical.

---

## 19. Implementation milestones

### Milestone 0 — Repository skeleton

- Create Go module and command entry point.
- Add version/help behavior.
- Add initial model types and a short README.
- Set up `go test`, `go vet`, and formatting checks.

**Exit criteria:** project builds and tests from a clean checkout.

### Milestone 1 — Procfs parsers

- Implement TCP/TCP6 parsing.
- Add IPv4/IPv6 endpoint decoding.
- Implement TCP state mapping.
- Implement UDP/UDP6 parsing.
- Implement Unix socket parsing.
- Add fixtures and parser tests.

**Exit criteria:** parser tests cover valid, malformed, and unknown entries.

### Milestone 2 — Process association

- Build inode-to-PID associations from `/proc/PID/fd`.
- Collect `comm`, UID, and redacted command metadata.
- Account for permissions and races.
- Return collection warnings rather than losing partial data.

**Exit criteria:** a test process's sockets can be associated when permissions allow, and inaccessible owners remain explicitly unknown.

### Milestone 3 — One-shot CLI and JSON

- Add `scan` command and filters.
- Add text table output.
- Add versioned JSON output.
- Add meaningful exit codes.

**Exit criteria:** command output can be consumed by a shell script and JSON parses correctly.

### Milestone 4 — TUI shell

- Add Bubble Tea application model.
- Implement header tabs, footer help, responsive layout, and empty/loading/error states.
- Use fixture or generated test data initially.

**Exit criteria:** UI navigation and resize behavior work independently of the collector.

### Milestone 5 — Live data integration

- Integrate scan snapshots into the TUI.
- Implement dashboard, socket tables, process view, findings, selected-item detail, refresh, filters, and export.
- Keep collection off the UI event path so rendering remains responsive.

**Exit criteria:** a user can launch the TUI, inspect live local socket data, refresh, filter, inspect details, and export JSON.

### Milestone 6 — Hardening and release

- Add edge-case tests and fuzz tests for procfs parsers where appropriate.
- Test under non-root and elevated permissions.
- Verify JSON output has no terminal escape sequences.
- Review command-line redaction and error messages.
- Add README examples and release instructions.

**Exit criteria:** all MVP acceptance criteria pass on at least one current Linux distribution and the project documents platform limitations.

---

## 20. MVP acceptance criteria

The MVP is complete when:

1. `sockhound` opens the full-screen TUI when run interactively.
2. `sockhound scan` produces a non-interactive summary.
3. TCP/TCP6/UDP/UDP6/Unix procfs data are parsed with unit-tested parsers.
4. Socket inodes are associated with PIDs where visible.
5. Owner-unknown records are preserved and counted.
6. TUI contains Dashboard, TCP/UDP, Unix, Processes, Findings, and Help views.
7. TUI supports keyboard navigation, filtering, sorting, refresh, and JSON export.
8. Layout adapts to terminal resizing and supports a compact layout for smaller terminals.
9. Rules produce evidence-backed informational findings without overclaiming risk.
10. `sockhound scan --json` produces valid, versioned JSON.
11. `go test ./...`, `go vet ./...`, and the build pass.
12. The program does not modify networking configuration or interactively alter target processes.
13. README documents procfs permissions, network namespace scope, partial visibility, and command-line privacy.

---

## 21. Out-of-scope future ideas

Do not implement these before the MVP is stable:

- Persistent scan history and timeline diffs.
- Cross-network-namespace enumeration.
- Optional eBPF-based connection lifecycle events.
- Container-runtime integration.
- User-configurable rules UI.
- Export to SIEM formats.
- Interface statistics or packet capture.
- Plugin architecture.

These are possible future projects, not commitments for v1.

---

## 22. Definition of done

SockHound v1 is done when it is a usable Go application—not just a working parser—with a clear TUI, correct socket decoding, transparent process-ownership limitations, explainable findings, stable JSON output, meaningful automated tests, and concise documentation. The TUI should make it easier to inspect local sockets, not hide the uncertainty inherent in procfs collection.

**Final implementation principle:** correct data and clear uncertainty come before visual polish; visual polish comes before adding more features.
