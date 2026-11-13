# Design: Haunted House Honeypot

This document describes **how** the system implements the requirements in `requirements.md` (R1–R8). Decisions with significant tradeoffs are recorded as ADRs in `docs/adr/` and referenced here rather than repeated.

Items marked **[DECISION]** are proposed defaults that the owner must confirm or change before implementation.

## Overview

- **What it is:** an SSH honeypot that presents a believable, increasingly haunted Linux environment, records every action, maps behavior to MITRE ATT&CK, and streams it to a protected live dashboard.
- **Requirements implemented:** R1–R6 and R8 (v1.0 release scope); R7 is a stretch goal.
- **Architecture diagram:** `docs/architecture.png`
- **Decisions:**

| ADR | Decision |
|---|---|
| ADR-0001 | Python 3.12+ with `asyncssh==2.24.1` |
| ADR-0002 | HMAC-SHA-256 password fingerprints, never plaintext |
| ADR-0003 | Two isolated services: honeypot and dashboard API |
| ADR-0004 | PostgreSQL event store with least-privilege roles |
| ADR-0005 | FastAPI, Next.js static export, Server-Sent Events |
| ADR-0006 | Weak-credential pair list for SSH authentication |

## Architecture

Three services run in separate containers (ADR-0003):

| Service | Zone | Exposed | Talks to |
|---|---|---|---|
| **Honeypot** (`honeypot/`) | Attacker zone | SSH, to the internet | PostgreSQL, LLM API |
| **Dashboard API** (`api/`) | Internal zone | Internal network / VPN only | PostgreSQL |
| **PostgreSQL** | Internal zone | Never | Honeypot, Dashboard API |

- The honeypot and dashboard API share **no memory and no secrets**. PostgreSQL is the only channel between them.
- The dashboard frontend (`dashboard/`) is a Next.js static export served by the dashboard API.
- Inside the honeypot, everything on the attacker's path is **synchronous from the attacker's view** (they wait for the response); recording and database writes are **asynchronous** and never block the attacker, matching the solid/dashed arrows on the diagram.

### Honeypot internal structure

```
SSH Listener ──► Admission Control
     │
     ▼
Auth Policy ──► Session Manager ──► Shell I/O
                      │
                      ▼
               Command Engine ──► Virtual Filesystem
                 │         │
                 │         └──► LLM Fallback ──► LLM API
                 ▼
            Haunt Engine     ATT&CK Tagger
                      │            │
                      ▼            ▼
                   Event Recorder ──► PostgreSQL (+ NOTIFY)
```

## Components and Interfaces

Each component lists its **responsibility**, **interface** (main classes and functions; names are provisional), **inputs and outputs**, and **requirements covered**.

### 3.1 SSH Listener (`honeypot/ssh_server.py`)

- **Responsibility:** accept SSH connections, run the SSH protocol, and hand authenticated sessions to the Session Manager. Refuse every SSH capability other than shell and exec.
- **Interface:**
  - `HoneypotServer(asyncssh.SSHServer)`: one instance per connection.
    - `connection_made(conn)`: record the source IP and port; ask Admission Control for a slot; close immediately if refused.
    - `begin_auth`, `password_auth_supported`, `kbdint_auth_supported`, `validate_password`: delegate to the Auth Policy; count failures per connection across **both** auth methods.
    - `connection_requested`, `server_requested`, `unix_connection_requested`, `unix_server_requested`: log and return `False`.
    - `connection_lost(exc)`: release the admission slot and finalize the session.
  - `create_honeypot_server(config) -> asyncssh.SSHAcceptor`: starts the listener with every option from the ADR-0001 configuration audit set explicitly.
- **Inputs:** TCP connections, SSH protocol messages.
- **Outputs:** an authenticated session handed to the Session Manager; auth and refusal events to the Event Recorder.
- **Requirements:** R1.1–R1.14, R8.7, R8.8.

### 3.2 Admission Control (`honeypot/limits.py`)

- **Responsibility:** decide whether a new connection may proceed, and track slots until release.
- **Interface:**
  - `AdmissionController.try_acquire(ip) -> bool`: checks the global cap (100), the per-IP cap (5), and the per-IP rolling rate (10 attempts / 60 s); records the attempt.
  - `AdmissionController.release(ip)`: frees the slot.
- **Atomicity (R8.10):** the honeypot runs on a single asyncio event loop. As long as `try_acquire` contains **no `await`** between checking and incrementing a counter, no other connection can run in between, so the check-and-increment is atomic without locks.
- **Requirements:** R8.1–R8.3, R8.10, R8.11, R8.12.

### 3.3 Auth Policy (`honeypot/auth.py`)

- **Responsibility:** decide whether a username/password pair succeeds, and produce password fingerprints.
- **Interface:**
  - `AuthPolicy.check(username, password) -> bool`: true if the pair is on the configured list (ADR-0006) or matches the demo credential.
  - `fingerprint(password) -> str`: HMAC-SHA-256 hex digest with the password-purpose key (ADR-0002).
- **Configuration:**
  - Credential pairs: `config/credentials.toml` (committed; publicly known decoy credentials).
  - Demo credential and HMAC secret: environment variables (never committed).
  - Startup fails if the HMAC secret is missing (R1.15).
- **Key derivation (domain separation):** derive a separate key per purpose from the master secret, e.g. `HMAC(master, "password-fingerprint")` and `HMAC(master, "identity-key")`.
- **Requirements:** R1.3, R1.5, R1.6, R1.15.

### 3.4 Session Manager (`honeypot/session.py`)

- **Responsibility:** own all per-connection state and its lifecycle, including timeouts.
- **Interface:**
  - `Session` (dataclass): `session_id` (UUID), `client_ip`, `client_port`, `client_version`, `started_at`, `authenticated_at`, `username`, `cwd`, `vfs`, `haunt` (HauntState), `command_count`, `llm_requests`, `next_seq`, `last_activity`, `recorded_bytes`, `last_exit_status`.
  - `Session.next_sequence() -> int`: monotonically increasing event sequence number (R5.8).
  - Idle watchdog: closes the connection after 300 s without client activity (R8.4).
  - Lifetime watchdog: closes the connection 1,800 s after acceptance (R8.5).
- **Isolation:** each session gets its own `Session` object and its own VFS copy; nothing mutable is shared between sessions (R2.10).
- **Requirements:** R2.10, R2.11, R2.16, R5.1, R5.8, R8.4, R8.5, R8.11.

### 3.5 Shell I/O (`honeypot/shell.py`)

- **Responsibility:** the terminal loop for interactive sessions, and the one-shot path for exec requests.
- **Interface:**
  - `run_interactive(process, session)`: prompt, read lines, dispatch to the Command Engine, write results. Catches `TerminalSizeChanged` **inside** the read loop and continues (spike finding); ends on `exit` (prints `logout`), EOF, or `BreakReceived`.
  - `run_exec(process, session)`: enforces the 4,096-byte limit on the command (R8.6, not covered by asyncssh's `max_line_length`), dispatches once, returns output and exit status.
  - `sanitize_for_terminal(text) -> str`: strips terminal control sequences from untrusted text (LLM output) before writing.
- **Prompt:** `{username}@{hostname}:{cwd_display}$ ` (`#` for root).
- **Requirements:** R1.4, R1.9, R4.9, R8.6.

### 3.6 Command Engine (`honeypot/commands/`)

- **Responsibility:** turn a command line into a result, without ever touching the host.
- **Interface:**
  - `parse(line) -> Pipeline | ParseError`: tokenizes with quote handling; recognizes `|`, `>`, `>>`.
  - `Pipeline`: up to 3 `CommandCall(name, args)` stages plus an optional redirection.
  - `REGISTRY: dict[str, Handler]`: maps command names to handlers.
  - `Handler(ctx, args, stdin) -> CommandResult`, where `CommandResult` has `stdout`, `stderr`, `exit_status`.
  - `execute(session, line) -> CommandResult`: parse, run each stage passing stdout to the next stage's stdin, apply redirection, record `last_exit_status`.
- **Unsupported syntax:** `;`, `&&`, `||`, `&`, `$(...)`, backticks, `<`, here-docs, and more than 3 stages produce a bash-style error or go to the LLM Fallback (R2.7). They are **never** interpreted.
- **Unknown commands:** routed to the LLM Fallback (R2.8).
- **Output cap:** stdout truncated at 256 KiB per command (R2.9).
- **Requirements:** R2.1, R2.5–R2.8, R2.13–R2.15.

### 3.7 Virtual Filesystem (`honeypot/vfs.py`)

- **Responsibility:** an in-memory fake Linux filesystem, one copy per session.
- **Interface:**
  - `Node`: `name`, `kind` (file/dir), `mode`, `owner`, `group`, `mtime`, `content` (files) or `children` (dirs).
  - `VirtualFS.from_template(template) -> VirtualFS`: deep copy of the base filesystem built from `config/fs_template/`.
  - `resolve(cwd, path) -> Node | None`: normalizes `.`, `..`, repeated slashes, and relative paths **inside the virtual root only**. `..` at `/` stays at `/`. Never consults the host filesystem.
  - `create_file`, `write_file`, `mkdir`, `remove`, `copy`, `move`: each checks **all** limits before changing anything, so a rejected operation leaves the tree unchanged (R2.9).
- **Limits:** 1,000 entries, 64 KiB per file, 5 MiB total attacker-created content, depth 16.
- **Symlinks:** not modeled in v1.0 (removes a whole class of path-escape bugs).
- **Requirements:** R2.2–R2.4, R2.9, R2.12, R2.13.

### 3.8 Haunt Engine (`honeypot/haunt.py`)

- **Responsibility:** compute the haunting level and choose haunting events.
- **Interface:**
  - `HauntState`: `level` (0–3), `score`, `last_event_at`.
  - `update(state, session, command, now) -> HauntState`: applies time and command-count thresholds plus behavior scores; never lowers the level (R3.5).
  - `maybe_event(state, context, now, rng) -> HauntEvent | None`: returns an event only if the 15 s cooldown has passed (R3.10).
  - `clock` and `rng` are injected, so tests are deterministic (R3.11).
- **Details:** section 7.
- **Requirements:** R3.1–R3.11.

### 3.9 LLM Fallback (`honeypot/llm.py`)

- **Responsibility:** produce believable output for commands the engine does not implement, safely and within budget.
- **Interface:**
  - `respond(session, command) -> str`: returns validated LLM output or a canned response.
  - Steps: check limits (20 per session, 500 per day, budget); build the request; call with a 5 s timeout (`asyncio.wait_for`); validate (section 8); record telemetry.
- **Request construction:** a fixed, trusted system prompt; the attacker's command passed as clearly delimited **data**, never as instructions; total request at most 8 KiB, command portion at most 4 KiB (R4.4).
- **State integrity:** LLM output is display text only. It never changes the VFS, cwd, or any session state (R4.12).
- **Requirements:** R4.1–R4.14.

### 3.10 ATT&CK Tagger (`honeypot/attack.py`)

- **Responsibility:** map recorded actions to MITRE ATT&CK techniques with deterministic rules.
- **Interface:**
  - `Rule`: `rule_id`, `technique_id`, `technique_name`, `matches(event) -> bool`.
  - `tag(event) -> list[Detection]`: runs inline after each command (rules are cheap string checks).
- **Initial rules:**


| Rule | Matches | Technique |
|---|---|---|
| AUTH-BRUTE | Multiple failed logins in one connection | T1110.001 Brute Force: Password Guessing |
| AUTH-VALID | Successful login with a listed weak credential | T1078.001 / T1078.003 Valid Accounts: Default / Local Accounts |
| DISC-SYS | `uname`, `cat /etc/os-release`, `hostname` | T1082 System Information Discovery |
| DISC-USER | `whoami`, `id` | T1033 System Owner/User Discovery |
| DISC-ACCT | `cat /etc/passwd`, `getent passwd` | T1087.001 Account Discovery: Local Account |
| DISC-PROC | `ps` | T1057 Process Discovery |
| DISC-FILE | `ls`, `find` | T1083 File and Directory Discovery |
| DISC-NET-CFG | `ifconfig`, `ip a` | T1016 System Network Configuration Discovery |
| DISC-NET-CONN | `netstat`, `ss` | T1049 System Network Connections Discovery |
| CRED-DUMP | Reading `/etc/shadow` | T1003.008 OS Credential Dumping: /etc/passwd and /etc/shadow |
| CRED-FILE | Reading `.bash_history`, SSH/API key files | T1552.003 / T1552.004 Unsecured Credentials: Bash History / Private Keys |
| TOOL-XFER | `wget`, `curl`, `tftp` | T1105 Ingress Tool Transfer |
| PERSIST-CRON | `crontab`, writes under `/etc/cron*` | T1053.003 Scheduled Task/Job: Cron |
| PERSIST-KEYS | Writes to `authorized_keys` | T1098.004 Account Manipulation: SSH Authorized Keys |
| PRIV-SUDO | `sudo`, `su` | T1548.003 Abuse Elevation Control Mechanism: Sudo and Sudo Caching |
| DEFENSE-HIST | `history -c`, `unset HISTFILE` | T1070.003 Indicator Removal: Clear Command History |
| DEFENSE-LOGS | Deleting or truncating files in `/var/log/` | T1070.002 Indicator Removal: Clear Linux or Mac System Logs |


- **Requirements:** R5.5–R5.7.

### 3.11 Event Recorder (`honeypot/recorder.py`)

- **Responsibility:** durably store every event without blocking the attacker's path.
- **Interface:**
  - `Recorder.record(session, event_type, payload)`: assigns the sequence number and timestamp, enforces the 10 MiB per-session cap, and puts the event on a bounded `asyncio.Queue`.
  - A background writer task inserts events into PostgreSQL through an async `psycopg` pool, then sends `NOTIFY honeypot_events` with `{session_id, seq}` only.
- **Fail closed (R5.11):** if an insert fails or the queue is full, the affected session is terminated rather than allowed to continue unrecorded.
- **Timestamps:** UTC, millisecond precision (R5.12).
- **Requirements:** R5.1–R5.4, R5.8, R5.10–R5.12, R8.9.

### 3.12 Dashboard API (`api/`)

- **Responsibility:** authenticate users, serve recorded data, and stream live events.
- **Interface (endpoints, provisional):**

| Method | Path | Role | Purpose |
|---|---|---|---|
| POST | `/api/login` | public | Start a session (sets cookie) |
| POST | `/api/logout` | any | End the session |
| GET | `/api/sessions` | admin, judge | List sessions (active and completed), paginated |
| GET | `/api/sessions/{id}` | admin, judge | Session metadata |
| GET | `/api/sessions/{id}/events` | admin, judge | Events, paginated by sequence, 100 per page (R6.14) |
| GET | `/api/detections` | admin, judge | ATT&CK detections |
| GET | `/api/stream` | admin, judge | SSE stream of new events |
| DELETE | `/api/sessions/{id}` | admin | Delete a recording (R5.9); requires CSRF token |

- **Live updates:** one dedicated connection runs `LISTEN honeypot_events`; each notification fetches the row by ID and fans it out to connected SSE clients. SSE event IDs are sequence numbers, so `Last-Event-ID` reconnection resends missed events (R6.13).
- **Database roles:** requests run as `dashboard_judge` or `dashboard_admin` depending on the user's role, so the database enforces permissions as a second layer (ADR-0004).
- **Requirements:** R5.9, R5.13, R5.14, R6.1–R6.16.

### 3.13 Dashboard Frontend (`dashboard/`)

- **Responsibility:** the defender and judge UI. Built by Kiro under review (see `conventions.md`).
- **Pages:** login; live overview (active sessions, haunt levels, detection feed); session detail with replay; detections view.
- **Rule:** attacker-supplied and LLM-generated text is rendered as plain text only, never as HTML (R6.9).
- **Requirements:** R6.2, R6.4–R6.9.

## Data Models

Provisional PostgreSQL schema. Table and column names are finalized in `migrations/`.

### `sessions`

| Column | Type | Notes |
|---|---|---|
| `session_id` | UUID, PK | One per accepted connection (R5.1) |
| `client_ip` | INET | |
| `client_port` | INTEGER | |
| `client_version` | TEXT | SSH client identification string |
| `started_at` | TIMESTAMPTZ | |
| `ended_at` | TIMESTAMPTZ, nullable | |
| `username` | TEXT, nullable | Set after successful auth |
| `auth_succeeded` | BOOLEAN | |
| `final_haunt_level` | SMALLINT | |
| `end_reason` | TEXT | disconnect, idle, lifetime, recording_cap, recording_failure, auth_failures, limit |

### `events`

| Column | Type | Notes |
|---|---|---|
| `session_id` | UUID, FK | `ON DELETE CASCADE` |
| `seq` | INTEGER | Monotonic within a session (R5.8) |
| `occurred_at` | TIMESTAMPTZ | UTC, millisecond precision (R5.12) |
| `event_type` | TEXT | See below |
| `payload` | JSONB | Type-specific fields; size-bounded |
| | | Primary key: (`session_id`, `seq`) |

**Event types:** `connect`, `auth_attempt`, `command`, `output`, `haunt_level`, `haunt_event`, `llm_request`, `detection`, `forward_denied`, `limit_rejected`, `truncated`, `disconnect`.

**Auth attempt payload:** username (as received), auth method, result, password fingerprint. **Never** the password.

### `detections`

| Column | Type | Notes |
|---|---|---|
| `detection_id` | BIGSERIAL, PK | |
| `session_id` | UUID, FK | `ON DELETE CASCADE` |
| `event_seq` | INTEGER | The triggering event (R5.6) |
| `rule_id` | TEXT | |
| `technique_id` | TEXT | |
| `detected_at` | TIMESTAMPTZ | |

### `llm_usage`

| Column | Type | Notes |
|---|---|---|
| `day` | DATE, PK | UTC calendar day |
| `request_count` | INTEGER | Daily cap 500 (R4.7) |
| `estimated_cost_usd` | NUMERIC | Budget tracking (R4.8) |

Increments use a single atomic `INSERT ... ON CONFLICT ... DO UPDATE ... RETURNING` statement, so concurrent sessions cannot exceed the cap.

### `dashboard_users`

| Column | Type | Notes |
|---|---|---|
| `username` | TEXT, PK | |
| `password_hash` | TEXT | Argon2 or bcrypt (real user accounts, unlike attacker passwords) |
| `role` | TEXT | `admin` or `judge` |

### Permissions (ADR-0004)

| Table | `honeypot_writer` | `dashboard_judge` | `dashboard_admin` |
|---|---|---|---|
| `sessions` | INSERT, UPDATE (`ended_at`, `final_haunt_level`, `end_reason` only) | SELECT | SELECT, DELETE |
| `events` | INSERT | SELECT | SELECT (deleted via cascade) |
| `detections` | INSERT | SELECT | SELECT (deleted via cascade) |
| `llm_usage` | SELECT, INSERT, UPDATE | none | SELECT |
| `dashboard_users` | none | none | SELECT |

Note: closing a session requires a narrow, column-level `UPDATE` on `sessions` for the honeypot. ADR-0004 should be amended to mention it.

## Key Flows

### 5.1 Command handling (interactive)

1. Shell I/O reads a line (asyncssh enforces the 4,096-character interactive limit).
2. Record a `command` event.
3. Command Engine parses the line.
   - Supported pipeline: execute against the session's VFS.
   - Unknown command or unsupported syntax: LLM Fallback (or a bash-style error).
4. Haunt Engine updates the level; if the cooldown allows, it may modify the output or the VFS.
5. ATT&CK Tagger evaluates the command; matching rules produce `detection` events.
6. Record `output` (and any `haunt_level`, `haunt_event`, `detection`) events.
7. Write the output and the next prompt to the terminal.

Steps 2 and 6 only enqueue events; database writes happen in the background writer.

### 5.2 Live update to the dashboard

1. The writer task inserts an event and sends `NOTIFY` with `{session_id, seq}`.
2. The dashboard API's listener fetches that event by ID.
3. The event is pushed to every connected SSE client, with `seq` as the SSE event ID.
4. A reconnecting client sends `Last-Event-ID`; the API resends events after that sequence number.

## Command Compatibility Table (R2.1)

**CONFIRMED** Every flag not listed produces the bash/coreutils-style "invalid option" error.

| Command | Supported flags and arguments |
|---|---|
| `pwd` | none |
| `cd` | `[dir]`, `~`, `-`, `..` |
| `ls` | `-l`, `-a`, `-h`, `-1`, combined (e.g. `-la`), `[paths...]` |
| `cat` | `-n`, `[files...]`, stdin |
| `echo` | `-n`, `[text...]` |
| `whoami` | none |
| `id` | none |
| `uname` | `-a`, `-s`, `-n`, `-r`, `-m` |
| `ps` | `aux`, `-ef`, none |
| `mkdir` | `-p`, `[dirs...]` |
| `touch` | `[files...]` |
| `rm` | `-r`, `-f`, `-rf`, `[paths...]` |
| `cp` | `-r`, `src dst` |
| `mv` | `src dst` |
| `find` | `[path]`, `-name <pattern>`, `-type f\|d` |
| `grep` | `-i`, `-v`, `-n`, `-c`, `pattern [files...]`, stdin |
| `head` | `-n N`, `[file]`, stdin |
| `tail` | `-n N`, `[file]`, stdin |
| `wc` | `-l`, `-w`, `-c`, `[files...]`, stdin |
| `exit` / `logout` | Ends the session (prints `logout`) |

Redirection: `>` and `>>` after `echo` and any command producing stdout (R2.15). Pipes: up to 3 stages (R2.6).

## Haunt Engine

### 7.1 Escalation thresholds (from R3)

| Level | Reached at | Feel |
|---|---|---|
| 0 | Start | Ordinary Ubuntu server |
| 1 | 60 s or 5 commands | Subtle anomalies |
| 2 | 120 s or 10 commands | Unsettling, increasingly personal |
| 3 | 240 s or 20 commands | The machine is aware of them |

### 7.2 Behavior scores (R3.4) **CONFIRMED**

| Behavior | Example | Score |
|---|---|---|
| Reading sensitive files | `cat /etc/shadow`, `cat ~/.ssh/id_rsa` | +3 |
| Enumerating users or processes | `cat /etc/passwd`, `ps aux` | +1 |
| Searching for credentials | `grep -r password`, `find / -name "*.pem"` | +2 |
| Privilege escalation attempts | `sudo`, `su` | +3 |
| Downloading or executing content | `wget`, `curl`, `chmod +x` | +2 |

**Score to level:** score 3 or more → at least level 1; 6 or more → at least level 2; 10 or more → level 3. The effective level is the highest of the time-based, count-based, and score-based levels, and never decreases.


## 7.3 Event Templates (R3.6)

**Decision: 15 event templates, 5 per level.**

All events are fictional, occur entirely within the emulated SSH environment, and increase in intensity as the attacker's engagement level rises.

### Level 1 — Subtle Anomalies

Small inconsistencies that could initially be mistaken for ordinary system behavior.

| ID | Event | Trigger and Behavior |
|---|---|---|
| L1-01 | Unexpected File | After `ls`, an unfamiliar `.cache.old` file appears in the current directory. |
| L1-02 | Timestamp Anomaly | `cat /var/log/syslog` reveals a log entry dated several minutes in the future. |
| L1-03 | Changing File Size | Two consecutive `ls -l` commands report different sizes for an untouched file. |
| L1-04 | Unfamiliar Process | `ps aux` includes a low-resource process named `observerd`, owned by `nobody`. |
| L1-05 | Missing Directory | A previously visible empty directory disappears from the next `ls` output without an intervening deletion. |

### Level 2 — Disturbing Anomalies

The simulated system appears to respond to the attacker's activity.

| ID | Event | Trigger and Behavior |
|---|---|---|
| L2-01 | Command Echo | A new file appears in the home directory with a filename derived from the attacker's most recent command. |
| L2-02 | Identity Confusion | `whoami` temporarily returns the username associated with an earlier fictional session. |
| L2-03 | Process Watcher | `ps aux` displays a process named `watching`, owned by `nobody`, whose elapsed runtime matches the current session. |
| L2-04 | Rewritten History | A simulated log file contains a command the attacker entered earlier, with a timestamp preceding its actual execution. |
| L2-05 | Unexplained Response | After reading a sensitive file, a new local file named `.still_here` appears containing `You already looked here.` |

### Level 3 — Direct Interaction

The environment appears aware of the session and begins addressing the attacker through fictional system artifacts.

| ID | Event | Trigger and Behavior |
|---|---|---|
| L3-01 | Prompt Mutation | The shell prompt changes from `user@host:~$` to `user@host:still_here$` for several commands. |
| L3-02 | Command Fragments | A simulated text file contains fragments of commands entered earlier in the same session. |
| L3-03 | Session Awareness | A fictional system log displays `SESSION ACTIVE: You have been here for 00:07:32.` using the actual elapsed session duration. |
| L3-04 | Persistent Observer | `ps aux` displays multiple fictional `observerd` processes, each named after a previously visited directory. |
| L3-05 | Final Message | A newly appearing file named `README.last` contains `The terminal remembers what you typed. It has been waiting for the next command.` |

### Event Execution Rules

1. **Level Gating:** Events may only trigger after the corresponding engagement level is reached.
2. **Monotonic Escalation:** The engagement level never decreases.
3. **No Repetition:** Each template triggers at most once per session.
4. **State Consistency:** Files, processes, and directory changes persist according to the simulated filesystem and process state unless an event explicitly reverses them.
5. **Command Compatibility:** Events must work with the confirmed shell command set. No additional executable commands are required.
6. **Session Isolation:** Events may reference commands and activity from the current session only, except for explicitly fictional historical artifacts.
7. **Controlled Frequency:** Trigger at most one event per command, with a configurable cooldown to avoid overwhelming the session.
8. **Deterministic Testing:** Event selection must support a fixed random seed for reproducible tests.

### Safety Requirements (R3.9)

All 15 templates must satisfy the following constraints:

- Events are entirely fictional and confined to the emulated SSH environment.
- No event references the attacker's real IP address.
- No event references the attacker's real geographic location.
- No event attempts to identify the attacker personally.
- No event threatens reporting, retaliation, or real-world harm.
- Any apparent surveillance or awareness is limited to simulated shell activity.
- Events must never execute real system commands or modify the host filesystem.

**Final Decision:** Approve R3.6 with 15 event templates across 3 engagement levels, subject to the execution and safety rules above.


## LLM Output Safety Validation (R4.11)

A response is discarded and replaced with a canned in-character response if **any** check fails:

1. **Empty or invalid:** empty, not valid UTF-8, or not a text response.
2. **Too long:** over 4,096 bytes after truncation rules (R4.5).
3. **Instruction leakage:** contains fragments of the system prompt or meta-text (e.g. "as an AI", "I cannot", "system prompt").
4. **Real-world threats:** matches a blocklist of real-world threat, retaliation, reporting, or doxxing phrases (R3.9).
5. **Out-of-character format:** contains markdown fences, explanations, or anything other than plausible terminal output.

After validation, terminal control sequences are stripped before writing to the terminal (R4.9).

**Limitation:** pattern-based validation cannot guarantee perfect detection. The design relies on layered controls (trusted system prompt, data delimiting, output validation, length limits, and the fact that output is display-only).

## Threat Model (STRIDE)

### Boundary A: Internet → Honeypot

| Threat | Example | Mitigation |
|---|---|---|
| Spoofing | Attacker poses as a judge | Demo credential never published; dashboard is a separate service |
| Tampering | Path traversal to host files | VFS-only path resolution; no host filesystem access (R2.12) |
| Repudiation | Unrecorded activity | Fail-closed recording (R5.11) |
| Information disclosure | Fingerprinting the honeypot | Banner masking; open question on algorithm lists |
| Denial of service | Connection floods, huge input, filesystem bombs | R8 limits, R2.9 limits, timeouts |
| Elevation of privilege | Command reaches a real shell | No `subprocess`/`eval` on attacker input; non-root process; container isolation |

### Boundary B: Honeypot → LLM API

| Threat | Example | Mitigation |
|---|---|---|
| Tampering | Prompt injection via commands | Data delimiting, output validation, display-only output |
| Information disclosure | Leaking the system prompt or API key | Leakage checks; key never in prompts or logs |
| Denial of service (cost) | Bot loops unknown commands | Per-session and daily caps, budget (R4.6–R4.8) |

### Boundary C: Honeypot → PostgreSQL

| Threat | Example | Mitigation |
|---|---|---|
| Tampering | Compromised honeypot rewrites history | `INSERT`-only role on event tables |
| Denial of service | Event flood | R8 limits, 10 MiB per-session cap |
| Injection | SQL injection via attacker text | Parameterized queries only |

### Boundary D: Dashboard API → Browser

| Threat | Example | Mitigation |
|---|---|---|
| Elevation of privilege | Judge performs admin actions | Server-side role checks plus database roles |
| Tampering | CSRF on delete | `SameSite=Strict` cookie plus CSRF token |
| Information disclosure | Stored XSS from attacker text | Plain-text rendering, escape stripping (R6.9, R6.10) |
| Spoofing | Credential stuffing on login | Login rate limiting; strong admin password |

## Correctness Properties

These properties must hold at all times and are verified by Hypothesis property-based tests (marked `[PBT]` in `requirements.md`):

- **VFS limits never exceeded (R2.9):** no sequence of VFS operations can exceed any configured limit (entry count, file size, total size, depth). A rejected operation leaves the tree unchanged.
- **Path confinement (R2.12):** for any path string — including inputs containing `..`, null bytes, or repeated slashes — VFS path resolution produces a node at or below the virtual root. The host filesystem is never consulted.
- **Haunt level monotonicity (R3.5):** for any sequence of commands and elapsed times, the haunt level never decreases.
- **Terminal output safety (R4.9, R6.10):** for any input text (including LLM output and attacker commands), the sanitized output contains no terminal control sequences.
- **Auth log safety:** for any attacker-supplied username, the auth log line is exactly one line and contains no control sequences or unescaped special characters.

## Error Handling

Each component's failure mode and recovery strategy:

| Component | Failure | Behavior |
|---|---|---|
| Admission Control | Global or per-IP cap reached | Close the TCP connection immediately; record a `limit_rejected` event |
| Auth Policy | Missing HMAC secret at startup | Process exits with a clear error message; no connections accepted |
| Event Recorder | Insert fails or queue full | The affected session is terminated; the error is logged internally (fail-closed, R5.11) |
| Event Recorder | NOTIFY fails | Logged; dashboard clients may miss live events but recording is unaffected |
| LLM Fallback | Timeout (5 s), API error, or failed validation | Return a canned in-character response; record the failure in `llm_usage` telemetry |
| LLM Fallback | Daily cap or budget exceeded | Return a canned response immediately without calling the API (R4.7, R4.8) |
| Command Engine | Parse error on unsupported syntax | Return a bash-style error message; never attempt host execution |
| Shell I/O | Exec command over 4,096 bytes | Reject with an error; record a `limit_rejected` event (R8.6) |
| VFS operations | Limit would be exceeded | Return an error result; leave the tree unchanged |
| Session watchdog | Idle timeout (300 s) or lifetime timeout (1,800 s) | Close the connection; record `disconnect` with the reason (R8.4, R8.5) |
| Dashboard API | Database connection lost | Return 503; SSE clients receive a retry hint and reconnect |
| PostgreSQL | Unavailable at honeypot startup | Honeypot fails to start; prevents unrecorded sessions |

No attacker-visible error message ever reveals internal implementation details, host paths, or stack traces.

## Testing Strategy

- **Unit tests:** parser, each command handler, VFS operations, haunt thresholds, ATT&CK rules, auth policy.
- **Property-based tests (Hypothesis), for every `[PBT]` criterion:**
  - R2.9: no sequence of VFS operations ever exceeds a limit, and rejected operations leave the tree unchanged.
  - R2.12: for any path string, resolution stays inside the virtual root.
  - R3.5: for any sequence of commands and times, the haunt level never decreases.
  - R4.9 and R6.10: for any text, the sanitized output contains no control sequences.
  - Log lines: for any username, the auth log line is a single safe line (from the spike).
- **Integration tests:** start the honeypot on port 0 and drive it with the asyncssh client (interactive and exec), as in the spike.
- **Host keys in tests:** generated in memory per test run; tests never read gitignored files.
- **Database tests:** run against a real PostgreSQL (a Docker container locally and a service container in CI), including role-permission tests (ADR-0004 verification).
- **Security tests:** forwarding and SFTP refusals, XSS payload rendering, CSRF rejection, judge permission checks.

## Deployment

- **Host:** one Linux VPS, at least 2 GB of RAM.
- **Before switching the honeypot to port 22:** move the real admin SSH daemon to another port, key-only, firewalled to the owner's IP, and verify login on it (R1.8 checklist from requirements).
- **Docker Compose:**
  - `honeypot`: publishes host port 22 to container port 2222, so the process never needs root (R1.2).
  - `api`: not published publicly; reachable on localhost or a VPN.
  - `postgres`: not published at all.
- **Networks:**
  - `honeypot_net`: honeypot ↔ postgres.
  - `dashboard_net`: api ↔ postgres.
  - The honeypot and api share no network.
- **Egress control [DECISION]:** the honeypot may reach only PostgreSQL and the LLM API. Options:
1. Put the honeypot on an `internal` Docker network (no internet) and route LLM requests through a small allowlisting egress proxy container.
2. Host firewall rules (the `DOCKER-USER` iptables chain) restricting the honeypot container's outbound traffic to the LLM API's addresses.
Option 1 is easier to reason about; option 2 avoids a fourth container but LLM API addresses can change.
- **Python version:** the container image uses the same Python version as development.
- **Secrets:** `.env` on the server only (database passwords, HMAC secret, LLM API key, demo credential).

## Open Questions

1. **IPv6:** should the honeypot also listen on IPv6?
2. **Fingerprint parity:** restrict advertised algorithms to match OpenSSH 9.6, and offer public-key auth that always fails (spike finding)?
3. **Forwarding refusal message:** return "administratively prohibited" like OpenSSH instead of "Connection refused"?
4. **Egress control:** proxy container or host firewall (section 11)?
5. **LLM provider:** still to be chosen (`tech.md`).
6. **R7 identity policy:** an ADR is required before any R7 work.