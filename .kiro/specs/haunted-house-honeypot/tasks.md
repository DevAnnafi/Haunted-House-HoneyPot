# Implementation Plan: Haunted House Honeypot

## Overview

Build an SSH honeypot that traps attackers in a fake haunted Linux environment, recording every action and mapping it to MITRE ATT&CK techniques shown on a live dashboard.

**Ownership key**
- [dev] Developer writes the implementation; Kiro may review, suggest, and write tests only.
- [kiro] Kiro writes the implementation; developer reviews before merging.

Tasks are ordered Must → Should → Could, then R7 (stretch) last. Each task is sized at roughly two hours or less.

## Tasks

## R1 — SSH Connection and Authentication (Must)

### T1.1 — Project scaffolding and virtual environment [kiro]
Set up the repository layout (`honeypot/`, `api/`, `dashboard/`, `shared/`, `migrations/`, `config/`, `tests/`, `docs/`), `requirements.txt` with pinned versions, `pyproject.toml` with ruff config, `.gitignore`, and a minimal `README.md` stub.
Satisfies: project conventions, tech.md layout.

### T1.2 — Auth policy: credential list and HMAC fingerprint [dev]
Implement `AuthPolicy` in `honeypot/auth.py`:
- `check(username, password) -> bool` against `config/credentials.toml` and the demo credential env var.
- `fingerprint(password) -> str` using HMAC-SHA-256 with domain-separated key derivation.
- Startup failure (raises `ConfigurationError`) when the HMAC secret env var is missing.
Satisfies: R1.3, R1.5, R1.6, R1.15.

### T1.3 — SSH listener and server class [dev]
Implement `HoneypotServer` and `create_honeypot_server` in `honeypot/ssh_server.py` using `asyncssh==2.24.1`. Set every option from the ADR-0001 configuration audit explicitly, including `sftp_factory=None` and `allow_scp=False` to disable SFTP and SCP. Wire `connection_made`, `begin_auth`, `validate_password`, `connection_lost`.
Satisfies: R1.1, R1.2, R1.13, R1.14.

### T1.4 — Forwarding and subsystem refusals [dev]
Override `connection_requested`, `server_requested`, `unix_connection_requested`, and `unix_server_requested` in `HoneypotServer` to log and return `False` / reject. Reject SSH agent and X11 forwarding. Add tests confirming that SFTP and SCP requests are refused (covered by the `sftp_factory=None` and `allow_scp=False` options set in T1.3).
Satisfies: R1.7, R1.10, R1.11, R1.12.

### T1.5 — Admission control [dev]
Implement `AdmissionController` in `honeypot/limits.py`:
- `try_acquire(ip) -> bool`: global cap 100, per-IP cap 5, per-IP rolling rate 10/60 s. All checks with no `await` between check and increment (atomic on the event loop).
- `release(ip)`: frees the slot.
Satisfies: R8.1, R8.2, R8.3, R8.10.

### T1.6 — Shell I/O loop and exec handler [dev]
Implement `run_interactive` and `run_exec` in `honeypot/shell.py`. Enforce the 4,096-byte exec command limit incrementally. Implement `sanitize_for_terminal`. Wire interactive prompt and EOF/`exit`/`BreakReceived` handling. Until T2.4 is complete, dispatch to a placeholder that echoes the input; replace it with the real command engine once T2.4 lands.
Satisfies: R1.4, R1.9, R4.9, R8.6.

### T1.7 — Tests: SSH layer (integration) [kiro]
Write `tests/test_ssh_integration.py`. Start the honeypot on port 0. Using an asyncssh client:
- Verify interactive shell is presented within 2 s after successful auth.
- Verify exec request returns simulated output and exit status.
- Verify rejected auth produces telemetry and no shell access.
- Verify forwarding, SFTP, SCP, agent, and X11 requests are all rejected.
- Verify 5 failed auth attempts terminate the connection (R8.7).
- Verify the setup timeout (R8.8; use the configurable timeout from T1.10 set to a short duration).
Use `try`/`finally` for server cleanup. All port-0 binding.
Satisfies: R1.1, R1.4, R1.6, R1.7, R1.9, R1.10, R1.11, R1.12, R8.7, R8.8.

### T1.8 — Tests: auth policy unit tests [kiro]
Write `tests/test_auth_policy.py`:
- Verify `check` accepts credentials from the list and the demo env var.
- Verify `check` rejects unknown pairs.
- Verify `fingerprint` is consistent for identical inputs under the same secret.
- Verify `fingerprint` differs for different secrets (domain separation).
- Verify startup raises `ConfigurationError` when the HMAC secret is absent.
- Property test (Hypothesis): for any username string, the produced auth log line is exactly one line and contains no unescaped control sequences.
Satisfies: R1.3, R1.5, R1.6, R1.15.

### T1.9 — Tests: admission control unit tests [kiro]
Write `tests/test_admission.py`:
- Verify the 101st concurrent connection is rejected.
- Verify the 6th concurrent connection from one IP is rejected.
- Verify the 11th attempt in a rolling 60 s is rejected.
- Verify `release` decrements the counter and allows a new acquisition.
- Verify unauthenticated connections count toward limits.
Satisfies: R8.1, R8.2, R8.3, R8.10.

### T1.10 — Honeypot entry point and config loader [dev]
Implement `honeypot/__main__.py` as the service entry point. Implement a config loader that reads all settings and secrets from environment variables (database URL, HMAC secret, LLM API key, demo credential, SSH port, host key path, idle timeout, lifetime limit, setup timeout). Raise `ConfigurationError` with a clear message on any missing required value. Apply the Windows selector event loop policy (see T9.2). Timeouts must be passed as configurable values so tests can use short durations.
Satisfies: R1.1, tech.md platform notes, tech.md deployment.

---

## R2 — Simulated Shell and Filesystem (Must)

### T2.1 — VFS data model and path resolution [dev]
Implement `Node`, `VirtualFS`, `VirtualFS.from_template`, and `resolve` in `honeypot/vfs.py`. Path resolution must handle `.`, `..`, repeated slashes, and absolute/relative paths entirely within the virtual root; `..` at `/` stays at `/`. No host filesystem access.
Satisfies: R2.2, R2.3, R2.12.

### T2.2 — VFS mutations with limit enforcement [dev]
Implement `create_file`, `write_file`, `mkdir`, `remove`, `copy`, `move` in `VirtualFS`. Check all limits before modifying the tree; a rejected operation must leave the tree unchanged. Limits: 1,000 entries, 64 KiB per file, 5 MiB total attacker-created content, depth 16.
Satisfies: R2.4, R2.9.

### T2.3 — Filesystem template [kiro]
Create `config/fs_template/` with a believable fake Ubuntu tree: `/`, `/home/user/`, `/root/`, `/etc/` (passwd, shadow, hostname, os-release, cron.d/), `/var/log/` (syslog, auth.log), `/tmp/`, `/usr/bin/`, `/bin/`. Populate files with plausible content (not real host data).
Satisfies: R2.2.

### T2.4 — Command engine: parser and registry [dev]
Implement `parse` and `execute` in `honeypot/commands/` with `Pipeline`, `CommandCall`, `CommandResult`, and the `REGISTRY`. Support `|` (up to 3 stages), `>`, `>>`. Unsupported syntax (`&&`, `||`, `;`, `&`, `$(...)`, backticks, `<`, here-docs, >3 stages) produces a bash-style error without host execution. Route unknown commands to the LLM fallback placeholder. Cap stdout at 256 KiB.
Satisfies: R2.1, R2.6, R2.7, R2.8, R2.9, R2.13.

### T2.5 — Command handlers: navigation and inspection (pwd, cd, ls, cat, echo) [dev]
Implement the five handlers in `honeypot/commands/handlers/`. Each supports only the flags listed in `design.md`. Invalid flags and paths produce Linux-compatible errors and correct exit codes.
Satisfies: R2.1, R2.3, R2.4, R2.5, R2.13.

### T2.6 — Command handlers: identity and system info (whoami, id, uname, ps) [dev]
Implement the four handlers in `honeypot/commands/handlers/`. `ps` returns a plausible fake process list; `uname` respects `-a`, `-s`, `-n`, `-r`, `-m`.
Satisfies: R2.1, R2.5.

### T2.7 — Command handlers: filesystem mutations (mkdir, touch, rm, cp, mv) [dev]
Implement the five handlers. Each delegates writes through VFS mutators so limits are always enforced. Appropriate Linux-compatible errors for all invalid cases.
Satisfies: R2.1, R2.4, R2.5, R2.9.

### T2.8 — Command handlers: search and filter (find, grep, head, tail, wc) [dev]
Implement the five handlers. Each supports only the flags from the compatibility table. `grep` and `wc` accept stdin from a pipe stage.
Satisfies: R2.1, R2.5, R2.6.

### T2.9 — Session manager and recorder interface [dev]
Implement `Session` dataclass and `Session.next_sequence` in `honeypot/session.py`. Wire per-session VFS copies, idle watchdog, and lifetime watchdog (durations configurable for tests). Confirm nothing mutable is shared between sessions. Also define a `Recorder` abstract interface (protocol or ABC) with a `record(event) -> None` method, and an `InMemoryRecorder` fake implementation that stores events in a list; this fake is used by all component tests in R2–R4 so they can emit events without a database.
Satisfies: R2.10, R2.11, R2.16, R5.1, R5.8, R8.4, R8.5, R8.11.

### T2.10 — Tests: VFS property-based tests [kiro]
Write `tests/test_vfs.py`:
- **[PBT] R2.9** — Hypothesis: any sequence of `create_file`, `write_file`, `mkdir`, `remove` on a fresh VFS never causes a limit to be exceeded; rejected operations leave the tree byte-for-byte unchanged.
- **[PBT] R2.12** — Hypothesis: for any path string (including inputs with `..`, null bytes, repeated slashes, Unicode), `resolve` returns a node at or below the virtual root and never raises a host filesystem error.
- Spot tests for `from_template` structure and standard directories.
Satisfies: R2.9 [PBT], R2.12 [PBT].

### T2.11 — Tests: command handler unit tests [kiro]
Write `tests/test_commands.py`. For each of the 19 commands test: expected output, Linux-compatible errors for invalid args/paths/flags, correct exit codes, state consistency between successive commands (`touch` → visible in `ls`, `rm` → absent from `ls`), and pipe pass-through. Verify output is capped at 256 KiB. Use `InMemoryRecorder` from T2.9.
Satisfies: R2.1, R2.3–R2.5, R2.6, R2.9, R2.13.

### T2.12 — Command exit status and `$?` (Could) [dev]
Implement `last_exit_status` tracking in `Session`. When an attacker submits `$?`, return the previous exit status without host-shell evaluation.
Satisfies: R2.14.

### T2.13 — Output redirection `>` and `>>` (Could) [dev]
Extend the parser and pipeline executor to handle `>` and `>>` targeting simulated files. Reject unsupported redirection syntax without filesystem modification.
Satisfies: R2.15.

---

## R3 — Progressive Haunting (Must)

### T3.1 — Haunt engine: state and escalation logic [dev]
Implement `HauntState`, `update`, and escalation thresholds in `honeypot/haunt.py`. Time thresholds (60 s / 120 s / 240 s), command-count thresholds (5 / 10 / 20), and score-based thresholds (3→L1, 6→L2, 10→L3). Effective level is the maximum; never decreases. Inject `clock` and `rng`.
Satisfies: R3.1, R3.2, R3.3, R3.4, R3.5.

### T3.2 — Haunt engine: event selection and templates [dev]
Implement `maybe_event`, event template data, and the 15 templates (L1-01–L1-05, L2-01–L2-05, L3-01–L3-05) in `honeypot/haunt.py`. Enforce: level gating, no-repeat per session, 15 s cooldown, deterministic RNG seed.
Satisfies: R3.6, R3.9, R3.10, R3.11.

### T3.3 — Haunt engine: VFS mutations and event logging [dev]
Implement the VFS side effects for haunting events (file appearances, process list modifications, prompt mutation). All changes apply to the session's own VFS only. Wire recording of `haunt_level` and `haunt_event` events via the `Recorder` interface.
Satisfies: R3.7, R3.8.

### T3.4 — Tests: haunt engine property and unit tests [kiro]
Write `tests/test_haunt.py`:
- **[PBT] R3.5** — Hypothesis: for any sequence of `(command, elapsed_seconds)` pairs, the haunting level produced by `update` never decreases.
- Spot tests for each of the three time thresholds and three command-count thresholds.
- Spot tests for each of the five behavioral triggers.
- Verify all 15 event templates are reachable and do not repeat within a session.
- Verify the 15 s cooldown prevents back-to-back events.
- Verify deterministic output with a fixed RNG seed.
- Verify no event references real IP or threatens real-world harm.
Use `InMemoryRecorder` from T2.9.
Satisfies: R3.1–R3.11, R3.5 [PBT].

---

## R4 — LLM Command Fallback (Must)

### T4.1 — LLM client module [dev]
Implement `respond(session, command) -> str` in `honeypot/llm.py`. Build the fixed system prompt with the command passed as clearly delimited data. Apply 8 KiB total / 4 KiB command limits. Call with `asyncio.wait_for` at 5 s. Return canned response on timeout, API error, or any validation failure. Never pass the API key in prompts or logs.
Satisfies: R4.1, R4.2, R4.3, R4.4, R4.13, R4.14.

### T4.2 — LLM output validation [dev]
Implement the five validation checks from `design.md` section 8: empty/invalid, too long (>4,096 bytes), instruction leakage, real-world threat phrases, out-of-character format. Strip terminal control sequences from accepted output before returning.
Satisfies: R4.5, R4.9, R4.11.

### T4.3 — Per-session and global API request limits [dev]
Implement the 20-per-session cap in `Session`. Implement the 500-per-day global cap using `llm_usage` with an atomic `INSERT … ON CONFLICT … DO UPDATE … RETURNING` so concurrent sessions cannot exceed it; the counter survives restarts (stored in PostgreSQL).
Satisfies: R4.6, R4.7.

### T4.4 — Tests: LLM fallback unit tests (with mocked LLM client) [kiro]
Write `tests/test_llm.py` using a mock LLM client:
- Verify timeout returns a canned response within 5.5 s.
- Verify API error returns a canned response without raising.
- Verify each of the five validation failures discards the response.
- Verify the 20-request session cap stops calls and returns canned responses.
- Verify the daily global cap stops calls atomically (simulate concurrent exhaustion).
- **[PBT] R4.9** — Hypothesis: for any string (including ANSI sequences), `sanitize_for_terminal` returns text with no terminal control sequences.
- Verify LLM output is display-only and cannot change VFS or session state (R4.12).
Satisfies: R4.1–R4.9, R4.11, R4.12 [PBT].

### T4.5 — Spending cap (Should) [dev]
Implement the configurable daily budget (default $2.00) in `honeypot/llm.py`. Before each request, reserve an upper-bound cost and check whether the budget would be exceeded; if so, return a canned response. Record estimated cost in `llm_usage`.
Satisfies: R4.8.

---

## R5 — Session Recording and ATT&CK Mapping (Must)

### T5.1 — PostgreSQL schema and migrations [kiro]
Write `migrations/001_initial.sql` creating tables `sessions`, `events`, `detections`, `llm_usage`, `dashboard_users` exactly as specified in the design. Create roles `schema_owner`, `honeypot_writer`, `dashboard_admin`, `dashboard_judge` with the permissions from ADR-0004. Add the column-level UPDATE grant for `honeypot_writer` on `sessions`.
Satisfies: R5.1, R5.2, R5.6, R5.14 (schema).

### T5.2 — Event recorder (PostgreSQL-backed) [dev]
Implement the PostgreSQL-backed `Recorder` in `honeypot/recorder.py`, conforming to the `Recorder` interface defined in T2.9. Assign sequence numbers from `Session.next_sequence`. Enforce the 10 MiB per-session cap (write a bounded truncation marker then terminate on overflow). Use a bounded `asyncio.Queue` and a background writer task with a `psycopg` pool. Send `NOTIFY honeypot_events` with `{session_id, seq}` only. Fail closed: terminate the session if an insert fails or the queue is full.
Satisfies: R5.1–R5.4, R5.8, R5.10, R5.11, R5.12, R8.9.

### T5.3 — ATT&CK tagger [dev]
Implement `Rule`, `tag`, and the 15 initial rules in `honeypot/attack.py` (at least 10 required; all 15 are defined). Wire `tag` to run after each command event and produce `detection` events.
Satisfies: R5.5, R5.6, R5.7.

### T5.4 — Tests: event recorder integration tests [kiro]
Write `tests/test_recorder.py` against a real PostgreSQL (Docker service in CI):
- Verify unique session IDs.
- Verify connection metadata fields are recorded on session start.
- Verify command records include input, output, and exit status.
- Verify auth attempt records contain HMAC fingerprints and no plaintext passwords.
- Verify sequence numbers are monotonically increasing within a session.
- Verify the 10 MiB cap writes a bounded marker and terminates the session.
- Verify recording failure (mocked insert error) terminates the session.
- Verify UTC timestamps with millisecond precision.
- Verify role permissions: `honeypot_writer` cannot SELECT from `dashboard_users`; `dashboard_judge` cannot DELETE.
Satisfies: R5.1–R5.4, R5.8, R5.10, R5.11, R5.12, R5.14.

### T5.5 — Tests: ATT&CK tagger unit tests [kiro]
Write `tests/test_attack.py`:
- For each of the 15 rules, verify a matching event produces the correct technique ID and rule ID.
- Verify an unmatched command produces no detection.
- Verify at least 10 distinct rules are present.
- Verify detection records contain rule_id, technique_id, timestamp, session_id, and event_seq.
Satisfies: R5.5–R5.7.

### T5.6 — Recording retention and manual deletion (Must portion) [kiro]
Implement the `DELETE /api/sessions/{id}` endpoint (admin role only) in `api/`. Reject judge and unauthenticated requests with 403. Use the `dashboard_admin` database role, which cascades to events and detections. Require the CSRF token.
Satisfies: R5.9 (Must portion), R6.11, R6.16.

### T5.7 — Automatic 30-day recording expiry (Could) [kiro]
Add a scheduled job (e.g., a daily asyncio task or pg_cron) that deletes sessions where `ended_at < now() - interval '30 days'`. Update deployment docs to note when this is active.
Satisfies: R5.9 (Could portion).

### T5.8 — Command flow integration [dev]
Wire the full per-command pipeline described in `design.md` section 5.1: shell receives input → command engine executes → haunt engine runs `update` and `maybe_event` → ATT&CK tagger runs `tag` → recorder persists the command and any detection or haunt events, all in that order within a single async turn. Error handling: if a command handler raises, convert the error into a bash-style error result (stderr text and a non-zero exit status); the haunt engine, ATT&CK tagger, and recorder still run on that result. If recording fails, terminate the session (fail closed, R5.11).
Satisfies: R2.1, R3.1, R5.5, R5.6.

---

## R6 — Live Dashboard and Session Replay (Must)

### T6.1 — Dashboard API: shared Pydantic models [kiro]
Define event, session, detection, and SSE payload schemas in `shared/models.py` as Pydantic models. Import them in both `honeypot/` and `api/`.
Satisfies: R5.1, R6.2, R6.4 (data layer).

### T6.2 — Dashboard API: auth, login/logout, CSRF [kiro]
Implement `POST /api/login`, `POST /api/logout` in `api/`. Set `HttpOnly`, `Secure`, `SameSite=Strict` session cookies. Issue a CSRF token for state-changing requests. Rate-limit login attempts. Hash dashboard user passwords with Argon2/bcrypt.
Satisfies: R6.1, R6.11.

### T6.3 — Dashboard API: session and event endpoints [kiro]
Implement:
- `GET /api/sessions` — paginated list (admin, judge).
- `GET /api/sessions/{id}` — metadata (admin, judge).
- `GET /api/sessions/{id}/events` — events paginated at 100 per page (admin, judge).
- `GET /api/detections` — ATT&CK detections (admin, judge).
Enforce role checks server-side.
Satisfies: R5.9, R5.13, R6.2, R6.4, R6.6, R6.11, R6.14, R6.15, R6.16.

### T6.4 — Dashboard API: SSE live-update stream [kiro]
Implement `GET /api/stream` in `api/`. One dedicated connection runs `LISTEN honeypot_events`; each notification fetches the row and fans it out to connected SSE clients. SSE event IDs are sequence numbers for `Last-Event-ID` reconnection recovery. Auth-guard the endpoint.
Satisfies: R6.3, R6.12, R6.13.

### T6.5 — Frontend: Next.js project setup, login page, and static serving [kiro]
Scaffold `dashboard/` with Next.js + TypeScript + Tailwind CSS as a static export. Implement the login page. Configure all attacker-supplied and LLM-generated text to render as plain text (never `dangerouslySetInnerHTML`). Configure the FastAPI app to serve the Next.js static export from `dashboard/out/` so a single `api/__main__.py` entry point starts both the API and the frontend. Implement `api/__main__.py` with the Windows selector event loop policy applied before startup.
Satisfies: R6.1, R6.9, tech.md platform notes.

### T6.6 — Frontend: live session overview page [kiro]
Implement the overview page. Display active sessions (ID, source IP, username, start time, command count, haunting level). Subscribe to the SSE stream and update the view in real time. Render all attacker text as plain text.
Satisfies: R6.2, R6.3, R6.5, R6.9.

### T6.7 — Frontend: session detail and replay page [kiro]
Implement the session detail page showing commands, outputs, auth events, haunting events, and ATT&CK detections in chronological order. Implement basic replay (play through events in sequence). Strip or escape terminal escape sequences before display.
Satisfies: R6.6, R6.7, R6.9, R6.10.

### T6.8 — Frontend: ATT&CK detections view [kiro]
Implement the detections page. Display technique ID, session, timestamp, and triggering command for each detection. All text rendered as plain text.
Satisfies: R6.4, R6.9.

### T6.9 — Frontend: replay controls (Could) [kiro]
Add pause, resume, restart, and 1×/2×/4× speed controls to the replay page.
Satisfies: R6.8.

### T6.10 — Tests: dashboard API tests [kiro]
Write `tests/test_api.py` using FastAPI's `TestClient` / `AsyncClient` against a test database:
- Verify unauthenticated requests to all protected endpoints return 401/403.
- Verify judge can list sessions and view events but cannot delete recordings or change configuration.
- Verify admin can delete a recording and the cascade removes events and detections.
- Verify CSRF token is required for state-changing requests.
- Verify SSE stream delivers a new event within 2 s after `NOTIFY` (integration).
- Verify `Last-Event-ID` reconnection replays missed events.
- Verify session event list is paginated at 100 per page.
- Verify stored XSS payloads in event text are returned as plain strings, not rendered HTML.
Satisfies: R5.9, R6.1, R6.3, R6.11, R6.13–R6.16.

### T6.11 — Tests: terminal escape sanitization property test [kiro]
Write `tests/test_sanitize.py`:
- **[PBT] R4.9 / R6.10** — Hypothesis: for any arbitrary byte string cast to text, `sanitize_for_terminal` returns a string containing no ANSI/VT100/OSC control sequences (verify with an independent regex).
Satisfies: R4.9 [PBT], R6.10 [PBT].

### T6.12 — Judge access documentation and submission prep [kiro]
Add a `README` section documenting: judge dashboard URL and login instructions; a separate simulated SSH test-login with attacker credentials to try; administrator credential handling (not committed). Explicitly note that no admin credentials or secrets are included.
Satisfies: R6.16 (documentation requirement).

### T6.13 — CLI: dashboard user management [kiro]
Implement a CLI command (e.g., `python -m api create-user`) that creates admin and judge dashboard users with Argon2/bcrypt-hashed passwords and stores them in the `dashboard_users` table. Accepts `--username`, `--role`, and `--password` (prompted securely if omitted). Requires the `schema_owner` database role (`dashboard_admin` has SELECT-only access to `dashboard_users` and cannot insert).
Satisfies: R6.1, R6.11.

---

## R8 — Abuse Prevention and Resource Limits (Must)

### T8.1 — Idle and lifetime watchdogs [dev]
Implement the idle watchdog and lifetime watchdog in `honeypot/session.py` with configurable durations (defaults: 300 s idle, 1,800 s lifetime) so tests can pass short values without an injected clock. Use `asyncio.call_later` or a background task. On expiry, close the connection and record a `disconnect` event with the reason.
Satisfies: R8.4, R8.5.

### T8.2 — Tests: resource limit integration tests [kiro]
Write `tests/test_limits.py` using the honeypot on port 0. Configure all timeouts (idle, lifetime, setup) to short durations via the config loader (T1.10) rather than injecting a clock:
- Verify the 101st concurrent connection is rejected.
- Verify the 6th concurrent connection from one IP is rejected.
- Verify the 11th attempt within a rolling 60 s is rejected.
- Verify idle connection is closed after the configured idle timeout.
- Verify lifetime limit closes the connection after the configured lifetime limit.
- Verify a 4,097-byte exec command is rejected without an LLM call and without unbounded buffering.
- Verify 5 failed auth attempts terminate the connection.
- Verify the connection is closed after the configured setup timeout.
- Verify cleanup: connection slot and VFS are released after disconnect.
Satisfies: R8.1–R8.8, R8.10, R8.11.

### T8.3 — Rejection telemetry (Should) [dev]
In `AdmissionController.try_acquire` and the shell input path, record a bounded `limit_rejected` event when a request is rejected. Include reason, timestamp, and permitted connection metadata only; never the oversized input.
Satisfies: R8.12.

---

## Infrastructure and Deployment

### T9.1 — Docker Compose configuration [kiro]
Write `docker-compose.yml` with three services: `honeypot` (publishes host 22 → container 2222), `api` (internal only), `postgres` (internal only). Define `honeypot_net` and `dashboard_net` networks. Set the honeypot container to run as the unprivileged `honeypot` user. Load secrets from `.env`.
Satisfies: R1.2, R1.8, tech.md deployment.

### T9.2 — Windows selector event loop shim [kiro]
Add the `asyncio.WindowsSelectorEventLoopPolicy` guard at all Python entry points (`honeypot/__main__.py`, `api/__main__.py`) so the async psycopg driver works on the development machine. No-op on Linux (production). (Entry points are created in T1.10 and T6.5; this task ensures the guard is present in both.)
Satisfies: tech.md platform notes.

### T9.3 — CI pipeline [kiro]
Write a GitHub Actions workflow (`.github/workflows/ci.yml`) that:
- Runs `ruff format --check` and `ruff check`.
- Starts a PostgreSQL service container.
- Runs `pytest -v` with the database URL pointed at the service container.
- Fails on any test error or lint violation.
Satisfies: testing conventions.

### T9.4 — Deployment documentation [kiro]
Write `docs/deployment.md` covering: VPS prerequisites, moving the real SSH daemon to another port, running `docker compose up --build`, generating and storing the host key, setting environment variables, verifying the firewall, creating the first dashboard user with T6.13, and the note that automatic 30-day expiry is not enforced until T5.7 is complete.
Satisfies: R1.8, R5.9, tech.md deployment.

### T9.5 — Kiro hooks [kiro]
Write `.kiro/hooks/` entries for:
- **On Python file save:** run `pytest` scoped to the file's corresponding test module (if one exists).
- **On Python file save under `honeypot/`:** check that any new ATT&CK rule definitions use a valid MITRE technique ID format (`T\d{4}(\.\d{3})?`).
- **On Python file save under `honeypot/`:** flag any use of `subprocess`, `os.system`, `eval`, or `exec` and report a warning in the Kiro agent output.
Satisfies: project conventions, security rules.

### T9.6 — Egress control for the honeypot container [dev]
Implement the egress control option chosen from `design.md` section 11 to restrict outbound network access from the honeypot container to PostgreSQL and the LLM API only. Document the chosen approach and any VPS-level configuration required in `docs/deployment.md`.
Satisfies: R1.7, tech.md deployment.

---

## Submission

### T10.1 — Early live deployment and data collection [dev]
Deploy to the VPS as soon as the SSH layer, filesystem, command handlers, and PostgreSQL recorder work (target Nov 22–24), so real attacker data accumulates for several days before the demo. Redeploy as haunting, the LLM fallback, and the dashboard land. Verify all Must-priority features end-to-end in production before recording the demo.
Satisfies: hackathon submission requirements.

### T10.2 — Demo video [dev]
Record the demo video (under 3 minutes). Show: an attacker SSHing in, the haunting escalating, and the dashboard lighting up with ATT&CK detections in real time.
Satisfies: hackathon submission requirements.

### T10.3 — Devpost project story and Kiro usage write-up [dev]
Write the Devpost project story covering what was built, why, and how. Write the Kiro usage write-up describing how Kiro was used throughout development (specs, code generation, tests, hooks, documentation).
Satisfies: hackathon submission requirements.

### T10.4 — Blog post and social post [dev]
Publish the blog post about the project. Post the `#KiroweenHackathon26` social post.
Satisfies: hackathon submission requirements.

### T10.5 — Best Student Project details [dev]
Prepare Best Student Project eligibility details: student email address and current enrollment information.
Satisfies: hackathon submission requirements.

---

## R7 — Persistent Attacker Environments (Stretch / Could)

> All R7 tasks are Could priority. Do not begin any R7 task until R1–R6 and R8 Must criteria are complete and an ADR covering the R7 identity policy is approved.

### T7.1 — ADR: attacker identity policy [dev]
Write `docs/adr/0007-attacker-identity.md` defining the identity key derivation, matching policy, collision safety statement, and expiry design before any R7 code is written.
Satisfies: R7.2, R7.12.

### T7.2 — Persistent environment store [dev]
Add `persistent_environments` table in a new migration. Implement serialisation and deserialisation of `VirtualFS` and `HauntState` to/from JSONB. Apply all R2 and R8 resource limits to restored environments.
Satisfies: R7.3, R7.4, R7.6, R7.11.

### T7.3 — Identity matching and session routing [dev]
Implement the provisional identity key derivation in `honeypot/identity.py`. Wire session startup to query for a matching persistent environment; fall back to a fresh environment on match failure, ambiguity, or load error. Record the restoration outcome.
Satisfies: R7.2, R7.3, R7.5, R7.13.

### T7.4 — Concurrent access and exclusive ownership [dev]
When two sessions resolve to the same provisional identity key, allow only one to acquire the persistent environment; give additional concurrent sessions a fresh isolated environment. Use a database advisory lock or `SELECT … FOR UPDATE SKIP LOCKED`.
Satisfies: R7.7.

### T7.5 — 7-day expiry and last-activity updates [dev]
Update `last_activity` on successful restoration. Add a daily job that deletes persistent environments inactive for more than 7 days.
Satisfies: R7.8, R7.9.

### T7.6 — Command history context for the haunt engine [dev]
Expose a bounded prior command-history context from the restored environment to the haunting engine. Enforce R4 context limits; never expose another environment's raw commands.
Satisfies: R7.10.

### T7.7 — Tests: persistent environment (Could) [kiro]
Write `tests/test_persistence.py`:
- Verify matching credentials and IP restore the previous VFS and haunting state.
- Verify credentials alone (different IP) do not merge environments.
- Verify ambiguous identity creates a fresh environment.
- Verify concurrent matching sessions cannot corrupt the shared environment.
- Verify environments expire after 7 days of inactivity.
- Verify unique session IDs across reconnects to the same environment.
- Verify MVP functionality (R1–R6, R8) is unaffected when persistence is disabled.
Satisfies: R7.1–R7.15.

## Task Dependency Graph

```json
{
  "waves": [
    {
      "wave": 1,
      "tasks": ["T1.1"],
      "note": "Project scaffolding — unblocks everything"
    },
    {
      "wave": 2,
      "tasks": ["T1.2", "T1.3", "T1.4", "T1.5", "T1.6", "T2.1", "T2.2", "T2.3"],
      "note": "SSH layer (dev) and VFS core (dev) + filesystem template — all depend on T1.1 only"
    },
    {
      "wave": 3,
      "tasks": ["T1.7", "T1.8", "T1.9", "T1.10", "T2.4", "T2.5", "T2.6", "T2.7", "T2.8", "T2.9"],
      "note": "SSH tests, entry point, command engine, session manager + Recorder interface — depend on wave 2"
    },
    {
      "wave": 4,
      "tasks": ["T2.10", "T2.11", "T2.12", "T2.13", "T3.1", "T3.2", "T3.3", "T4.1", "T4.2", "T4.3", "T5.1", "T8.1", "T8.3"],
      "note": "VFS tests, Could tasks, haunt engine, LLM client, DB schema, watchdogs — depend on wave 3"
    },
    {
      "wave": 5,
      "tasks": ["T3.4", "T4.4", "T4.5", "T5.2", "T5.3", "T5.6", "T5.7", "T8.2", "T9.1", "T9.2", "T9.3", "T9.4", "T9.5"],
      "note": "Haunt + LLM tests, PostgreSQL recorder, ATT&CK tagger, manual deletion, infra/CI/docs — depend on wave 4"
    },
    {
      "wave": 6,
      "tasks": ["T5.4", "T5.5", "T5.8", "T6.1", "T9.6"],
      "note": "Recorder + tagger tests, command flow wiring, shared models, egress control — depend on wave 5"
    },
    {
      "wave": 7,
      "tasks": ["T6.2", "T6.3", "T6.4", "T6.5"],
      "note": "Dashboard API (auth, endpoints, SSE) and frontend setup — depend on T6.1"
    },
    {
      "wave": 8,
      "tasks": ["T6.6", "T6.7", "T6.8", "T6.9", "T6.10", "T6.11", "T6.12", "T6.13"],
      "note": "Frontend pages, replay controls, API tests, sanitization test, docs, user CLI — depend on wave 7"
    },
    {
      "wave": 9,
      "tasks": ["T10.1"],
      "note": "Early live deployment — starts after T2.8 + T5.2 (can begin mid-wave 5)"
    },
    {
      "wave": 10,
      "tasks": ["T10.2", "T10.3"],
      "note": "Demo video and Devpost write-up — after all Must work verified end-to-end"
    },
    {
      "wave": 11,
      "tasks": ["T10.4", "T10.5"],
      "note": "Blog post, social post, student eligibility — after T10.2 + T10.3"
    },
    {
      "wave": 12,
      "tasks": ["T7.1"],
      "note": "R7 stretch — only after R1–R6 + R8 Must complete and ADR-0007 approved"
    },
    {
      "wave": 13,
      "tasks": ["T7.2"],
      "note": "Persistent environment store — depends on T7.1"
    },
    {
      "wave": 14,
      "tasks": ["T7.3"],
      "note": "Identity matching — depends on T7.2"
    },
    {
      "wave": 15,
      "tasks": ["T7.4", "T7.5", "T7.6"],
      "note": "Concurrent access, expiry, command history context — depend on T7.3"
    },
    {
      "wave": 16,
      "tasks": ["T7.7"],
      "note": "Persistence tests — depends on T7.4–T7.6"
    }
  ]
}
```

```
T1.1 (scaffolding)
└── T1.2, T1.3, T1.4, T1.5, T1.6 (SSH layer — developer)
    ├── T1.7 (SSH integration tests)
    ├── T1.8 (auth policy tests)
    ├── T1.9 (admission control tests)
    └── T1.10 (entry point + config loader — developer)
        └── T8.2 (resource limit tests use configurable timeouts from T1.10)

T1.1
└── T2.1, T2.2 (VFS core — developer)
    ├── T2.3 (filesystem template)
    ├── T2.4–T2.9 (command engine + session + Recorder interface — developer)
    │   ├── T2.10 (VFS property tests)
    │   ├── T2.11 (command handler tests — uses InMemoryRecorder)
    │   └── T2.12, T2.13 (Could: exit status, redirection)
    └── T2.9 → T3.1–T3.3 (haunt engine — developer)
        └── T3.4 (haunt tests — uses InMemoryRecorder)

T2.4, T2.9
└── T4.1–T4.3 (LLM fallback — developer)
    ├── T4.4 (LLM tests — uses mock LLM client)
    └── T4.5 (Should: spending cap)

T1.1
└── T5.1 (DB schema migration) ← T1.2, T2.9, T3.1, T4.1
    ├── T5.2 (PostgreSQL recorder — implements Recorder interface from T2.9)
    │   └── T5.4 (recorder integration tests)
    ├── T5.3 (ATT&CK tagger — 15 rules)
    │   └── T5.5 (ATT&CK tagger tests)
    ├── T5.6 (manual deletion endpoint)
    ├── T5.7 (Could: auto-expiry)
    └── T5.8 (command flow integration — wires shell→engine→haunt→tagger→recorder)

T5.1, T5.2
└── T6.1 (shared Pydantic models)
    ├── T6.2–T6.4 (dashboard API)
    │   ├── T6.10 (API tests)
    │   └── T6.13 (dashboard user CLI)
    └── T6.5 (frontend setup + api/__main__.py + static serving)
        ├── T6.6–T6.8 (frontend pages)
        ├── T6.9 (Could: replay controls)
        └── T6.11 (sanitization property test)

T1.1
└── T9.1–T9.6 (infra / Docker / CI / docs / hooks / egress — parallel with R2–R6)
    └── T9.5 depends on T5.3 (ATT&CK rule format check needs rules to exist)

[Submission — T10.1 starts after T2.8 + T5.2 (early deploy); T10.2 onward after all Must work is complete]
T2.8, T5.2 → T10.1 → T10.2, T10.3 → T10.4, T10.5

[R7 — stretch, only after R1–R6 + R8 Must complete]
T7.1 → T7.2 → T7.3 → T7.4, T7.5, T7.6 → T7.7
```

## Notes

- **Ownership:** Tasks marked [dev] are developer-owned; Kiro may review, write tests, and suggest improvements but must not produce the implementation. Tasks marked [kiro] are Kiro-owned; the developer reviews before merging.
- **Security-critical path:** T1.2–T1.6, T1.10, T2.1–T2.9, T3.1–T3.3, T4.1–T4.3, T5.2–T5.3, T5.8 all touch attacker-controlled input or authentication logic. No shortcuts on input sanitization, VFS path isolation, HMAC fingerprinting, or the command-to-recorder pipeline.
- **Recorder interface (T2.9):** Every component from R2 onward emits events through the `Recorder` interface. Tests use `InMemoryRecorder`; production uses the PostgreSQL-backed recorder from T5.2. This keeps R2–R4 tests free of database dependencies.
- **Configurable timeouts (T1.10, T8.1):** Idle timeout, lifetime limit, and setup timeout are config values, not constants. Tests in T8.2 and T1.7 pass short durations via the config loader instead of injecting a clock or sleeping.
- **SFTP/SCP refusal:** Disabled via `sftp_factory=None` and `allow_scp=False` in T1.3. T1.4 covers the four TCP/Unix forwarding overrides and verifies the SFTP/SCP refusal in tests.
- **ATT&CK rules:** T5.3 and T5.5 use 15 rules (matching `design.md`), not 17.
- **Port 0 rule:** Every test that starts a server must bind to port 0 and clean up in `try`/`finally`.
- **R7 gate:** Do not start any T7.x task until all R1–R6 and R8 Must-priority acceptance criteria pass and ADR-0007 is approved.
- **Could tasks** (T2.12, T2.13, T4.5, T5.7, T6.9, T8.3) and **Should tasks** are deferred if deadline pressure requires cuts. The demo moment (SSH in, haunt activates, dashboard lights up) requires only the Must tasks.
- **Submission gate:** T10.1 (early live deployment) starts as soon as T2.8 and T5.2 are complete. T10.2 onward wait until all Must-priority work is verified end-to-end in production.
