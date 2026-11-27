# Development Log — Haunted House Honeypot

## November 4, 2026 — Project Setup

### Completed
- Created the GitHub repository for Haunted House Honeypot.
- Selected the project concept for the Kiroween 2026 hackathon.
- Created the initial architecture diagram showing the SSH server, simulated shell, haunting engine, LLM fallback, session recording, MITRE ATT&CK mapping, and live dashboard.
- Began organizing the project around Kiro's specification-driven development workflow.

### Status
Project initialized and initial architecture diagram created. Implementation not yet started.

---

## November 5, 2026 — Product Requirements and Security Planning

### Completed
- Defined the product vision, target users, demo experience, and seven product goals.
- Established the MVP boundary around SSH emulation, escalating haunting, LLM fallback, session recording, MITRE ATT&CK mapping, and the live dashboard.
- Moved persistent attacker environments into a stretch goal.
- Established security constraints for command execution, filesystem isolation, outbound traffic, and untrusted LLM input.
- Defined the haunting's slow-burn progression, playful horror style, and prohibition on real-world threats or retaliation.
- Created the Kiro steering documentation, including `.kiro/steering/product.md`.
- Finalized `requirements.md`, covering R1–R8 with EARS acceptance criteria, MoSCoW priorities, and verification checklists.
- Identified property-based testing candidates for filesystem limits, path traversal, haunting progression, and output sanitization.
- Added requirements for read-only judge access, session recording, SSH abuse prevention, and resource limits.
- Reviewed and corrected the requirements before beginning the detailed engineering design.

### Design decisions
- Fresh simulated environments for each session in the MVP.
- Seven-day attacker state retention proposed for the persistence stretch goal.
- Attacker identity matching remains unresolved. Common SSH credentials cannot safely identify a unique attacker.
- SSH forwarding, SFTP, SCP, and other potentially dangerous SSH features will be rejected.
- Passwords will not be stored in plaintext; keyed HMAC fingerprints will be used for correlation.
- The honeypot will run without root privileges and will never execute attacker commands on the host.
- The MVP will prioritize Must requirements. Optional features will be implemented only if time permits.
- Kiro will assist with specifications, implementation, and tests, while architectural and security decisions remain subject to human review.

### Challenges / Open questions
- **Attacker identity:** Bots frequently reuse the same default SSH credentials. Using credentials alone to identify returning attackers could incorrectly merge unrelated sessions.
- **Realistic shell behavior:** The simulated environment needs believable Linux commands and error messages without allowing actual host execution.
- **Project scope:** The original feature set was too large for the hackathon timeline, requiring clear Must, Should, and Could priorities.
- **Persistent environments:** A reliable identity-matching strategy must be documented before implementing the stretch goal.

### Lessons / surprises
- **Credential collisions:** Multiple attackers can use identical usernames and passwords. I learned that credentials are useful telemetry but are not reliable proof of identity.
- **SSH forwarding:** Allowing forwarding could turn the honeypot into an open proxy. I had to consider SSH features beyond interactive command execution.
- **Stored XSS:** Attackers control the text recorded by the honeypot. That text could target the administrator's browser if the dashboard renders it unsafely.
- **Kiro workflow:** The hackathon evaluates how Kiro contributes to development. I need to document where Kiro helped and where I made, reviewed, or changed decisions myself.

### Next steps
1. Write **ADR-0001** to select the programming language and SSH server library.
2. Write **ADR-0002** to document the password HMAC strategy and credential-handling tradeoffs.
3. Create `design.md`, defining component responsibilities, interfaces, data models, security boundaries, and deployment architecture.
4. Create `tasks.md` from the approved requirements and design, prioritizing Must requirements.
5. Begin implementing the SSH honeypot MVP, starting with simulated authentication, shell interaction, and session recording.

### Status
Product requirements and engineering acceptance criteria finalized. Initial architecture diagram completed. Detailed system design and implementation are next. No functional implementation or tests completed yet.

# Devlog — November 5–8, 2026

### Completed
- Wrote ADR-0001 (language and SSH library): compared Python + AsyncSSH, Python + Paramiko,
  and TypeScript + ssh2. Chose Python 3.12+ with `asyncssh==2.24.1`.
- Audited AsyncSSH's server defaults from its source code and recorded an explicit
  security configuration for every relevant option.
- Built a throwaway spike (`spikes/asyncssh/`) that validated all six ADR acceptance checks:
  connection, auth logging, forwarding/SFTP rejection, custom banner, persistent host key,
  and Hypothesis + asyncio tests.
- Wrote the first property-based test (Hypothesis) and the first end-to-end async test
  (pytest-asyncio + asyncssh client).
- Marked ADR-0001 **Accepted** (2026-11-08).

### Design decisions
- AsyncSSH handles transport, auth, and session lifecycle; a separate application layer
  will handle command emulation, filesystem, haunting, recording, and LLM fallback.
- Every security-relevant AsyncSSH option is set explicitly, even when the default is safe.
- Full-project checks (connection limits, 100-connection load test, dependency review,
  host isolation) are tracked in requirements verification, not in the ADR.

### Lessons and surprises
- **AsyncSSH allows agent forwarding by default.** Only reading the source revealed it;
  the honeypot must set `agent_forwarding=False` explicitly.
- **One connection got 6 password guesses.** AsyncSSH offers both keyboard-interactive and
  password auth, and the client tried 3 of each. The failure limit (R8.7) must be my own
  per-connection counter across both methods.
- **A terminal resize would have killed every session.** Resizing raises
  `TerminalSizeChanged`; catching it outside the read loop ended the session. It must be
  caught inside the loop and the read restarted.
- **The banner isn't the only fingerprint.** Even with an OpenSSH version string, the
  advertised algorithm list, an unrecognized extension, and the offered auth methods still
  reveal AsyncSSH to a tool like ssh-audit.
- **Hypothesis caught a bug on its first run.** The extracted log formatter still referenced
  `self`; Hypothesis reported the minimal failing input (`username=''`).
- **Weak assertions can pass for the wrong reason.** Checking `"SUCCESS" in line` could be
  satisfied by attacker-controlled text; assertions on my own fields must check exact positions.

### Next steps
1. Write `conventions.md` (human/Kiro split) and `tech.md`.
2. Write ADR-0002 (HMAC password fingerprints).
3. Write `design.md`: components, data model, and threat model.
4. Set up CI (GitHub Actions running pytest) and the first Kiro hook.
5. Generate `tasks.md` from the design.

### Status
SSH library choice validated and accepted. Engineering design next.

# Devlog — November 10–11, 2026

### Completed

- Added `conventions.md` steering: human/Kiro ownership split, security rules, Python style (ruff), testing and git conventions.
- Added `tech.md` steering: full stack, repository layout, platform notes, common commands.
- Added `requirements.txt` and a project virtual environment (`.venv/`, gitignored).
- ADR-0002: HMAC-SHA-256 fingerprints for submitted passwords (no plaintext storage).
- ADR-0003: two-service model (honeypot and dashboard API isolated, communicating only through the database).
- ADR-0004: PostgreSQL event store with least-privilege roles and `LISTEN`/`NOTIFY` live updates.
- ADR-0005: dashboard stack (FastAPI, Next.js static export, Server-Sent Events).
- ADR-0006: SSH auth policy (weak-credential pair list, plus a private judge/demo login).
- Chose `psycopg` 3 (async) as the PostgreSQL driver.
- Rebuilt the development environment after a PC reset; spike tests pass again (2/2).

### Design decisions

- SSE event IDs are the session event sequence numbers, so the browser's built-in `Last-Event-ID` reconnection recovers missed events (R6.13).
- `EventSource` cannot send custom headers, so dashboard auth uses an `HttpOnly`, `Secure`, `SameSite=Strict` session cookie, plus CSRF tokens on state-changing requests.
- `NOTIFY` payloads carry only event IDs, because notifications are capped at 8,000 bytes and are not stored.
- The honeypot's database role can insert events but never read, update, or delete history; the one exception is the LLM usage counter (R4.7).
- The auth failure counter (R8.7) spans both keyboard-interactive and password auth on a connection.

### Lessons and surprises

- **A ZIP download is not a repository.** After the reset, downloading the repo as a ZIP and running `git init` created an unrelated history that could not be pushed without force-pushing over the real one. Re-cloning preserved the full history.
- **A one-character typo unlinked my commits.** The git email was missing `.com`, so GitHub showed a grey avatar and the commits did not count on my contribution graph. The quickest check is whether the commit shows my real avatar.
- **Tests must not depend on files outside the repository.** The end-to-end test failed after the reset because the gitignored host key no longer existed. CI will hit the same problem. In the real test suite, each test should generate a temporary host key in memory instead of reading one from disk.
- **The venv runs Python 3.15, not 3.12.** `py -3.12` was not available, so the default Python was used. Compatible with `tech.md` (3.12+), but the Dockerfile must use the same version I test with.
- **Windows blocks the venv activation script by default.** Fixed once with `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.
- **`psycopg` 3's async mode does not work with Windows' default event loop.** Windows entry points must switch to the selector event loop before starting asyncio. Linux production is unaffected.

### Carry into `design.md`

- **Testing section:** tests generate temporary host keys and never read gitignored files; tests that start servers bind to port 0 and clean up in `finally`.
- **Deployment section:** pin the container's Python version to the version used in development.
- **Open questions:** IPv6 listening; matching OpenSSH 9.6's advertised algorithms and auth methods; the forwarding refusal message ("administratively prohibited").

### Next steps

1. Choose the LLM provider and fill in the last `[YOUR CALL]` in `tech.md`.
2. Pin all versions in `requirements.txt` with `pip freeze` once the stack works.
3. Write `design.md`, starting with section 3 (Components): SSH Listener and Session Manager first.
4. Set up CI (GitHub Actions running pytest) and the first Kiro hook.

### Status

All blocking architecture decisions are made and recorded (ADR-0001 through ADR-0006). Engineering design next.

# Devlog — November 12–16, 2026

### Completed

- **`design.md`:** 13 components with interfaces and requirement mappings, data model and per-role permissions, key flows, command compatibility table, haunt scoring, LLM output validation, STRIDE threat model, testing strategy, and deployment.
- **ATT&CK rules refined to 15,** using sub-techniques where they fit (e.g. T1003.008 for `/etc/shadow`, T1087.001 for `/etc/passwd`, T1098.004 for `authorized_keys`).
- **ADR amendments:** ADR-0004 now allows a narrow, column-level `UPDATE` on `sessions` so the honeypot can record how a session ended; ADR-0002 clarifies that it covers attacker passwords only, while dashboard accounts use a slow salted hash.
- **`tasks.md`:** generated with Kiro's spec flow from requirements and design, then reviewed and corrected (missing integration tasks, a recorder interface moved earlier, ownership tags, submission tasks, an early live deployment).
- **T1.1 scaffolding** (Kiro): repository layout, pinned `requirements.txt`, `pyproject.toml` with ruff.
- **T9.3 CI** (Kiro): GitHub Actions running ruff and pytest with a PostgreSQL service container.
- **T9.5 hooks** (Kiro): tests on save, security scan, ATT&CK ID check, and an ownership guard that blocks Kiro from writing developer-owned code.
- **T1.2 auth policy** (me): credential-pair list, HMAC-SHA-256 fingerprints with a derived key, timing-safe demo login check, fail-closed configuration loading.
- **T1.8 auth tests** (Kiro): 18 tests, including Hypothesis property tests.
- **T1.5 admission control** (me): global, per-IP, and rolling-window rate limits.
- **T1.9 admission tests** (Kiro): 10 tests, including a property test over random acquire/release/clock sequences.

### Design decisions

- **Recorder interface early:** every component records through a small interface with an in-memory fake for tests; the PostgreSQL recorder plugs in later without changes.
- **Early deployment:** the honeypot goes live as soon as the SSH layer, filesystem, commands, and recorder work, so real attacker data accumulates before the demo.
- **Domain-separated keys:** the password fingerprint key is derived from the master secret with its own label, so future keys (e.g. attacker identity) can never be substituted for it.
- **Rate limit counts rejected attempts:** a flooding IP stays blocked until it stops for the full window.
- **Configurable timeouts** instead of an injected clock for the idle and lifetime watchdogs, so tests can use short durations.

### Lessons and surprises

- **An AI guardrail that had never fired.** Kiro's steering refused to write into `honeypot/` on its own, which made the ownership guard look fine, but the hook itself had never run. Testing it live with deliberate attempts exposed six separate bugs, each of which let a write through:
  1. Blocking requires **exit code 2**; the script used exit 1, which Kiro treats as a hook error, not a block.
  2. A shortcut **allowed** the call when no payload arrived (fail open).
  3. The path normalizer turned `c:\Users\...` into `c://Users//...`, so absolute Windows paths never matched.
  4. The save hooks used an invalid trigger name (`PostFileSave` instead of `FileSave`), so they had never run either.
  5. The shell check only matched `honeypot/` with a forward slash, missing PowerShell's `honeypot\`.
  6. The regex required a quote or slash before the path, missing unquoted paths after a space.

  Every script passed when tested manually. Only the end-to-end test proved the control. Shell detection remains best-effort; reviewing every diff before commit is the final control.
- **Security checks must fail closed.** Twice, Kiro's first version skipped the check when it couldn't read its input (the security scan and the guard). For a control, "can't verify" must mean "block."
- **Property tests found a real bug.** A lone Unicode surrogate in an attacker-supplied password made `fingerprint()` and `check()` raise `UnicodeEncodeError`. Fixed with `surrogatepass` encoding. I confirmed the tests fail without the fix and pass with it. (Hypothesis excludes surrogates by default; the strategy has to request them explicitly.)
- **A package name is not an import name.** `requirements.txt` listed `dotenv` instead of `python-dotenv`. CI failed because no matching version existed, but `dotenv` on PyPI is an unrelated project: a near-miss typosquat. Pin from `pip freeze`, never by guessing.
- **`.gitignore` doesn't untrack committed files.** An empty `.env` had been committed before it was ignored; `git rm --cached .env` removed it from tracking while keeping the local file.
- **Packages went into the wrong Python.** With the venv inactive, `pip install` targeted the system Python and `ruff`/`pytest` weren't found. Every new terminal needs the venv activated.
- **pytest exits with code 5 when it collects no tests,** which fails CI. A smoke test that imports each package keeps CI meaningful before real tests exist.
- **CI caught formatting drift** from an AI edit, which is exactly its job.
- **Rate limiter ordering is subtle.** The decision must be computed before recording the attempt, the attempt recorded every time (even when rejected), and the rejection returned afterwards. Returning early would let a flood slip back in.

### Next steps

1. T1.3: the real SSH server, wiring in `AuthPolicy` and `AdmissionController`, with a per-connection failure counter across both auth methods (R8.7).
2. Prune stale rate-limit entries in `AdmissionController` before deployment.
3. Settle the remaining design decisions: command flags and haunt score weights.
4. Turn the ownership-guard test cases into permanent tests; add a format-on-save hook.

### Status

SSH layer in progress: auth policy and admission control are done and tested. CI and Kiro hooks are working. Roughly on schedule for an early deployment around Nov 22–24.

# Devlog — November 16, 2026 (evening)

### Completed

- **T1.3 SSH server** (me): `honeypot/ssh_server.py` with `HoneypotServer` and a module-level `create_honeypot_server`. Admission control runs in `connection_made`; every auth attempt is logged with an HMAC fingerprint (never the password); a per-connection failure counter closes the connection after 5 failures (R8.7); every ADR-0001 security option is set explicitly.
- **T1.4 forwarding refusals** (me): local, remote, and Unix-socket forwarding are refused explicitly and logged as `FORWARD DENIED`, instead of relying on asyncssh's defaults.
- **T1.7 SSH server tests** (Kiro): integration tests against the real server on port 0 (login, exec, wrong password, version banner, forwarding, SFTP/SCP, agent/X11, per-IP limit with release on disconnect) and unit tests with a fake connection (failure limit, fingerprint logging, single-line log property test). CI is green.

### Design decisions

- **Dependency injection:** asyncssh creates one server object per connection with no arguments, so `create_honeypot_server` passes a factory, `lambda: HoneypotServer(auth, admission)`, giving every connection the same shared `AuthPolicy` and `AdmissionController`. Tests use it to inject a test secret and tiny limits.
- **Release only what was acquired:** `connection_lost` releases the admission slot only if the connection was admitted, and clears the flag so a duplicate call can't release twice. Otherwise refused connections would free slots they never held.
- **`logging` instead of `print`:** levels, formatted arguments, and `%r` for attacker-controlled values, so the entry point and recorder can capture every security event.

### Lessons and surprises

- **A callback that crashes can look like a working refusal.** The first forwarding overrides referenced `self.client_ip` instead of `self._client_ip`. Each one raised `AttributeError`, asyncssh treated the crash as a refusal, and the tests passed, but nothing was logged. Only a test that asserts the refusal is *recorded* (not just that it happens) catches this.
- **One wrong character can silently drop a log line.** A `$s` instead of `%s` gave a format string fewer placeholders than values. Python's logging doesn't raise; it prints a "Logging error" traceback and discards the message.
- **A strict `xfail` test can announce its own fix.** Kiro recorded the "factory is indented inside the class" bug as a strict expected failure. Once I dedented the function, the test reported XPASS and failed the suite on purpose: a reminder to remove the marker.
- **Check what's actually on disk.** Twice, the file on disk didn't match the version I'd written: once half-updated, once with a signature pasted into the wrong file. `Get-Content` showed the truth faster than rereading the editor.
- **`ruff check --fix` acts on the file as it is right now.** Run on the stale version, it removed `Path` and `Callable` as unused, and the corrected code then failed on missing imports. Save first, then fix.

### Next steps

1. Kiro: T2.3 (fake filesystem template) and T5.1 (SQL migration), in parallel with my work.
2. T1.6: the shell loop in `honeypot/shell.py`, building on the spike's resize handling.
3. T1.10: entry point and config loader.
4. T2.1–T2.2: the virtual filesystem.
5. T1.5a: prune stale rate-limit entries before deployment.

### Status

SSH layer complete except the shell. Target: early live deployment around Nov 22–24.

# Devlog — November 17, 2026

### Completed

- **T5.1 verified in CI:** the migration and all role-permission tests ran against a real PostgreSQL 16 server and passed (74 passed, 1 skipped for R8.8). ADR-0004's least-privilege guarantees are now tested on every push, not just documented.
- **T1.6 (part 1), `sanitize_for_terminal`** (me): strips every Unicode `Cc` control character except `\n` and `\t`, which covers C0, DEL, and C1 in one check, so ESC-based sequences (CSI, OSC 52 clipboard writes, OSC 8 hyperlinks, window titles) and the single-character C1 forms like `\x9b` are all neutralized. `\r` is dropped to prevent overwriting text.
- **R4.9 sanitizer tests** (Kiro): 19 tests, including Hypothesis properties (no control characters left, idempotent, never raises, output is a subsequence of the input) and a test proving the strategy actually generates C0, DEL, C1, and lone surrogates.
- **T1.6 (part 2), `run_exec` and placeholder `dispatch`** (me): one-shot exec requests are measured in **bytes** and rejected over 4,096 (R8.6). Output goes through `dispatch`, then the sanitizer, then stdout, and the exit status is passed through. `dispatch` returns `(output, status)`, the same shape the T2.4 command engine will use.
- **Manual end-to-end test** over real SSH with a throwaway dev script: the 4,096-byte boundary, a multibyte boundary, the exit codes, the sanitizer, and fingerprint-only auth logging.

### Design decisions

- **Allowlist, not blocklist, for terminal output.** Removing every control character except two is the security guarantee; a regex that removes whole sequences would only be cosmetic. Leftover text like `[2J` is visible but can't do anything.
- **Sanitizing prevents hack-back.** Without it, LLM output or attacker-created file content could write to a visitor's clipboard or terminal, which `product.md`'s guardrail forbids.
- **Log the size of a rejected command, never its content,** so a huge command can't fill the disk or inject into logs.
- **Host keys are ignored by pattern (`*host_key*`), not by exact path,** so newly generated keys are protected by default.

### Lessons and surprises

- **A library's default logging bypassed my own logging rule.** My code logs only the byte count of a rejected command, but asyncssh's INFO logging printed every raw command and username. Sending a real OSC sequence through the honeypot changed the **server** terminal's title: log injection (CWE-117) into the admin's terminal. Fix: run the `asyncssh` logger at WARNING (added to T1.10). Only testing with real traffic showed this.
- **Characters are not bytes.** `len(command)` would have let 2,049 `é` (4,098 bytes) through. asyncssh's `max_line_length` counts characters too, and doesn't apply to exec requests at all.
- **Security checks can fail silently.** In my drafts: `"CC"` instead of `"Cc"` made the sanitizer a no-op, `"\s"` instead of `"\n"` dropped every newline, and `if MAX_COMMAND_BYTES > 4096` compared the limit to itself, so the check never ran. None of these raise an error, and every one would pass a casual test.
- **`return` in the middle of a handler hangs the client:** the `write` and `exit` after it never ran.
- **Windows PowerShell 5.1 doesn't support `` `e``.** My first escape-sequence test sent a plain letter `e`, so it tested nothing. `$([char]27)` works everywhere. Check that a test actually sends what you think it sends.
- **`python -m package.module`, not a file path,** so imports resolve from the project root.

### Next steps

1. T1.6 (part 3): `run_interactive` (prompt, read loop, resize handling inside the loop, `exit` → `logout`, EOF/break), plus a router that sends shell sessions to `run_interactive` and exec requests to `run_exec`.
2. Kiro: tests for `run_exec` and the router.
3. Log a `CONNECTION CLOSED` event in `connection_lost` (needed later for R5 `end_reason`).
4. T1.10: entry point, config loader, and logging setup.
5. T2.1–T2.2: the virtual filesystem.

### Status

Shell is about two-thirds done. On track but tight for an early live deployment around Nov 22–24.

# Devlog — November 18, 2026

### Completed

- **T1.6 shell finished** (me): `run_interactive` and the `handle_process` router join yesterday's `sanitize_for_terminal` and `run_exec`.
  - The prompt (`root@web-prod-01:~# `, or `$` for non-root users) is built from the logged-in username.
  - `exit` and EOF (Ctrl+D) both print `logout` and end the session, as real bash does.
  - An empty line shows the prompt again without dispatching anything.
  - Lines over 4,096 bytes are rejected with the same message and log entry as exec requests (R8.6).
  - Output goes through `dispatch`, then `sanitize_for_terminal`, then the terminal (R4.9).
  - A terminal resize never ends the session (the spike bug), and Ctrl+C prints `^C` and a fresh prompt.
  - The router sends shell sessions to `run_interactive` and exec requests to `run_exec`.
- **Refactor:** the byte-limit check moved into one helper, `_is_too_long`, used by both exec and interactive paths. Regression-tested by hand with the same four boundary cases as yesterday.
- **Shell tests** (Kiro): 18 tests against a real server on port 0, covering exec boundaries (including multibyte from both sides), sanitized output, prompts for root and non-root users, empty lines, `exit`/EOF, Ctrl+C, resize, the interactive byte limit, and logs that record the byte count but never the command.
- **Manually tested over real SSH:** every interactive behavior above, with the root and admin accounts.

### Design decisions

- **Ctrl+C follows real bash, not the original design.** `design.md` said the session ends on Ctrl+C, but bash just prints `^C` and a new prompt. Disconnecting would tell an attacker something is off. Updated `design.md` §3 to match.
- **One helper for one rule.** The 4,096-byte limit applies to both exec and interactive input, so it lives in one function. A copied check could be fixed in one place and missed in the other, as almost happened with the characters-vs-bytes bug.
- **The prompt is written only before a new command is read.** A `show_prompt` flag skips the prompt when `readline()` was only interrupted by a resize.

### Lessons and surprises

- **The terminal hid a bug that the raw bytes showed.** My manual resize test looked clean, but Kiro's test read the raw output and found a second prompt sent after every resize: the resize handler's `continue` jumped back to the line that writes the prompt. The fix was the `show_prompt` flag. I then confirmed the tightened test fails without the fix (2 failures) and passes with it.
- **The same bug twice in one evening:** `if _is_too_long:` without parentheses tests the function object, which is always truthy, so every command would be rejected. It's the same mistake as printing a function instead of calling it in the spike.
- **A variable that doesn't exist yet crashes the session immediately.** An early draft computed `byte_count` from `command` before the loop, where neither existed, so every session would have died right after login.
- **A stray `process.exit()` inside the loop** would have disconnected attackers after their first command, and a `return` in place of `continue` would have skipped `exit` entirely and hung the client.
- **asyncssh's line editor converts `\n` to `\r\n` on output** (checked in its source), so writing `\r\n` sends `\r\r\n`. Use `\n` everywhere.
- **Unpacking must match.** Dropping the unused `status` from `output, status = dispatch(...)` would have turned `output` into the whole tuple and crashed the sanitizer. The fix was the `_status` naming convention for a deliberately ignored value.
- **The ownership guard blocked a git command too:** Kiro tried to check out an old `shell.py` to test against it, and the hook stopped it. The break-it check is mine to run, which is how it should be.
- **Run ruff before committing,** not after: a commit went out with an unused-variable error and needed a follow-up fix.

### Next steps

1. T1.10: entry point and config loader (with the `asyncssh` logger at WARNING and a startup log line), replacing the dev script.
2. Log a `CONNECTION CLOSED` event in `connection_lost`.
3. T1.5a: prune stale rate-limit entries before deployment.
4. T2.1–T2.2: the virtual filesystem, after which the prompt shows the real current directory.
5. T2.4: the command engine, replacing the placeholder `dispatch`.

### Status

SSH layer and shell complete and tested. Remaining before the early deployment (Nov 22–24): entry point, VFS, core commands, and the PostgreSQL recorder. Tight but on track.

# Devlog — November 19–20, 2026

### Completed

- **T1.10 entry point and config** (me): `python -m honeypot` now starts the real service.
  - `honeypot/config.py` holds a frozen `Config` dataclass, loaded by `load_config_from_env()`. Only values that are in use today are required (the host key path, plus the HMAC secret and demo login from `auth.py`). The rest have safe defaults: `127.0.0.1:2222`, a 15-second setup timeout, and `config/credentials.toml`.
  - Bad values fail closed with `ConfigurationError`: missing or nonexistent host key, non-integer or out-of-range port, a timeout that's zero, negative, `nan`, or `inf`, and a missing credentials file.
  - `honeypot/__main__.py` loads `.env` (the only place that does), sets the `asyncssh` logger to WARNING (the log-injection fix from T1.6), loads config before starting the event loop so a bad value prints one `CONFIG ERROR` line and exits with code 1, logs a startup line, and uses a selector event loop on Windows through `asyncio.run(..., loop_factory=...)`.
  - `create_honeypot_server` takes a configurable `login_timeout`, which let the R8.8 setup-timeout test run for the first time (with a 0.5-second timeout).
  - The throwaway `scripts/dev_exec.py` is gone.
- **T9.1 Docker** (Kiro): a hardened honeypot container (non-root user, read-only root filesystem, `cap_drop: ALL`, `no-new-privileges`, resource limits), Postgres 16 on an internal-only network with no published ports, the host key mounted read-only from outside the repo, and no secrets in the image.
- **Requirements split:** `requirements.txt` (runtime only), `requirements-dev.txt` (adds pytest, Hypothesis, ruff), and `requirements-api.txt` (for the future API image). The honeypot image no longer ships test tools.
- **T2.1 virtual filesystem, read side** (me):
  - `normalize_path(cwd, path)` turns any attacker path into one clean absolute path inside the virtual root, using a stack (LeetCode 71). It never uses `os.path` or `pathlib`, which would bring in Windows separators and the host filesystem.
  - `Node` is a dataclass with `children` from `field(default_factory=dict)`, so no two nodes share a dictionary.
  - `VirtualFS.resolve(cwd, path)` walks the tree one name at a time and returns `None` for missing names or paths that go through a file.
  - `load_template()` builds the tree from `config/fs_template.toml`: it sorts entries by depth so parents come first, parses `mode` as octal and `mtime` as a timezone-aware `datetime`, and lets the template's `/` entry set the root's own metadata.
- **VFS tests** (Kiro): 41 tests, including R2.12 property tests over random paths full of `..`, `.`, `//`, and backslashes; every rejected template case; and an R2.10 test proving that two copies of the loaded tree share no nodes.

### Design decisions

- **Secure defaults:** the server listens on `127.0.0.1` unless told otherwise. Docker sets `0.0.0.0` explicitly, so exposing a fake root shell to the network is always a deliberate choice.
- **Require configuration only when a feature uses it,** and fail closed on anything invalid. `HONEYPOT_DATABASE_URL` becomes required with the recorder (T5.2).
- **Keep the Postgres superuser password out of the honeypot's environment** (a separate `postgres.env`), so a compromised honeypot can't take over the database. This was Kiro's catch, and it follows ADR-0003.
- **Parse at the boundary:** the template's `"0644"` and ISO timestamps are converted to an `int` and a `datetime` once, at load time, so the rest of the code works with clean values.
- **Per-session copies** with `copy.deepcopy` of a tree loaded once at startup (R2.10).

### Lessons and surprises

- **One `and` almost broke the path-traversal guarantee.** My draft had `elif part == ".." and stack:`. With an empty stack, the condition was false, so `..` fell through to `else` and was pushed: `normalize_path("/", "..")` would have returned `"/.."`, above the virtual root. The fix was to match every `..` in its own branch and check the stack inside it. A single test case, `("/", "..")`, catches it.
- **`list.pop()` takes a position, not a value.** `stack.pop(part)` raises `TypeError`.
- **Fail-closed validation found a real gap.** The loader rejected the template's `/` entry. That entry wasn't a mistake; it describes the root, so the loader now uses it to set the root's metadata instead of discarding it.
- **Wrong-type values need their own handling.** `int(644, 8)` (a number instead of a string) raises `TypeError`, not `ValueError`, and `int("-644", 8)` returns a negative mode. Both are caught now.
- **`float("nan")` slips past `<= 0`** because every comparison with NaN is false. `math.isfinite` closes that gap.
- **Python imports a module only once per shell session,** so a REPL opened before an edit keeps the old code. Restart the shell after changing a module.
- **The indentation-inside-a-class bug happened again:** `load_template` became a method of `VirtualFS`. `Select-String -Pattern "^def |^class |    def "` shows the real indentation on disk in one line.
- **Run `ruff check .` before pushing.** CI failed on unsorted imports, a duplicate `datetime` import, and the newer `datetime.UTC` spelling, all fixable in one `ruff check --fix`.
- **A test that failed only in Kiro's terminal:** the entry-point subprocess test raised `WinError 6` there (no valid console handle to inherit) but passes in my terminal and in CI.

### Next steps

1. T2.2: VFS write operations (`mkdir`, write, `rm`, `cp`, `mv`), each checking every limit before changing anything (R2.9).
2. T2.4: the parser and command engine, starting with `ls`, `cd`, `pwd`, `cat`, `whoami`, `uname`, `id`, and "command not found".
3. Log a `CONNECTION CLOSED` event in `connection_lost`.
4. T1.5a: prune stale rate-limit entries before deployment.
5. T9.6: egress restriction, which must be done before going live.

### Status

Caught up after being about a day behind: the entry point, Docker, and the VFS read side are done and tested. Remaining before the early deployment (Nov 22–24): VFS writes, core commands, the recorder, and egress restriction.

