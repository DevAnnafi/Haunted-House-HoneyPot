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