# ADR-0001: Language and SSH Server Library

- **Status:** Accepted
- **Date:** 2026-11-05
- **Accepted:** 2026-11-08
- **Project:** Haunted House Honeypot
- **Decision owner:** Annafi Islam

## Context

Haunted House Honeypot requires an SSH server capable of accepting attacker connections, recording authentication attempts, and providing a simulated interactive Linux environment without executing attacker commands on the host operating system.

The selected language and SSH library must satisfy the following requirements:

- **R1.3, R1.5:** Intercept username and password authentication attempts, record them securely, and apply custom authentication decisions.
- **R1.9–R1.12:** Support interactive SSH sessions and command execution requests while rejecting unauthorized SSH capabilities, including port forwarding, SFTP, agent forwarding, and X11 forwarding.
- **R1.13:** Support a configurable SSH identification string to control the server's advertised identity.
- **R1.14:** Load a persistent SSH host private key from a file.
- **R8:** Enforce connection limits, authentication timeouts, per-IP restrictions, and resource controls.
- **PBT:** Support property-based testing of command parsing, session state, protocol policy, and security invariants.
- **Deadline:** Support rapid v1.0 implementation within the Kiroween hackathon development window.

Each authenticated attacker session receives an isolated simulated environment. The application processes commands through a controlled command emulator rather than a real system shell.

The architecture must also support session recording, escalating haunting behavior, MITRE ATT&CK mapping, an LLM fallback mechanism, and a live monitoring dashboard.

The selection prioritizes protocol control, secure defaults, development speed, maintainability, and integration with the project's Python-based components.

## Options considered

1. Python 3.12+ + AsyncSSH (`asyncssh==2.24.1`)
2. Python 3.12+ + Paramiko
3. TypeScript/Node.js + ssh2

### Not considered

- **Fork Cowrie:** Ineligible, since the rules require a brand-new project. It's also a different architecture (Twisted) and an older design.
- **Go / Rust:** Viable, but outside my stack, and not worth the learning cost in four weeks.

## Comparison

| Criterion | Python + AsyncSSH | Python + Paramiko | TypeScript/Node.js + ssh2 |
|---|---|---|---|
| **SSH server support** | Native asynchronous SSH server through `SSHServer` and `create_server()` | Supported through `ServerInterface`, `Transport`, and sockets | Event-driven SSH server through `Server` |
| **Rejects forwarding/SFTP/agent/X11** | Supports deny-by-default session and forwarding callbacks; SFTP disabled when no factory is supplied; agent forwarding requires explicit `agent_forwarding=False` | Explicit channel authorization methods; most unsupported features denied by default | Event-based handlers allow selective acceptance; rejection behavior must be implemented and tested |
| **Custom banner** | `server_version` argument / config options | `Transport.local_version` property mapping | `ident` server configuration property |
| **Host key** | `server_host_keys` accepts key files | Load private key and register using `add_server_key()` | `hostKeys` accepts private key data |
| **Auth hooks** | `begin_auth()`, `password_auth_supported()`, `validate_password()` | `check_auth_password()` and related methods | `authentication` event with `accept()` and `reject()` |
| **Pre-auth limits/timeouts** | Async server callbacks and configurable protocol timeouts (`login_timeout=15`); custom IP admission controls required | Socket admission control and transport authentication timeouts; custom limits required | Connection handlers and timeout controls; custom IP admission controls required |
| **100 concurrent connections** | Suitable asynchronous architecture; benchmark required | Possible using threads/transports; benchmark required | Suitable event-driven architecture; benchmark required |
| **PBT library** | Hypothesis | Hypothesis | fast-check |
| **Maintenance** | Active documented project; release and advisory monitoring required | Established project; release and advisory monitoring required | Established package; release and advisory monitoring required |
| **My fluency** | High: existing Python experience and `asyncio` familiarity | High: Python familiarity, but additional threading complexity | Moderate: TypeScript/Node experience, but greater implementation overhead |

### Option 1: Python 3.12+ + AsyncSSH (asyncssh==2.24.1)

AsyncSSH provides native asynchronous SSH server functionality using Python's `asyncio` framework.

**Advantages**
- Official server implementation and examples.
- Asynchronous connection handling without requiring one application thread per client.
- Customizable authentication callbacks.
- Session and forwarding requests can be accepted or rejected through dedicated handlers.
- Configurable server identification string and host keys.
- Integrates with Python-based command simulation, logging, API services, and LLM components.
- Compatible with `pytest`, `pytest-asyncio`, and `Hypothesis`.

**Disadvantages**
- Default `agent_forwarding` setting is `True` and must be explicitly overridden.
- Requires careful asynchronous programming and cancellation handling.
- Blocking code can stall the event loop.
- Connection admission limits and application resource budgets require additional implementation.

**Assessment:** Best overall fit for v1.0.

### Option 2: Python 3.12+ + Paramiko

Paramiko supports SSH server development through its `ServerInterface` and `Transport` APIs.

**Advantages**
- Established Python SSH implementation.
- Fine-grained control over authentication and channel requests.
- Unsupported channel types and several forwarding requests are rejected by default.
- Compatible with existing Python testing tools.
- Straightforward integration with synchronous Python code.

**Disadvantages**
- Requires more explicit socket and connection lifecycle management.
- Thread-based connection handling increases resource-management complexity.
- Scaling concurrent sessions requires careful thread, socket, and timeout management.
- Additional implementation work compared with AsyncSSH's native event-driven server architecture.

**Assessment:** Technically viable, but less convenient for the expected concurrent-session workload.

### Option 3: TypeScript/Node.js + ssh2

The `ssh2` package provides event-driven SSH server functionality through Node.js.

**Advantages**
- Supports SSH server creation and custom authentication.
- Event-driven connection handling.
- Custom server identification and host keys.
- Suitable for integration with a TypeScript dashboard and backend.
- Property-based testing available through `fast-check`.

**Disadvantages**
- Requires implementing the SSH service in a separate language from the planned Python simulation components.
- May introduce cross-service communication or additional architectural complexity.
- Protocol event handling requires careful review to ensure unsupported requests are rejected.
- Less aligned with the project's existing Python development workflow.

**Assessment:** A reasonable alternative, but increases implementation overhead.

## Critical AsyncSSH Security Configuration Audit

Source code review of AsyncSSH (`2.24.1`) requires explicit overrides for default parameters during server initialization:

| Setting | AsyncSSH Default | Required Honeypot Setting | Requirement / Rationale |
| :--- | :--- | :--- | :--- |
| `agent_forwarding` | `True` *(Allowed)* | `False` *(Explicit)* | Prevents attackers from abusing ssh-agent forwarding (R1.12). |
| `x11_forwarding` | `False` | `False` *(Explicit)* | Blocks X11 window forwarding channels (R1.12). |
| `sftp_factory` | `None` | `None` *(Explicit)* | Disables SFTP subsystem requests (R1.11). |
| `allow_scp` | `False` | `False` *(Explicit)* | Disables SCP file transfers (R1.11). |
| `login_timeout` | `120` seconds | `15` seconds | Limits pre-authentication hanging connections (R8.8). |
| `server_version` | `AsyncSSH_2.24.1` | Custom (e.g., `OpenSSH_9.6p1 Ubuntu-3ubuntu13.5`) | Fingerprint masking via printable ASCII string (R1.13). |
| `rdns_lookup` | `False` | `False` *(Kept Off)* | Prevents outbound reverse DNS lookups on connecting IPs. |
| `max_line_length` | `1024` (Line editor only) | `4096` for interactive sessions; custom byte check for exec requests | Enforces line length limits (R8.6) across line-edited interactive sessions and direct command execution requests. |

## Decision

**Use Python 3.12+ with AsyncSSH (`asyncssh==2.24.1`) as the SSH server library because it provides native asynchronous server support, configurable authentication and protocol controls, and direct integration with the Python-based honeypot architecture while minimizing v1.0 development overhead.**

AsyncSSH will handle SSH transport, authentication, and session lifecycle management.

A separate application layer will handle command emulation, simulated filesystem state, haunting progression, event recording, and LLM fallback.

The SSH server must never pass attacker-controlled commands to a host shell.

## Consequences

### Easier

- Supporting many simultaneous SSH sessions through `asyncio`.
- Integrating SSH sessions with asynchronous event recording.
- Implementing custom authentication and session behavior.
- Connecting the SSH service to Python-based command emulation and LLM clients.
- Testing protocol handlers and session state using `pytest` and `Hypothesis`.
- Keeping v1.0 within a primarily Python technology stack.

### Harder

- Correctly managing asynchronous cancellation, shutdown, and connection cleanup.
- Preventing slow clients from consuming excessive resources.
- Keeping blocking database, filesystem, or LLM operations off the event loop.
- Tracking per-IP admission limits across connections.
- Preserving consistent session state during concurrent events.
- Maintaining reliable backpressure between SSH sessions and event consumers.

### Risks and mitigations

| Risk | Mitigation |
|---|---|
| Unauthorized forwarding or subsystems | Explicitly set `agent_forwarding=False`, omit `sftp_factory`, and verify via integration tests |
| Excessive concurrent connections | Enforce global and per-IP limits and reject excess connections |
| Authentication brute force | Enforce attempt budgets, authentication deadlines (`login_timeout=15`), and structured logging |
| Event-loop blocking | Use asynchronous I/O and bounded worker execution for unavoidable blocking operations |
| Attacker command execution | Route commands exclusively through a simulated command interpreter |
| LLM-generated unsafe actions | Treat LLM output as untrusted data and validate against the simulator's allowed operations |
| Resource exhaustion | Apply session timeouts, output limits, bounded queues, and memory budgets |
| Credential exposure | Redact sensitive authentication data from ordinary logs and restrict access to any separately retained research data |
| SSH host key compromise | Store private keys outside source control with restricted permissions |
| Library vulnerabilities | Pin reviewed dependency version (`asyncssh==2.24.1`), scan dependencies, and monitor security advisories |
| SSH implementation fingerprinting | Configure the `server_version` identification string and test observable protocol behavior |

## Verification and acceptance criteria

### 1. Spike Checklist (Required for ADR Acceptance)

The decision was to remain Proposed until the following checks passed in a throwaway spike:

- [x] **SSH server:** A real OpenSSH client can establish a connection to the AsyncSSH server.
- [x] **Authentication:** Username/password attempts are recorded and the application controls acceptance or rejection.
- [x] **Channel restrictions:** Unsupported agent forwarding (`ssh -A`), port forwarding (`-L`, `-R`, `-D`), SFTP, and X11 requests are rejected.
- [x] **Server identification:** A packet capture or `ssh -v` output confirms the configured SSH identification string.
- [x] **Host key:** A persistent host key loads from a file and remains stable across restarts.
- [x] **Property-based testing:** A Hypothesis property test (the auth log line is always a single safe line) and a pytest-asyncio end-to-end exec test run in the same suite.

All six spike checks passed on 2026-11-08; status updated to **Accepted**.
Evidence: [spike results](../../spikes/asyncssh/README.md)

Agent and X11 forwarding are verified by configuration only: the Windows test client could not issue those requests (no ssh-agent running; DISPLAY not set). Re-test from a Linux client before production.

### 2. Verified During Implementation (Tracked in Requirements)

These are not part of ADR acceptance and remain open until the full build verifies them:

- [ ] **Connection controls:** Per-IP and global connection limits, authentication timeouts, and idle timeouts operate correctly.
- [ ] **Concurrency:** At least 100 simultaneous connections are sustained under a documented load test without crashes, unbounded resource growth, or session-state corruption.
- [ ] **Dependency security:** The pinned `asyncssh==2.24.1` release and its dependencies pass the project's vulnerability review.
- [ ] **Host isolation:** Attacker input cannot execute host commands, access host files, or establish unauthorized outbound connections.

## References

- [AsyncSSH API documentation](https://asyncssh.readthedocs.io/en/latest/api.html)
- [AsyncSSH GitHub repository](https://github.com/ronf/asyncssh)
- [Paramiko server documentation](https://docs.paramiko.org/en/latest/api/server.html)
- [Paramiko GitHub repository](https://github.com/paramiko/paramiko)
- [ssh2 GitHub repository](https://github.com/mscdex/ssh2)
- [Hypothesis documentation](https://hypothesis.readthedocs.io/)
- [fast-check documentation](https://fast-check.dev/)