# Requirements Document

## Introduction

Haunted House Honeypot is an SSH honeypot that lures attackers into a fake, haunted Linux environment. It accepts SSH connections, presents a simulated shell and filesystem, and gradually escalates supernatural behavior the longer an attacker stays. Every command is recorded, mapped to MITRE ATT&CK techniques, and surfaced on a live dashboard — all while the attacker is kept entirely isolated from the host system.

This document specifies the functional and non-functional requirements for the MVP, scoped to the Kiroween 2026 hackathon deadline of December 4, 2026.

## Glossary

| Term | Definition |
|---|---|
| Attacker | Any entity — bot or human — that connects to the honeypot's SSH port. |
| ATT&CK detection rule | A deterministic, rule-based pattern that matches a recorded action and associates it with a MITRE ATT&CK technique identifier. |
| ATT&CK mapping | Associating a recorded attacker action with the corresponding MITRE ATT&CK technique ID and name. |
| Canned response | A pre-written, in-character reply returned when the LLM is unavailable, times out, or produces an unsafe or invalid response. |
| Defender | The administrator who monitors the dashboard and reviews session recordings. |
| Exec request | An SSH channel request that asks the server to execute a command directly, without starting an interactive shell. |
| Haunting event | A single supernatural occurrence injected into a session — such as a modified file, an eerie message, or anomalous command output — triggered at or above the current haunting level. |
| Haunting level | An integer from 0 to 3 representing the current intensity of supernatural behavior in a session. Level 0 is a normal environment; level 3 is fully aware. |
| Haunting score | A nonnegative score accumulated from configured attacker behaviors; separate from time- and command-based escalation thresholds. |
| HMAC fingerprint | A keyed HMAC-SHA-256 fingerprint of submitted credentials used for correlation without retaining plaintext passwords. |
| Honeypot | A decoy system designed to attract and observe attackers without exposing real resources. |
| Host isolation | The guarantee that no attacker-controlled input ever reaches the host operating system shell, filesystem, accounts, or unauthorized network resources. |
| LLM fallback | The component that routes unsupported commands to a language model API and returns a sanitized, fictional response. |
| MITRE ATT&CK | A publicly maintained framework of adversary tactics, techniques, and procedures, used here for rule-based labeling of observed attacker behavior. |
| MVP | Minimum viable product — mandatory Must criteria from R1–R6 and R8; R7 is optional. |
| Persistent environment | An attacker-specific simulated filesystem and haunting state that survives reconnection; a stretch goal (R7), not required for the MVP. |
| Provisional identity key | A derived key computed from source IP and a credential HMAC fingerprint, used as a non-authoritative signal for matching returning attackers to a persistent environment. |
| Session | Every accepted SSH connection, including failed authentication attempts, identified by a unique session ID. |
| Session recording | The durable, ordered log of all events in a session — commands, outputs, authentication attempts, haunting events, and ATT&CK detections. |
| Simulated filesystem | A per-session, in-process virtual directory tree, isolated from the host filesystem, that stores files and directories created or modified during the session. |
| Simulated shell | A command interpreter that parses and responds to attacker input using only simulated handlers, never executing on the host OS. |

## Requirements

**Prioritization:** Must = required for the safe hackathon MVP; Should = implement after all Must criteria; Could = optional and must not block the MVP. R7 is entirely Could. Build and test Must criteria first.

**Scope:** R1–R6 plus R8 Must criteria form the MVP. Requirements marked Should or Could are not MVP acceptance gates.

## R1 — SSH Connection and Authentication

**User Story:** As a defender, I want attackers to connect to a believable simulated SSH server so that authentication attempts and commands can be observed without exposing the host operating system or internal network.

### Acceptance Criteria

**R1.1 — SSH Listener [Must]**

WHEN the honeypot starts, THE SYSTEM SHALL listen for SSH connections on a configurable TCP port, defaulting to 2222 in development.

**R1.2 — Production Port Support [Must]**

WHEN the honeypot is configured for production, THE SYSTEM SHALL support receiving SSH connections directed to TCP port 22 without requiring the honeypot process to run as root.

**R1.3 — Simulated Authentication [Must]**

WHEN a client submits credentials, THE SYSTEM SHALL evaluate them against the simulated authentication policy defined in configuration without consulting host operating-system accounts.

**R1.4 — Interactive Shell [Must]**

WHEN simulated authentication succeeds and the client requests an interactive shell, THE SYSTEM SHALL present a simulated Linux shell within 2 seconds under local test conditions.

**R1.5 — Authentication Telemetry [Must]**

WHEN an SSH authentication attempt succeeds or fails, THE SYSTEM SHALL record its timestamp, source IP, submitted username, authentication method, result, and a keyed HMAC fingerprint of any submitted password, without storing plaintext passwords.

**R1.6 — Authentication Failure [Must]**

WHEN submitted credentials do not satisfy the configured authentication policy, THE SYSTEM SHALL reject the attempt without granting access to a simulated shell or host resources.

**R1.7 — Host Isolation [Must]**

THE SYSTEM SHALL prevent SSH clients from accessing the host operating-system shell, host accounts, host filesystem, or unauthorized network resources.

**R1.8 — Non-root Execution [Must]**

WHILE the honeypot is running, THE SYSTEM SHALL execute its application process under a dedicated, unprivileged operating-system account and SHALL NOT run as root.

**R1.9 — SSH Exec Requests [Must]**

WHEN an authenticated SSH client submits an exec request, THE SYSTEM SHALL route the command through the same simulated command handler, haunting engine, telemetry recorder, and ATT&CK detection rules used for interactive shell commands; count the command toward haunting thresholds; return simulated output and an exit status; and close the channel without executing the command on the host.

**R1.10 — Port Forwarding [Must]**

WHEN an SSH client requests local, remote, or dynamic port forwarding, THE SYSTEM SHALL reject the request without opening a forwarding listener, proxy connection, or outbound network connection.

**R1.11 — SFTP and SCP [Must]**

WHEN an SSH client requests the SFTP subsystem, THE SYSTEM SHALL reject the request.

WHEN an SSH client attempts SCP through an exec request, THE SYSTEM SHALL reject the transfer operation without reading or writing host files or transferring file contents.

**R1.12 — Agent and X11 Forwarding [Must]**

WHEN an SSH client requests SSH agent forwarding or X11 forwarding, THE SYSTEM SHALL reject the request without exposing agent sockets, display services, or other host resources.

**R1.13 — Configurable SSH Banner [Must]**

WHEN the SSH server starts, THE SYSTEM SHALL advertise a configurable SSH protocol identification string compatible with the configured SSH implementation, allowing it to resemble a supported OpenSSH version.

**R1.14 — Persistent SSH Host Key [Must]**

WHEN the honeypot starts, THE SYSTEM SHALL load its previously generated SSH host key from protected persistent storage.

IF no host key exists during initial setup, THE SYSTEM SHALL generate and securely store one before accepting connections.

**R1.15 — Authentication Data Protection [Must]**

WHILE authentication telemetry is stored, THE SYSTEM SHALL protect password fingerprints using a server-held HMAC secret stored separately from session records.

IF the HMAC secret is missing or cannot be loaded during startup, THE SYSTEM SHALL refuse to start the SSH listener and report a configuration error without exposing the secret.

### Verification

- Connect using OpenSSH and verify interactive shell access.

- Execute `ssh -p 2222 root@localhost "uname -a"` and verify simulated output.

- Verify rejected authentication attempts produce telemetry.

- Verify attempted passwords are not stored in plaintext.

- Verify password fingerprints remain consistent for identical inputs under the same secret.

- Attempt local, remote, and dynamic SSH forwarding; verify all are rejected.

- Attempt SFTP, SCP, agent forwarding, and X11 forwarding; verify all are rejected.

- Verify no attacker-controlled command executes on the host.

- Verify the honeypot runs without root privileges.

- Restart the honeypot and confirm its SSH host key fingerprint remains unchanged.

- Verify the configured SSH identification string is advertised.

- Verify the server fails safely if its HMAC secret is missing.

## R2 — Simulated Shell and Filesystem

**User Story:** As a defender, I want attackers to interact with a believable Linux shell and filesystem so that their commands and behavior can be observed without giving them access to the actual host operating system.

### Acceptance Criteria

**R2.1 — Supported Commands [Must]**

WHEN an authenticated attacker submits a command, THE SYSTEM SHALL execute its simulated behavior for the following 19 commands:

- `pwd`

- `ls`

- `cd`

- `cat`

- `echo`

- `whoami`

- `id`

- `uname`

- `ps`

- `mkdir`

- `touch`

- `rm`

- `cp`

- `mv`

- `find`
- `grep`
- `head`
- `tail`
- `wc`

THE SYSTEM SHALL support only the flags and argument behaviors explicitly listed in the command compatibility table in `design.md`; unsupported flags SHALL produce simulated Linux-compatible errors.

**R2.2 — Simulated Filesystem [Must]**

WHEN a new session starts, THE SYSTEM SHALL initialize a simulated Linux filesystem containing standard directories, including `/`, `/home`, `/root`, `/etc`, `/var`, `/tmp`, `/usr`, and `/bin`.

THE SYSTEM SHALL populate the filesystem with configurable, believable simulated files and directory metadata.

**R2.3 — Working Directory [Must]**

WHEN an attacker executes `cd` with a valid simulated directory, THE SYSTEM SHALL update the session's current working directory.

WHEN an attacker executes `pwd`, THE SYSTEM SHALL return the session's current working directory.

**R2.4 — File Operations [Must]**

WHEN an attacker executes a supported file operation with valid arguments, THE SYSTEM SHALL update the simulated filesystem according to the command's defined behavior.

THE SYSTEM SHALL support simulated file creation, reading, modification, deletion, copying, and moving.

**R2.5 — Linux-Compatible Errors [Must]**

WHEN a supported command receives invalid arguments, unsupported flags, nonexistent paths, or incompatible file types, THE SYSTEM SHALL return a Linux-compatible error message and exit status for the configured simulated Linux environment.

Examples include:

- `cat missing.txt` → `cat: missing.txt: No such file or directory`

- `cd /does-not-exist` → `bash: cd: /does-not-exist: No such file or directory`

- `mkdir /tmp/existing` → `mkdir: cannot create directory '/tmp/existing': File exists`

- `ls --invalid-option` → an error identifying the unrecognized option

THE SYSTEM SHALL use deterministic error responses for supported commands rather than sending these failures to the LLM.

**R2.6 — Simple Pipe Support [Should]**

WHEN an attacker submits a command containing pipes, THE SYSTEM SHALL support a maximum of 3 command stages connected by 2 pipe operators.

Each stage SHALL use a supported simulated command or an explicitly configured simulated stream-processing handler.

The output of each stage SHALL become the input of the next stage.

WHEN a pipeline exceeds 3 stages, THE SYSTEM SHALL reject the pipeline with a simulated shell error.

**R2.7 — Unsupported Shell Features [Must]**

WHEN an attacker submits shell scripting constructs, command substitution, background execution, job control, or unsupported shell operators, THE SYSTEM SHALL prevent those constructs from being interpreted or executed by the host operating system.

Unsupported syntax SHALL produce a simulated error or a bounded LLM-generated response, subject to R4.

**R2.8 — Unsupported Commands [Must]**

WHEN an attacker submits a command that is not implemented by the simulated command handler, THE SYSTEM SHALL route the command to the LLM fallback component defined in R4.

THE SYSTEM SHALL treat the returned response as untrusted text and SHALL NOT execute any generated command or instruction.

**R2.9 — Filesystem Resource Limits [Must] [PBT]**

WHILE a simulated filesystem is active, THE SYSTEM SHALL enforce the following per-environment limits:

- Maximum 1,000 filesystem entries, including files and directories created by the attacker.

- Maximum 64 KiB of content per simulated file.

- Maximum 5 MiB of total attacker-created file content.

- Maximum directory nesting depth of 16.

- Maximum 256 KiB of generated output per command before truncation.

WHEN an operation would exceed any filesystem limit, THE SYSTEM SHALL reject the operation without partially modifying the simulated filesystem and return a simulated filesystem or resource-limit error.

These limits SHALL apply to both interactive shell commands and SSH exec requests.

**R2.10 — Concurrent Session Isolation [Must]**

WHEN two or more SSH sessions are active concurrently, THE SYSTEM SHALL maintain independent working directories, filesystem modifications, and shell state for each session.

THE SYSTEM SHALL prevent one session from reading or modifying another session's simulated environment.

**R2.11 — Fresh Session State [Must]**

WHEN a new SSH session starts during the MVP, THE SYSTEM SHALL initialize a fresh simulated environment from the configured filesystem template.

THE SYSTEM SHALL NOT restore filesystem modifications from previous sessions.

Persistent attacker environments are deferred to R7.

**R2.12 — Filesystem Path Safety [Must] [PBT]**

WHEN a command references a filesystem path, THE SYSTEM SHALL resolve the path entirely within the simulated filesystem namespace.

THE SYSTEM SHALL prevent path traversal, symbolic-link resolution, or path normalization from accessing host filesystem resources.

**R2.13 — Command Output Consistency [Must]**

WHEN a supported command returns output, THE SYSTEM SHALL maintain consistency between the simulated filesystem state and subsequent command results.

For example, a file created using `touch` SHALL appear in subsequent `ls` output, and a file removed using `rm` SHALL no longer appear.

**R2.14 — Command Exit Status [Could]**

WHEN a simulated command completes, THE SYSTEM SHALL assign a deterministic exit status consistent with the configured command behavior.

WHEN an attacker requests the previous command's exit status through `$?`, THE SYSTEM SHALL return that status without invoking a host shell.

**R2.15 — Simulated File Content and Redirection [Could]**

WHEN an attacker uses supported output redirection (`>` or `>>`) with `echo` or another explicitly supported output-producing command, THE SYSTEM SHALL write or append the resulting text to a simulated file, subject to filesystem limits.

WHEN an attacker uses unsupported redirection syntax, THE SYSTEM SHALL reject it without modifying the filesystem.

**R2.16 — Session State Cleanup [Must]**

WHEN a non-persistent SSH session ends, THE SYSTEM SHALL release its simulated filesystem and shell state after the required telemetry has been recorded.

THE SYSTEM SHALL retain the session's recorded activity according to R5 without retaining its mutable simulated environment.

### Verification

- [ ] Verify all 19 supported commands return the expected simulated results.

- [ ] Verify valid file operations modify only the simulated filesystem.

- [ ] Verify nonexistent files, invalid flags, and invalid paths produce Linux-compatible errors and exit statuses.

- [ ] [Should] Verify pipelines containing 1, 2, and 3 stages.

- [ ] [Should] Verify pipelines exceeding 3 stages are rejected.

- [ ] Verify shell scripting and command substitution never execute on the host.

- [ ] Verify unsupported commands reach the bounded LLM fallback.

- [ ] Verify the 1,000-entry filesystem limit.

- [ ] Verify the 64 KiB per-file content limit.

- [ ] Verify the 5 MiB total content limit.

- [ ] Verify the maximum directory depth of 16.

- [ ] Verify oversized command output is truncated at 256 KiB.

- [ ] Verify resource-limit failures do not partially modify simulated state.

- [ ] Verify path traversal cannot access host files.

- [ ] Verify concurrent sessions cannot access each other's state.

- [ ] Verify new MVP sessions start with clean filesystem state.

- [ ] [Could] Verify `$?` returns the previous simulated exit status.

- [ ] [Could] Verify file redirection operates only within the simulated filesystem.

- [ ] Verify shell state is released after session termination.

## R3 — Progressive Haunting

**User Story:** As a defender, I want the simulated environment to become increasingly unsettling as attackers interact with it, so that attackers remain engaged while their behavior is recorded.

### Acceptance Criteria

**R3.1 — Haunting Levels [Must]**

WHEN a new SSH session begins, THE SYSTEM SHALL initialize its haunting level to 0.

THE SYSTEM SHALL support four states:

- Level 0: Normal Linux environment.

- Level 1: Subtle anomalies.

- Level 2: Unsettling and increasingly personalized in-world behavior.

- Level 3: The simulated environment appears aware of the attacker's actions.

**R3.2 — Initial Escalation [Must]**

WHEN an authenticated session reaches 60 seconds elapsed since authentication or receives 5 commands, whichever occurs first, THE SYSTEM SHALL immediately raise its haunting level to at least 1.

**R3.3 — Escalation Thresholds [Must]**

WHEN an authenticated session reaches 120 seconds elapsed since authentication or receives 10 commands, THE SYSTEM SHALL immediately raise its haunting level to at least 2.

WHEN an authenticated session reaches 240 seconds elapsed since authentication or receives 20 commands, THE SYSTEM SHALL immediately raise its haunting level to 3.

THE SYSTEM SHALL NOT exceed level 3.

**R3.4 — Behavior-Based Escalation [Must]**

WHEN an attacker performs a configured suspicious action, THE SYSTEM SHALL add the corresponding score to the session's haunting score.

THE SYSTEM SHALL support at least five behavioral triggers, including:

- Reading simulated sensitive files.

- Enumerating users or processes.

- Searching for credentials.

- Attempting privilege escalation.

- Attempting to download or execute suspicious content.

WHEN the behavior score reaches a configured threshold, THE SYSTEM SHALL immediately raise the haunting level to the corresponding level (maximum 3); the score weights and thresholds SHALL be specified in `design.md`.

**R3.5 — Monotonic Escalation [Must] [PBT]**

WHILE a session is active, THE SYSTEM SHALL NOT decrease its haunting level.

WHEN multiple escalation conditions are satisfied, THE SYSTEM SHALL apply the highest eligible level, up to level 3.

**R3.6 — Haunting Event Selection [Must]**

WHEN a haunting event is triggered, THE SYSTEM SHALL select an event compatible with the current haunting level and command context.

THE SYSTEM SHALL provide at least three distinct event templates for each haunting level above 0.

**R3.7 — Simulated Filesystem Haunting [Must]**

WHEN a haunting event modifies a simulated file or directory, THE SYSTEM SHALL apply the modification only to the affected session's simulated filesystem.

THE SYSTEM SHALL preserve filesystem consistency for subsequent commands.

**R3.8 — Event Logging [Must]**

WHEN a haunting event occurs, THE SYSTEM SHALL record its timestamp, session ID, haunting level, trigger, event type, and simulated output.

**R3.9 — Tone and Safety [Must]**

WHEN the system generates or selects haunting content, THE SYSTEM SHALL restrict the content to fictional, in-world supernatural behavior and eerie humor.

THE SYSTEM SHALL NOT threaten real-world harm, claim to hack back, claim to report the attacker, reveal private information, or imply physical retaliation.

**R3.10 — Event Frequency [Must]**

WHILE a session is active, THE SYSTEM SHALL enforce a minimum 15-second interval between unsolicited haunting events.

WHEN a haunting event is suppressed by the cooldown, THE SYSTEM SHALL still apply any qualifying level escalation immediately; the cooldown limits events, not level changes.

**R3.11 — Deterministic Testing [Should]**

WHEN the haunting engine runs in test mode, THE SYSTEM SHALL support an injected clock and deterministic event selection.

### Verification

- [ ] Verify every session starts at level 0.

- [ ] Verify escalation at 60, 120, and 240 seconds.

- [ ] Verify escalation at 5, 10, and 20 commands.

- [ ] Verify all five behavioral trigger categories.

- [ ] Verify haunting levels never decrease.

- [ ] Verify the maximum haunting level is 3.

- [ ] Verify at least three event templates exist for each haunting level above 0.

- [ ] Verify simulated file changes remain isolated.

- [ ] Verify haunting events are recorded.

- [ ] Verify the 15-second unsolicited-event cooldown.

- [ ] Verify prohibited real-world threats are rejected.

- [ ] Verify deterministic tests produce repeatable results.

---

## R4 — LLM Command Fallback

**User Story:** As a defender, I want unsupported commands to receive believable simulated responses without executing them, while keeping API costs, latency, and attacker-controlled input bounded.

### Acceptance Criteria

**R4.1 — Fallback Routing [Must]**

WHEN an authenticated attacker submits a command unsupported by the simulated command handler, THE SYSTEM SHALL route the command to the LLM fallback component unless a security or usage limit prevents the request.

**R4.2 — Request Timeout [Must]**

WHEN an LLM request does not produce a valid response within 5 seconds, THE SYSTEM SHALL terminate or cancel the request and return a canned in-character response.

THE SYSTEM SHALL complete fallback handling within 5.5 seconds under local test conditions.

**R4.3 — API Failure Handling [Must]**

WHEN the LLM API returns an error, an invalid response, or an unavailable-service result, THE SYSTEM SHALL return a canned in-character response without terminating the SSH session.

**R4.4 — Untrusted Input [Must]**

WHEN attacker-controlled text is included in an LLM request, THE SYSTEM SHALL treat that text as untrusted data rather than instructions governing system behavior.

THE SYSTEM SHALL limit the total serialized request context to 8 KiB and the attacker-controlled command portion to 4 KiB.

**R4.5 — Output Length [Must]**

WHEN the LLM produces a response, THE SYSTEM SHALL limit the accepted response to 4,096 UTF-8 bytes.

WHEN a response exceeds that limit, THE SYSTEM SHALL truncate it at a valid UTF-8 boundary or replace it with a canned response.

**R4.6 — Per-Session API Limit [Must]**

WHILE an SSH session is active, THE SYSTEM SHALL permit no more than 20 LLM API requests.

WHEN the session reaches this limit, THE SYSTEM SHALL respond to further unsupported commands using canned responses without making additional LLM API requests.

**R4.7 — Global Daily API Limit [Must]**

WHILE the honeypot is running, THE SYSTEM SHALL permit no more than 500 LLM API requests per UTC calendar day.

WHEN the global limit is reached, THE SYSTEM SHALL disable further LLM API requests until the next UTC day and use canned responses.

THE SYSTEM SHALL enforce the limit atomically across concurrent sessions and retain the counter across application restarts.

**R4.8 — Spending Cap [Should]**

WHEN the configured daily LLM spending budget is exhausted or cannot be verified, THE SYSTEM SHALL stop making new LLM API requests and use canned responses.

THE SYSTEM SHALL support a configurable daily budget, defaulting to USD $2.00. As a Should enhancement, THE SYSTEM SHALL reserve a conservative upper-bound cost for each request before dispatching it. Request-count limits remain mandatory; the estimated budget is not a guaranteed provider billing ceiling.

**R4.9 — Safe Output Rendering [Must] [PBT]**

WHEN LLM-generated text is returned to an SSH client or dashboard, THE SYSTEM SHALL treat it as untrusted text.

THE SYSTEM SHALL strip or safely escape terminal control sequences before sending text to a terminal and render text without HTML interpretation in the dashboard.

**R4.10 — No Host Execution [Must]**

THE SYSTEM SHALL NOT execute LLM-generated commands, scripts, file paths, or instructions on the host operating system.

**R4.11 — Fictional Response Policy [Must]**

WHEN an LLM response fails the explicit output safety validation defined in `design.md`, THE SYSTEM SHALL discard the response and return an approved canned response. The design SHALL specify detection rules, validation failures, and safe fallback behavior; filtering SHALL NOT be represented as a guarantee of perfect detection.

**R4.12 — Simulated State Integrity [Must]**

WHEN the LLM generates a response, THE SYSTEM SHALL NOT apply filesystem modifications or shell-state changes based solely on generated text.

**R4.13 — API Credential Protection [Must]**

THE SYSTEM SHALL load LLM API credentials from protected configuration or a secrets manager and SHALL NOT expose them in SSH responses, session recordings, or dashboard events.

**R4.14 — Request Telemetry [Must]**

WHEN an LLM request completes or fails, THE SYSTEM SHALL record its session ID, latency, outcome, and available token-usage and estimated-cost metadata without recording API secrets.

### Verification

- [ ] Verify unsupported commands reach the LLM component.

- [ ] Verify timeout fallback completes within 5.5 seconds.

- [ ] Verify API errors return canned responses.

- [ ] Verify attacker input cannot override trusted instructions.

- [ ] Verify the 8 KiB context limit and 4 KiB command limit.

- [ ] Verify the 4,096-byte output limit.

- [ ] Verify the 20-request session limit.

- [ ] Verify the 500-request daily limit under concurrent load.

- [ ] Verify the daily counter survives restarts.

- [ ] Verify the $2.00 daily spending budget and fail-closed budget handling.

- [ ] Verify terminal escape sequences are neutralized.

- [ ] Verify LLM output cannot execute commands or mutate filesystem state.

- [ ] Verify unsafe responses are replaced with canned responses.

- [ ] Verify API secrets never appear in logs or dashboard events.

---

## R5 — Session Recording and MITRE ATT&CK Mapping

**User Story:** As a defender, I want SSH activity recorded and mapped to MITRE ATT&CK techniques so that I can review attacker behavior and understand which techniques were attempted.

### Acceptance Criteria

**R5.1 — Session Identification [Must]**

WHEN a new SSH connection is accepted, THE SYSTEM SHALL assign a unique session identifier.

**R5.2 — Connection Metadata [Must]**

WHEN a session starts, THE SYSTEM SHALL record its session ID, source IP, source port, start timestamp, SSH client identification string, and authentication outcome.

**R5.3 — Command Recording [Must]**

WHEN an attacker submits a command, THE SYSTEM SHALL record its original input, timestamp, session ID, simulated output, and exit status, subject to recording limits and the credential-protection policy.

**R5.4 — Authentication Recording [Must]**

WHEN an authentication attempt occurs, THE SYSTEM SHALL record its outcome and permitted authentication metadata according to R1.

**R5.5 — ATT&CK Rule Mapping [Must]**

WHEN a recorded action matches a configured ATT&CK detection rule, THE SYSTEM SHALL associate the action with the corresponding MITRE ATT&CK technique identifier.

THE SYSTEM SHALL implement at least 10 distinct detection rules.

**R5.6 — Detection Evidence [Must]**

WHEN an ATT&CK technique is detected, THE SYSTEM SHALL record the matched rule identifier, technique identifier, timestamp, session ID, and triggering event identifier.

**R5.7 — Unmatched Activity [Must]**

WHEN an action does not match a detection rule, THE SYSTEM SHALL retain the action without assigning an unsupported ATT&CK technique.

**R5.8 — Chronological Ordering [Must]**

WHEN events are recorded, THE SYSTEM SHALL assign monotonically increasing sequence numbers within each session.

**R5.9 — Recording Retention and Deletion [Must / Could]**

WHEN an authenticated administrator selects a completed session recording for deletion in the dashboard, THE SYSTEM SHALL delete that recording and its associated session-specific telemetry. [Must]

WHEN a judge or other non-administrator requests recording deletion, THE SYSTEM SHALL deny the request without modifying stored data. [Must]

WHEN a completed session recording reaches 30 days after its end time, THE SYSTEM SHALL automatically delete the recording and associated session-specific telemetry. [Could]

Until automatic expiration is implemented, the administrator SHALL be able to delete recordings manually through the dashboard; deployment documentation SHALL state that automatic expiration is not yet enforced. [Must]

**R5.10 — Recording Size Limit [Must]**

WHILE a session is active, THE SYSTEM SHALL limit its stored recording payload to 10 MiB.

WHEN the next event would exceed the limit, THE SYSTEM SHALL record a bounded truncation/termination marker within the 10 MiB limit and terminate the SSH connection without accepting further commands.

**R5.11 — Recording Failure [Must]**

WHEN session recording fails, THE SYSTEM SHALL terminate the affected SSH session rather than continue accepting unrecorded attacker commands.

**R5.12 — Timestamp Standardization [Must]**

WHEN an event is recorded, THE SYSTEM SHALL use a UTC timestamp with millisecond precision.

**R5.13 — Replay Integrity [Must]**

WHEN a recorded session is replayed, THE SYSTEM SHALL reconstruct its stored events in session sequence order without re-executing commands.

**R5.14 — Sensitive Data Protection [Must]**

WHEN session recordings are stored or displayed, THE SYSTEM SHALL prevent stored credentials, API secrets, and internal configuration secrets from being exposed.

### Verification

- [ ] Verify unique session identifiers.

- [ ] Verify connection and authentication metadata.

- [ ] Verify commands, outputs, and exit statuses are recorded.

- [ ] Verify at least 10 ATT&CK detection rules.

- [ ] Verify unmatched commands receive no fabricated ATT&CK tags.

- [ ] Verify session event ordering.

- [ ] [Must] Verify administrator-only deletion through the dashboard and rejection of judge deletion attempts.

- [ ] [Could] Verify automatic deletion after 30 days.

- [ ] Verify the 10 MiB recording limit terminates the session with a bounded marker.

- [ ] Verify recording failures terminate affected sessions.

- [ ] Verify UTC timestamps with millisecond precision.

- [ ] Verify replay does not execute commands.

- [ ] Verify sensitive values are not exposed.

---

## R6 — Live Dashboard and Session Replay

**User Story:** As a defender, I want to monitor active attackers, inspect their behavior, and replay completed sessions from a protected dashboard.

### Acceptance Criteria

**R6.1 — Dashboard Authentication [Must]**

WHEN a user requests access to protected dashboard functionality, THE SYSTEM SHALL require valid defender authentication.

**R6.2 — Session Overview [Must]**

WHEN an authenticated defender opens the dashboard, THE SYSTEM SHALL display active sessions with their session IDs, source IPs, usernames, start times, command counts, and current haunting levels.

**R6.3 — Live Updates [Must]**

WHEN a new session event is recorded, THE SYSTEM SHALL deliver the event to a connected dashboard within 2 seconds under local test conditions.

**R6.4 — ATT&CK Visualization [Must]**

WHEN an ATT&CK detection occurs, THE SYSTEM SHALL display the technique identifier, associated session, timestamp, and triggering command or event.

**R6.5 — Haunting Visualization [Must]**

WHEN a session's haunting level changes, THE SYSTEM SHALL update its displayed haunting level and event history.

**R6.6 — Session Details [Must]**

WHEN the defender selects a session, THE SYSTEM SHALL display its recorded commands, simulated outputs, authentication events, haunting events, and ATT&CK detections.

**R6.7 — Session Replay [Must]**

WHEN the defender starts a replay, THE SYSTEM SHALL present recorded events in chronological sequence without reconnecting to the attacker or executing commands.

**R6.8 — Replay Controls [Could]**

WHILE replay is active, THE SYSTEM SHALL provide pause, resume, restart, and playback-speed controls supporting 1×, 2×, and 4× playback.

**R6.9 — Plain-Text Rendering [Must]**

WHEN attacker-supplied or LLM-generated text is displayed, THE SYSTEM SHALL render it as inert text rather than interpreted HTML, JavaScript, or executable content.

**R6.10 — Terminal Escape Safety [Must] [PBT]**

WHEN recorded text contains terminal control characters or escape sequences, THE SYSTEM SHALL strip or safely escape those sequences before displaying them in the dashboard, replay viewer, or administrator-facing terminal output.

**R6.11 — Authorization Enforcement [Must]**

WHEN an unauthenticated or unauthorized client requests session recordings, live events, replay data, or administrative APIs, THE SYSTEM SHALL reject the request without disclosing protected telemetry.

**R6.12 — LLM Independence [Must]**

WHEN the LLM service is unavailable, THE SYSTEM SHALL continue displaying recorded sessions, ATT&CK detections, haunting events, and replay data.

**R6.13 — Connection Recovery [Could]**

WHEN a dashboard live-update connection is interrupted, THE SYSTEM SHALL attempt reconnection and recover missed events using recorded event sequence identifiers.

**R6.14 — Dashboard Resource Bounds [Should]**

WHEN the defender opens a session event list, THE SYSTEM SHALL return at most 100 events per paginated request.

WHEN an event contains oversized text, THE SYSTEM SHALL display a bounded preview and require an explicit request for additional stored content.

**R6.15 — Defensive Read-Only Monitoring [Must]**

THE SYSTEM SHALL NOT provide dashboard controls that execute commands on the host or issue arbitrary commands to attacker sessions.

**R6.16 — Read-Only Judge Access [Must]**

WHEN a judge authenticates with the dedicated judge dashboard account, THE SYSTEM SHALL allow the judge to view active and completed sessions, recorded events, ATT&CK detections, and session replays.

WHEN a judge attempts to delete recordings, change configuration, manage accounts, or access administrator-only operations, THE SYSTEM SHALL deny the action server-side without modifying data.

WHEN the hackathon submission is prepared, THE SYSTEM SHALL provide documented judge dashboard access and separate simulated SSH test-login instructions in the README or submission form, without exposing administrator credentials or secrets.

### Verification

- [ ] Verify unauthenticated dashboard requests are rejected.

- [ ] Verify active sessions and metadata display correctly.

- [ ] Verify live updates arrive within 2 seconds.

- [ ] Verify ATT&CK detections appear with supporting evidence.

- [ ] Verify haunting-level updates appear.

- [ ] Verify session detail views contain recorded events.

- [ ] [Must] Verify replay ordering and basic playback.

- [ ] [Could] Verify pause, resume, restart, and 1×/2×/4× replay speed controls.

- [ ] Verify stored XSS payloads cannot execute JavaScript.

- [ ] Verify terminal escape sequences are neutralized.

- [ ] Verify protected APIs enforce authorization.

- [ ] Verify dashboard functionality without the LLM API.

- [ ] [Could] Verify live-update reconnection and event recovery.

- [ ] [Should] Verify pagination and oversized-output previews.

- [ ] Verify dashboard controls cannot execute host commands.

- [ ] [Must] Verify judge account can view sessions, detections, and replays but cannot delete recordings or change configuration.

- [ ] [Must] Verify judge dashboard and simulated SSH test-login instructions are included in the README or submission form.

---

## R7 — Persistent Attacker Environments (Stretch Goal)

**User Story:** As a defender, I want confidently recognized returning attackers to encounter their previous simulated environment so that repeated interactions can produce a continuous haunting experience.

**Priority:** Could (stretch) — excluded from MVP completion. ADR-0003 must be approved before implementation.

### Acceptance Criteria

**R7.1 — Optional Persistence [Could]**

WHEN persistent environments are disabled, THE SYSTEM SHALL initialize a fresh simulated environment for every new SSH session.

**R7.2 — Attacker Identity Matching [Could]**

WHEN an authenticated SSH connection is established with persistence enabled, THE SYSTEM SHALL evaluate the connection using the identity policy defined in ADR-0003 (attacker identity; to be written before R7 implementation).

THE SYSTEM SHALL NOT use SSH credentials alone as proof of attacker identity.

**R7.3 — Provisional Identity Key [Could]**

WHEN persistence is enabled, THE SYSTEM SHALL derive a provisional environment key from the source IP and a keyed HMAC fingerprint of the submitted credential pair.

THE SYSTEM SHALL NOT store plaintext passwords for identity matching.

**R7.4 — Environment Restoration [Could]**

WHEN an incoming connection matches an eligible persistent environment under the configured identity policy, THE SYSTEM SHALL restore its simulated filesystem, haunting level, and permitted command-history context.

**R7.5 — Uncertain Identity [Could]**

WHEN identity matching is uncertain or ambiguous, THE SYSTEM SHALL create a fresh isolated environment instead of restoring an existing one.

**R7.6 — Environment Isolation [Could]**

WHILE persistent environments are enabled, THE SYSTEM SHALL prevent sessions assigned to different environment identifiers from accessing each other's simulated filesystem or mutable state.

**R7.7 — Concurrent Access [Could]**

WHEN multiple sessions resolve to the same provisional identity, THE SYSTEM SHALL avoid unsafe concurrent modification by allowing at most one active session to own the persistent environment.

THE SYSTEM SHALL provide a fresh isolated environment to additional concurrent sessions rather than merging their modifications.

**R7.8 — Persistence Duration [Could]**

WHEN a persistent environment has been inactive for 7 days, THE SYSTEM SHALL expire and delete its simulated filesystem state and haunting state.

**R7.9 — Activity-Based Expiration [Could]**

WHEN an eligible persistent environment is successfully restored, THE SYSTEM SHALL update its last-activity timestamp.

**R7.10 — Command History [Could]**

WHEN a persistent environment is restored, THE SYSTEM SHALL make its permitted prior command-history context available to the haunting engine without exceeding R4 context limits.

THE SYSTEM SHALL NOT expose raw historical commands from another environment.

**R7.11 — Resource Limits [Could]**

WHILE persistence is enabled, THE SYSTEM SHALL apply the filesystem resource limits defined in R2 and the session resource limits defined in R8.

**R7.12 — Identity Collision Safety [Could]**

WHEN separate attackers share the same source IP and credential pair, THE SYSTEM SHALL treat the match as provisional rather than as proof of a shared identity.

THE SYSTEM SHALL NOT claim guaranteed individual-attacker separation based solely on network and credential attributes.

**R7.13 — Persistence Failure [Could]**

WHEN persistent state cannot be loaded safely, THE SYSTEM SHALL start a fresh isolated environment and record the restoration failure without exposing another environment's data.

**R7.14 — Session Recording Independence [Could]**

WHEN persistent environments are enabled, THE SYSTEM SHALL assign a unique session identifier to every SSH connection, even when multiple sessions are associated with the same persistent environment.

**R7.15 — MVP Independence [Could]**

WHEN persistence is disabled or unavailable, THE SYSTEM SHALL continue supporting all mandatory functionality defined in R1–R6 and R8.

### Verification

- [ ] Verify persistence can be disabled.

- [ ] Verify fresh sessions when persistence is disabled.

- [ ] Verify matching identity attributes can restore eligible state.

- [ ] Verify credentials alone cannot merge environments.

- [ ] Verify uncertain identities receive fresh environments.

- [ ] Verify different environment IDs remain isolated.

- [ ] Verify concurrent matching sessions cannot corrupt shared state.

- [ ] Verify simulated files and haunting levels survive eligible reconnects.

- [ ] Verify persistent environments expire after 7 days.

- [ ] Verify successful restoration updates last activity.

- [ ] Verify restored command history respects LLM context limits.

- [ ] Verify filesystem and session resource limits still apply.

- [ ] Verify persistence failures produce fresh isolated environments.

- [ ] Verify unique session IDs across reconnects.

- [ ] Verify the MVP works with persistence disabled.

---

## R8 — Abuse Prevention and Resource Limits

**User Story:** As a defender, I want bounded SSH connections, input, and resource usage so that abusive clients cannot exhaust the honeypot or disrupt monitoring.

### Acceptance Criteria

**R8.1 — Global Concurrent Connections [Must]**

WHILE the honeypot is running, THE SYSTEM SHALL allow at most 100 accepted SSH connections concurrently, including unauthenticated connections. WHEN the cap is reached, THE SYSTEM SHALL reject new connections before allocating a simulated filesystem or making LLM requests.

**R8.2 — Per-IP Concurrent Connections [Must]**

WHILE the honeypot is running, THE SYSTEM SHALL allow at most 5 concurrent accepted SSH connections per source IP, including unauthenticated connections, and reject additional connections from that IP.

**R8.3 — Per-IP Connection Rate [Must]**

WHEN a source IP has initiated 10 connection attempts within the preceding rolling 60 seconds, THE SYSTEM SHALL reject further attempts from that IP until the rolling count falls below 10. Rejected and failed-authentication attempts SHALL count toward this limit.

**R8.4 — Idle Timeout [Must]**

WHEN an accepted connection has no valid client activity for 300 consecutive seconds, THE SYSTEM SHALL close it and release its resources.

**R8.5 — Maximum Lifetime [Must]**

WHEN an accepted connection reaches 1,800 seconds since acceptance, THE SYSTEM SHALL close it regardless of activity.

**R8.6 — Input Line Limit [Must]**

WHEN a submitted command line exceeds 4,096 UTF-8 bytes, THE SYSTEM SHALL reject it before command handling or LLM routing. THE SYSTEM SHALL enforce the bound incrementally while reading, without buffering an unbounded input line. This SHALL apply to interactive shell input and exec requests.

**R8.7 — Failed Authentication Attempts [Must]**

WHEN a connection reaches 5 failed authentication attempts, THE SYSTEM SHALL terminate that connection and reject further attempts on it.

**R8.8 — Setup Timeout [Must]**

WHEN an accepted connection fails to complete SSH negotiation and authentication within 15 seconds, THE SYSTEM SHALL terminate it.

**R8.9 — Recording Bound [Must]**

WHILE a connection is active, THE SYSTEM SHALL enforce the single 10 MiB recording cap defined in R5.10, including its bounded final marker and connection termination behavior.

**R8.10 — Atomic Limit Enforcement [Must]**

WHEN connections arrive concurrently, THE SYSTEM SHALL enforce global and per-IP limits atomically so simultaneous attempts cannot exceed the configured caps.

**R8.11 — Resource Cleanup [Must]**

WHEN a connection ends for any reason, THE SYSTEM SHALL release its connection slot, transient shell state, and in-memory simulated filesystem without deleting retained telemetry.

**R8.12 — Rejection Telemetry [Should]**

WHEN a request is rejected by a resource limit, THE SYSTEM SHALL record a bounded event containing the reason, timestamp, and permitted connection metadata without retaining oversized rejected input.

### Verification

- [ ] Verify the 101st concurrent connection is rejected.
- [ ] Verify the 6th concurrent connection from one IP is rejected.
- [ ] Verify the 11th connection attempt within a rolling minute is rejected.
- [ ] Verify unauthenticated connections count toward concurrency and rate limits.
- [ ] Verify 300-second idle timeout and 1,800-second maximum lifetime.
- [ ] Verify a 4,097-byte line is rejected without unbounded buffering or an LLM call.
- [ ] Verify termination after 5 failed authentication attempts.
- [ ] Verify 15-second setup timeout.
- [ ] Verify the R5.10 recording cap and termination behavior.
- [ ] Verify atomic enforcement during concurrent connection attempts.
- [ ] Verify cleanup after disconnect, timeout, and rejection.
- [ ] Verify bounded rejection telemetry (Should).
