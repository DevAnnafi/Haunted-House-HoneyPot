---
inclusion: always
---

# Conventions: Haunted House Honeypot

## Ownership: who writes what

This project uses a deliberate human/AI split. The developer owns the security-critical
core; Kiro supports, reviews, tests, and builds the UI.

### The developer writes (Kiro must NOT write or modify unless explicitly asked)
- SSH layer: server class, auth policy, connection limits, forwarding/subsystem refusals
- Command engine: parser, command registry, the 19 simulated commands
- Virtual filesystem: data model, path resolution, resource limits
- Haunt engine: levels, escalation logic, event selection
- LLM fallback: request building, input/output sanitization, timeouts, budget caps
- Session recorder and ATT&CK detection rules
- Any code that touches attacker-controlled input

For these areas, Kiro explains concepts, reviews code, points out bugs and security issues,and suggests what a piece must accomplish, but does not produce the implementation.

### Kiro may write (the developer reviews before merging)
- Dashboard frontend (`dashboard/`)
- Documentation: README, docs/, setup guides
- CI/CD configuration and Kiro hooks
- Additional tests: extra property-based tests, integration tests, and test fixtures
- Boilerplate: config loading, packaging, Docker files

### Kiro always
- Reviews any code it is shown, with security issues first
- Flags any change that conflicts with requirements.md or an accepted ADR

## Security rules (non-negotiable, all code)
- Never call `subprocess`, `os.system`, `eval`, `exec`, or any shell from code that
  handles attacker input.
- Never build host filesystem paths from attacker input. All attacker paths resolve
  inside the virtual filesystem only.
- Treat all attacker input and LLM output as untrusted. Escape it with `repr()` or a
  sanitizer before logging; render it as plain text in the dashboard (never as HTML).
- Never log or store plaintext passwords. Use HMAC fingerprints (see ADR-0002).
- No outbound network calls except through the LLM client module.
- Set every security-relevant library option explicitly, even when the default is safe.
- Secrets live in environment variables or `.env` (gitignored), never in code.

## Python style
- Python 3.12+, type hints on all function signatures.
- Formatting and linting: ruff format and ruff linting.
- Async code: never block the event loop. No `time.sleep`, blocking I/O, or blocking
  HTTP calls inside `async def`; use async libraries or `asyncio.to_thread`.
- Small, pure functions where possible, so they can be property-tested.

## Testing
- Framework: pytest, with pytest-asyncio for async tests and Hypothesis for
  property-based tests.
- Every acceptance criterion tagged `[PBT]` in requirements.md gets a Hypothesis test.
- Name tests after the requirement they verify where practical
  (e.g. `test_r2_12_paths_never_escape_vfs`).
- Tests that start servers use port 0 and clean up with `try`/`finally`.
- When attacker-controlled text appears in output, assertions check exact positions,
  never `in`.

## Git
- Conventional Commits: `feat:`, `fix:`, `test:`, `docs:`, `chore:`, `spike:`, with an
  optional scope, e.g. `feat(vfs): ...`.
- Small commits; each one should leave tests passing.
- Add files explicitly (`git add <path>`), never `git add .` blindly.
- Never commit secrets, host keys, `.env`, or tool caches.

## Documentation
- Significant technical decisions get an ADR in `docs/adr/`, numbered in order.
- Progress, findings, and surprises go in `docs/devlog.md`.
- Requirement IDs (R1.1, R2.9, ...) are referenced in code comments, tests, and commits
  where relevant.