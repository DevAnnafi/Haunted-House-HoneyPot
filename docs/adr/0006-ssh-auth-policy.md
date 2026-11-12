# ADR-0006: SSH Authentication Policy (Weak-Credential List)

- **Status:** Accepted
- **Date:** 2026-11-11
- **Project:** Haunted House Honeypot
- **Decision owner:** Annafi Islam

## Context

R1.3 requires a simulated authentication policy defined in configuration. The policy decides which logins succeed, which directly controls:

- **how many attackers reach the shell** (and therefore the haunting, ATT&CK detection, and demo), and
- **how realistic the server looks.** A server that accepts any password is an obvious
honeypot to a human attacker, and some bots test for it by trying a random password first.

It also interacts with abuse limits:
- **R8.7:** a connection is closed after 5 failed authentication attempts.
- **R8.3:** a source IP is limited to 10 connection attempts per rolling 60 seconds.

## Options considered

1. **Accept everything:** captures every session, but is the easiest honeypot tell.
2. **Weak-credential list:** accept only specific username/password pairs that real breached servers commonly use.
3. **Accept on the Nth attempt:** mimics a brute force succeeding, but is harder to explain, test, and keep consistent.

## Decision

**Accept only username/password pairs on a configured weak-credential list. All other
attempts fail.**

- The list is **pairs**, not "any listed username with any listed password"
(e.g. `root`/`123456`, `admin`/`admin`, `ubuntu`/`ubuntu`, `pi`/`raspberry`), so behavior resembles real misconfigured servers.
- The list is drawn from commonly attacked default and weak credentials and lives in a
configuration file, not in code. These are publicly known decoy credentials, so the list itself may be committed.
- The policy is **deterministic**: the same pair always succeeds, so a returning attacker sees consistent behavior.
- **Judge/demo login:** a separate, non-guessable demo credential is accepted for judges. It is supplied through environment configuration, **not committed**, and shared only in the private Devpost submission form (R6.16).
- **Every attempt is recorded** before any disconnect: timestamp, source IP, username,
auth method, result, and an **HMAC fingerprint** of the password (ADR-0002). The
password itself is never stored or logged.

### Interaction with abuse limits
- **R8.7 (5 failures per connection):** a bot that misses the list 5 times is disconnected before reaching a later list entry. This is accepted: bots try the most common passwords first, and those are exactly what the list contains. Every failed attempt is still recorded.
- **Reconnect-and-retry:** attackers can reconnect and keep guessing, but **R8.3** caps this at 10 connection attempts per IP per minute, which bounds the total guessing rate.
- The failure counter covers **both** keyboard-interactive and password auth on a
connection (finding from the ADR-0001 spike: one connection got 6 guesses across the two methods).

## Consequences

### Pros
- Realistic: the server behaves like a genuinely misconfigured machine, not a trap.
- Bots that try common credentials still get in, so sessions and haunting still happen.
- Deterministic and easy to test.
- Failed attempts still produce useful intelligence (usernames, password fingerprints,
  attempt patterns).

### Cons
- Fewer sessions than accept-all: attackers whose guesses miss the list never reach the shell.
- R8.7 can cut off a bot before it reaches a listed credential.
- The list needs tuning: too small loses sessions, too large starts to look suspicious.

### Risks and mitigations

| Risk | Mitigation |
|---|---|
| Too few attackers get in | Tune the list from recorded failed usernames and fingerprint frequency |
| Demo login leaks publicly | Kept out of the repo; provided only in the private submission form |
| Plaintext passwords recorded | HMAC fingerprints only (ADR-0002); property test asserts no password in logs |
| Unbounded guessing via reconnects | R8.3 per-IP connection rate limit |
| Failure limit bypassed via two auth methods | One failure counter per connection across all methods |

## Verification

- [ ] A listed pair is accepted; the same username with an unlisted password is rejected.
- [ ] The judge/demo credential works and is not present anywhere in the repository.
- [ ] A connection is closed after 5 failed attempts, counted across both auth methods (R8.7).
- [ ] Every attempt is recorded with an HMAC fingerprint and no plaintext password (R1.5).
- [ ] The 11th connection attempt from one IP within a minute is rejected (R8.3).