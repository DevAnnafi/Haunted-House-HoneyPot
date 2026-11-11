# ADR-0002: HMAC Fingerprints for Submitted Passwords

- **Status:** Accepted
- **Date:** 2026-11-10
- **Project:** Haunted House Honeypot
- **Decision owner:** Annafi Islam

## Context

Attackers submit passwords during SSH authentication. These are valuable intelligence:
repeated passwords reveal credential lists and campaigns, and R7 needs them to recognize
returning attackers. But a submitted password may also be a real person's real password,
for example someone who mistyped an IP address.

Relevant requirements:
- **R1.5:** Record authentication attempts without storing plaintext passwords.
- **R1.15:** Protect password fingerprints with a server-held secret stored separately from
  session records; refuse to start if the secret is unavailable.
- **R7.3:** Derive a provisional identity key from the source IP and a credential fingerprint.

The chosen approach must let the defender tell when two attempts used the **same** password,
without letting anyone who obtains the database recover the password.

## Options considered

1. **Plaintext.** Most useful for analysis (e.g. a "top passwords" panel), and what many
   honeypots do. Exposes real users' passwords if the database leaks.
2. **Unkeyed hash (e.g. SHA-256).** Supports correlation, but common passwords are reversed
   instantly with precomputed tables or a dictionary, so it is close to plaintext in practice.
3. **Salted slow hash (bcrypt / Argon2).** Strong storage, but a random salt per record means
   identical passwords produce different hashes, which **breaks correlation**. Slow hashing
   on every attempt also lets a bot flood consume CPU.
4. **Keyed hash (HMAC-SHA-256 with a server secret).** Identical inputs give identical
   fingerprints, so correlation works. Without the secret, fingerprints cannot be reversed
   or dictionary-attacked. Fast enough to run on every attempt.

## Decision

**Store an HMAC-SHA-256 fingerprint of each submitted password, keyed with a 32-byte random
server secret. Never store or log the plaintext password.**

- The secret is generated once (e.g. Python's `secrets.token_bytes(32)`), stored outside the
  repository and outside the session database (environment variable or a protected file),
  and loaded at startup.
- Passwords are encoded as UTF-8 before hashing, so the same password always produces the
  same fingerprint.
- **Domain separation:** password fingerprints and R7 identity keys use different derived keys
  (or a distinct prefix per purpose), so one value can never be substituted for the other.
- If the secret is missing or unreadable, the SSH listener refuses to start (R1.15). It never
  falls back to an unkeyed hash or plaintext.

## Consequences

### Easier
- Counting how often the same password is tried, across sessions and IPs.
- Supporting R7 attacker matching without plaintext.
- Publishing the repository and dashboard without exposing real users' passwords.

### Harder
- The dashboard cannot show the actual passwords tried. A "top passwords" panel can only
  show fingerprints and counts.
- **Rotating the secret breaks correlation** with all earlier fingerprints.
- The secret becomes sensitive data and must be backed up and protected.

### Risks and mitigations

| Risk | Mitigation |
|---|---|
| Secret leaks alongside the database | Store the secret separately from session records; restrict file permissions; never log it |
| Secret holder dictionary-attacks weak passwords | Accepted: only the defender holds the secret. Treat the secret like a credential. |
| Secret lost | Back it up; document that losing it only breaks correlation, not security |
| Plaintext leaks through logs or errors | Never pass the password to logging; property tests assert log lines contain no password |
| Inconsistent encoding breaks correlation | Always encode as UTF-8 before hashing |

## Verification

- [ ] Identical passwords under the same secret produce identical fingerprints.
- [ ] Different secrets produce different fingerprints for the same password.
- [ ] No plaintext password appears in stored records or logs (property test).
- [ ] The server refuses to start when the secret is missing (R1.15).
- [ ] Password fingerprints and identity keys never collide for the same input (domain separation).