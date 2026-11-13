# ADR-0004: PostgreSQL as the Event Store

- **Status:** Accepted
- **Date:** 2026-11-11
- **Project:** Haunted House Honeypot
- **Decision owner:** Annafi Islam

## Context

ADR-0003 splits the system into two services that share no memory. They need a shared,
durable store that:

- accepts a high rate of concurrent writes from the honeypot (brute-force floods, up to 100 concurrent connections under R8.1)
- lets the dashboard query and replay sessions while those writes continue (R5, R6)
- delivers new events to the dashboard within 2 seconds (R6.3)
- survives restarts, including the daily LLM request counter (R4.7)
- supports different permission levels for the honeypot, the admin, and judges
  (R5.9, R6.11, R6.16)

## Options considered

1. **SQLite:** one embedded database file, no separate server.
2. **PostgreSQL:** a dedicated database server.

## Decision

**Use PostgreSQL as the shared event store, with a separate least-privilege role for each service and per-table permissions.**

### Roles and permissions

| Role | Used by | Permissions |
|---|---|---|
| `schema_owner` | Migrations only, never at runtime | Owns all tables |
| `honeypot_writer` | SSH honeypot | `INSERT` on event tables; `UPDATE` on three `sessions` columns only (`ended_at`, `final_haunt_level`, `end_reason`); `SELECT`/`UPDATE` on the LLM usage counter |
| `dashboard_admin` | Dashboard API, admin requests | `SELECT` on all event tables; `DELETE` on session recordings (R5.9) |
| `dashboard_judge` | Dashboard API, judge requests | `SELECT` only (R6.16) |

Table names are provisional and are finalized in `design.md` (Data model). The intended shape:
- **Event tables** (sessions, events, auth attempts, detections): the honeypot can only **add** rows. It can never read, change, or delete history.
- **Closing a session:** when a connection ends, the honeypot records how and when it ended. This needs a narrow, **column-level** `UPDATE` on `sessions` (`ended_at`, `final_haunt_level`, `end_reason`). The honeypot still cannot change any event, detection, or auth record, so recorded history stays tamper-proof. Amended 2026-11-12 during `design.md`.
- **LLM usage counter:** the one table the honeypot reads and updates, so the daily limit survives restarts (R4.7).
- **Persistent environments (R7, stretch):** if built, the honeypot gets `SELECT`/`UPDATE` on that table only.

### Live updates

- After inserting an event, the honeypot sends a PostgreSQL `NOTIFY` whose payload is **only the event ID** (and session ID), never the event contents. Notification payloads are limited to 8,000 bytes, and attacker output can exceed that.
- The dashboard API `LISTEN`s, fetches the full row by ID, and pushes it to the browser.
- Notifications are not stored: if the dashboard is disconnected, they are lost. So the dashboard also **catches up by sequence number** (R5.8, R6.13): on reconnect it queries for every event after the last sequence number it saw. `NOTIFY` is for speed; the sequence query is for correctness.

### Network exposure

- The PostgreSQL port is **never published** to the internet or the host. Services reach it only over an internal Docker network (or a Unix socket).
- Every role authenticates with `scram-sha-256` and its own password, supplied through
environment variables, never committed.

## Consequences

### Pros

- **Granular security permissions:** a compromised honeypot can add events but cannot read, alter, or delete past attack logs. Judges can only read.
- **High concurrency without locks:** PostgreSQL handles hundreds of concurrent writes from the honeypot while the dashboard runs analytical queries, avoiding SQLite's "database is locked" errors under write-heavy load.
- **Built-in real-time streaming:** `LISTEN`/`NOTIFY` pushes new-event signals to the
  dashboard without a separate message broker such as Redis.

### Cons

- **Higher memory and CPU overhead:** a database server needs noticeably more RAM and disk than an embedded database, which can strain small VPS instances (plan for at least 2 GB of RAM for the full stack).
- **Extra infrastructure to maintain:** a third service to deploy, secure, back up, and monitor alongside the honeypot and the dashboard API.
- **Network attack surface:** a misconfigured PostgreSQL exposed over TCP adds a port and an authentication layer an attacker could target after pivoting out of the honeypot. Mitigated by never publishing the port and using per-role credentials.
- **Async driver required:** the honeypot is asyncio-based, so database access must use an async driver to avoid blocking the event loop (ADR-0001, Harder). The driver choice is made in `tech.md`.

### Risks and mitigations

| Risk | Mitigation |
|---|---|
| Compromised honeypot tampers with history | `honeypot_writer` has `INSERT` only on event tables |
| Compromised honeypot floods or forges events | R8 rate limits; R5.10 per-session recording cap; dashboard treats events as untrusted |
| Live updates lost during a disconnect | Catch-up query by sequence number (R6.13) |
| Large attacker output breaks `NOTIFY` | Payload carries IDs only; the dashboard fetches the row |
| Database port reachable from outside | Port never published; internal network only |
| Credential leak | One password per role, in environment variables only; `.env` gitignored |

## Verification

- [ ] `honeypot_writer` cannot `SELECT`, `UPDATE`, or `DELETE` event tables.
- [ ] `honeypot_writer` can read and update the LLM usage counter, and the counter survives a restart.
- [ ] `dashboard_judge` cannot `DELETE` or `UPDATE` anything.
- [ ] `dashboard_admin` can delete a session recording.
- [ ] The PostgreSQL port is not reachable from outside the internal network.
- [ ] A `NOTIFY` carries only IDs, and the dashboard receives a new event within 2 seconds (R6.3).
- [ ] After a dashboard disconnect, missed events are recovered by sequence number (R6.13).
- [ ] `honeypot_writer` can update only `ended_at`, `final_haunt_level`, and `end_reason` on `sessions`, and no other column.