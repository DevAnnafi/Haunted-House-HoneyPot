---
inclusion: always
---

# Tech Stack: Haunted House Honeypot

This file lists the technologies, versions, layout, and commands for the project. Decisions behind them are recorded in `docs/adr/`.

## Architecture at a glance

Three services (ADR-0003):

1. **Honeypot:** Python asyncio SSH server, faces the internet. Writes events to PostgreSQL.
2. **Dashboard API:** FastAPI, internal only. Reads events, streams them to the browser over SSE.
3. **PostgreSQL:** the only channel between the two (ADR-0004). Never exposed publicly.

The dashboard frontend is a Next.js static export served by the API (ADR-0005).

## Languages and runtimes

- **Python 3.12+** for the honeypot and the dashboard API.
- **TypeScript** for the dashboard frontend (Node.js used only at build time).

## Honeypot

- **SSH server:** `asyncssh==2.24.1` (ADR-0001). Every security-relevant option is set explicitly; see the configuration audit table in ADR-0001.
- **Database driver:** `psycopg` 3 (async API), with `psycopg_pool` for connection pooling.
- **Auth policy:** weak-credential pair list loaded from configuration (ADR-0006).
- **Password fingerprints:** HMAC-SHA-256 with a server secret, via Python's `hmac` and `secrets` modules (ADR-0002).
- **LLM fallback:** Anthropic. Called only from the LLM client module, with timeouts, request caps, and output validation (R4).

## Dashboard API

- **Framework:** FastAPI, served by Uvicorn.
- **Database driver:** `psycopg` 3 (async), with a dedicated connection for `LISTEN`.
- **Live updates:** Server-Sent Events. Event IDs are session event sequence numbers, so `Last-Event-ID` reconnection recovers missed events (R6.13).
- **Auth:** session cookie (`HttpOnly`, `Secure`, `SameSite=Strict`) plus a CSRF token on state-changing requests. Roles: admin, judge.
- **Shared models:** event schemas defined once (Pydantic) and used by both Python services.

## Dashboard frontend

- **Next.js** with TypeScript and **Tailwind CSS**, built as a **static export** (no Node.js server at runtime).
- Attacker-supplied and LLM-generated text is always rendered as plain text, never as raw HTML (R6.9).

## Database

- **PostgreSQL** with least-privilege roles: `schema_owner` (migrations only), `honeypot_writer`, `dashboard_admin`, `dashboard_judge` (ADR-0004).
- **Migrations:** plain SQL files in `migrations/`, applied in order by `schema_owner`.
- All queries use **parameterized placeholders** (`%s`). Never build SQL with f-strings or string concatenation.
- `NOTIFY` payloads carry IDs only, never event contents.

## Testing and quality

- **pytest**, **pytest-asyncio** for async tests, **Hypothesis** for property-based tests.
- **ruff** for formatting (`ruff format`) and linting (`ruff check`).
- Tests that start servers bind to port 0 and clean up in `finally`.

## Deployment

- **Docker Compose** with one container per service on internal networks. Only the honeypot's SSH port is published.
- Target: a single Linux VPS with at least 2 GB of RAM.
- A host egress firewall allows the honeypot to reach only PostgreSQL and the LLM API.
- Secrets (database passwords, HMAC secret, LLM API key, demo login) come from environment variables or `.env`, which is gitignored.

## Platform notes

- **Development happens on Windows; production runs on Linux.**
- `psycopg` 3's async API does not support Windows' default asyncio event loop (Proactor). On Windows, the entry points must switch to the selector event loop before starting asyncio:

```python
import asyncio, sys

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
```

- Linux needs no change, so production is unaffected.

## Repository layout

```
haunted-house-honeypot/
├── .kiro/                 steering, specs, hooks
├── honeypot/              SSH honeypot service (Python package)
├── api/                   dashboard API service (FastAPI)
├── dashboard/             dashboard frontend (Next.js, static export)
├── shared/                event schemas shared by both Python services
├── migrations/            SQL migrations
├── config/                non-secret configuration (e.g. credential list)
├── tests/                 pytest suite
├── docs/                  ADRs, devlog, architecture diagram
├── spikes/                throwaway experiments (not production code)
├── docker-compose.yml
├── requirements.txt
└── README.md
```

## Common commands

```bash
pip install -r requirements.txt        # install Python dependencies
pytest -v                              # run all tests
ruff format . && ruff check .          # format and lint
docker compose up --build              # run the full stack locally
```