# Haunted House Honeypot 🕯️

An SSH honeypot that traps attackers inside a fake, haunted Linux server.
It looks real at first. The longer they stay, the stranger it gets.
Every command is recorded and mapped to MITRE ATT&CK — live on a dashboard.

Built for the [Kiroween 2026 hackathon](https://kiro.dev) (Frankenstein category).

---

## What it does

1. **Accepts SSH connections** on a configurable port (default 2222 in dev, 22 in prod).
2. **Presents a believable fake Linux shell** backed by an in-process virtual filesystem — no attacker command ever touches the host OS.
3. **Escalates haunting** as the session progresses: subtle oddities at first, then the system seems to notice them.
4. **Falls back to an LLM** (Anthropic) for unsupported commands, generating in-character responses within a strict sandboxed context.
5. **Records everything** — commands, auth attempts, haunting events, ATT&CK detections — to PostgreSQL.
6. **Streams it live** to a protected dashboard via Server-Sent Events.

---

## Architecture

```
Attacker ──SSH──► Honeypot (Python/asyncssh)
                       │ writes events
                       ▼
                  PostgreSQL ──LISTEN──► Dashboard API (FastAPI)
                                              │ SSE
                                              ▼
                                        Browser dashboard (Next.js)
```

Three Docker services; only the honeypot's SSH port is published to the internet.
See [`docs/`](docs/) for ADRs and the devlog.

---

## Quick start (development)

```bash
# 1. Clone and create a virtual environment
git clone https://github.com/your-org/haunted-house-honeypot
cd haunted-house-honeypot
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux/macOS

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Copy and fill in secrets
cp .env.example .env          # edit DATABASE_URL, HMAC_SECRET, etc.

# 4. Run all tests
pytest -v

# 5. Format and lint
ruff format . && ruff check .
```

---

## Running the full stack

```bash
docker compose up --build
```

See [`docs/deployment.md`](docs/deployment.md) for production setup instructions,
including moving the host SSH daemon, firewall rules, and creating dashboard users.

---

## Repository layout

```
haunted-house-honeypot/
├── .kiro/            steering, specs, hooks
├── honeypot/         SSH honeypot service (Python package)
│   └── commands/     command engine and handlers
├── api/              dashboard API service (FastAPI)
├── dashboard/        dashboard frontend (Next.js, static export)
├── shared/           Pydantic event schemas used by both services
├── migrations/       SQL migrations (applied in order)
├── config/           non-secret configuration (credential list, fs template)
├── tests/            pytest suite
├── docs/             ADRs, devlog, architecture diagram
├── spikes/           throwaway experiments (not production code)
├── docker-compose.yml
├── pyproject.toml
├── requirements.txt
└── README.md         ← you are here
```

---

## Security notes

- Attacker commands **never** execute on the host.
- All attacker input and LLM output is treated as untrusted.
- Passwords are stored only as HMAC-SHA-256 fingerprints (ADR-0002).
- The LLM API is the only allowed outbound network destination from the honeypot.
- Secrets live in environment variables or `.env` (gitignored) — never in code.

---

## Judges

See [`docs/deployment.md`](docs/deployment.md) for SSH test-login credentials and
dashboard access instructions. No secrets are committed to this repository.

---

## License

[MIT](LICENSE)
