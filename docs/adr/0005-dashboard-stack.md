# ADR-0005: Dashboard Stack (FastAPI, Next.js, Server-Sent Events)

- **Status:** Accepted
- **Date:** 2026-11-11
- **Project:** Haunted House Honeypot
- **Decision owner:** Annafi Islam

## Context

ADR-0003 makes the dashboard its own service, and ADR-0004 makes PostgreSQL the only channel between it and the honeypot. The dashboard must:
- show active sessions, ATT&CK detections, haunting levels, and replays (R6.2–R6.7)
- deliver new events to the browser within 2 seconds (R6.3)
- recover missed events after a disconnect (R6.13)
- authenticate defenders and judges, and enforce admin-only actions server-side
  (R6.1, R6.11, R6.16, R5.9)
- render all attacker and LLM text as inert text (R6.9, R6.10)
- never send commands to attacker sessions (R6.15)

The frontend is also the part judges see most, so it carries the Design and Costume-style polish scores, and it is the main area Kiro builds (see `conventions.md`).

## Options considered

**API:** FastAPI (Python) or Next.js API routes (TypeScript).
**Frontend:** Next.js + TypeScript + Tailwind, or Vite + React + TypeScript + Tailwind.
**Live updates:** WebSocket or Server-Sent Events (SSE).

## Decision

**Use FastAPI for the dashboard API, Next.js with TypeScript and Tailwind CSS for the
frontend (built as a static export), and Server-Sent Events for live updates.**

### API: FastAPI

- Async, so it pairs with an async PostgreSQL driver and a long-lived `LISTEN` connection.
- Same language as the honeypot, so event schemas (e.g. Pydantic models) can be shared.
- Integrates well with Python-based security tooling.

### Frontend: Next.js + TypeScript + Tailwind, static export

- TypeScript improves reliability; Tailwind speeds up building a polished, themed UI.
- The dashboard is entirely client-side (it fetches from FastAPI), so Next.js is built as a **static export**: plain HTML, JS, and CSS served by FastAPI or a small web server. This avoids running a Node.js server as a fourth service. Server-side Next.js features (server actions, middleware) are not used.

### Live updates: Server-Sent Events

- The dashboard only **receives** events and never sends commands (R6.15), so the two-way channel of WebSockets is unnecessary.
- **Event IDs are the session event sequence numbers.** When an SSE connection drops, the browser reconnects automatically and sends the last ID it saw in the `Last-Event-ID` header; the API resends everything after it. This implements R6.13 directly.

### Authentication (consequence of SSE)

- The browser's `EventSource` API cannot send custom headers, so token-in-header auth will not work on the stream. The dashboard uses a **session cookie**: `HttpOnly`, `Secure`, `SameSite=Strict`.
- Because cookies are sent automatically, state-changing requests (e.g. admin deletion, R5.9) also require a **CSRF token**.
- Roles: **admin** (read and delete) and **judge** (read-only), enforced server-side and backed by the matching database roles in ADR-0004.

## Consequences

### Pros

- FastAPI integrates well with Python-based security tools and shares models with the honeypot.
- SSE gives efficient real-time updates without WebSocket complexity, and its built-in
reconnection with `Last-Event-ID` covers R6.13.
- TypeScript improves code reliability; Tailwind simplifies building a polished frontend.
- Static export keeps the deployment to three services (honeypot, API, database).

### Cons

- Separate frontend and backend codebases increase development complexity.
- SSE is one-way only. Acceptable, since the dashboard never sends commands (R6.15).
- Continuous event streaming consumes resources. In practice, only the defender and judges connect, and only over an internal network or VPN, so this is a handful of streams; a per-user stream cap bounds it.
- Cookie-based auth requires CSRF protection on every state-changing request.

### Risks and mitigations

| Risk |Mitigation                                                                            |
| --------------------------------------- | ---------------------------------------------------------------------------------------------- |
| Stored XSS from attacker text in the UI | Render as plain text only; never use raw-HTML rendering (R6.9); strip terminal escapes (R6.10) |
| CSRF on admin actions                   | `SameSite=Strict` cookie plus a CSRF token on state-changing requests                          |
| Judge escalates to admin actions        | Role checks enforced server-side, plus a SELECT-only DB role for judges (ADR-0004)             |
| Missed events after a disconnect        | SSE `Last-Event-ID` mapped to sequence numbers (R6.13)                                         |
| Too many open streams                   | Per-user stream cap; dashboard reachable only internally or over VPN                           |

## Verification

- [ ] A new event reaches the browser within 2 seconds (R6.3).
- [ ] After dropping the SSE connection, the browser reconnects and receives every missed event (R6.13).
- [ ] The session cookie is `HttpOnly`, `Secure`, and `SameSite=Strict`.
- [ ] An admin delete without a valid CSRF token is rejected.
- [ ] A judge session cannot delete recordings or change configuration (R6.16).
- [ ] A stored XSS payload in a recorded command renders as text and never executes (R6.9).
- [ ] The frontend builds as a static export and is served without a Node.js server.
