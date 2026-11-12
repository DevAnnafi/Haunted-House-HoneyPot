# ADR-0003: Two-Service Process Model

- **Status:** Accepted
- **Date:** 2026-11-11
- **Project:** Haunted House Honeypot
- **Decision owner:** Annafi Islam

## Context

The system has two very different jobs:
- **The SSH honeypot** faces the public internet and processes hostile input from every connection (R1, R2, R8).
- **The dashboard API** serves the defender and judges recorded sessions, live events, and replays (R6), and holds the most sensitive data and credentials. The architecture diagram already separates these into an **attacker zone** and an
- **internal zone**. This decision determines whether that separation is real at runtime:
one process sharing memory, or two independent services.

Relevant requirements:
- **R1.7:** Attackers must not reach host resources or unauthorized network resources.
- **R6.1, R6.11, R6.16:** The dashboard and its data must be reachable only by authenticated
  defenders and judges.
- **R6.12:** The dashboard keeps working when other parts fail.
- **R8:** Abusive clients must not exhaust the system.

## Options considered

1. **Single process:** the SSH server and dashboard API run in one Python process and share
   memory.
2. **Two separate services:** the honeypot and the dashboard API run as independent processes (containers), communicating only through a shared data store.

## Decision

**Run the SSH honeypot and the dashboard API as two separate services. They share no memory and communicate only through PostgreSQL (see ADR-0004).**

- The **honeypot** writes session events to PostgreSQL and notifies listeners.
- The **dashboard API** reads events from PostgreSQL and listens for those notifications to
  push live updates to the browser.

The separation is only real if it is enforced, so the following are part of this decision:

- **Separate identities:** each service runs in its own container (or as its own
  unprivileged OS user), never as root (R1.8).
- **No shared secrets:** the honeypot has no access to the dashboard's configuration,
  session keys, or database credentials, and vice versa. Each service gets only its own.
- **Network segmentation:**
  - The honeypot is the only service exposed to the internet (SSH).
  - The dashboard API is bound to an internal network, `localhost`, or a VPN, and is never
    reachable from the honeypot.
  - The honeypot may reach only PostgreSQL and the configured LLM API. All other outbound
    traffic is blocked (enforced by a host egress firewall; detailed in `design.md`,
    Deployment).

## Consequences

### Pros

- **Contained blast radius:** if an attacker exploits a flaw in the honeypot, they land in
  a locked-down container with no route to the dashboard API and no access to its
  credentials.
- **Strict network segmentation:** the honeypot can face the public internet while the
  dashboard is reachable only internally or over a VPN.
- **Fault isolation:** a botnet flood or memory crash in the honeypot does not take down the dashboard, so an active attack can still be monitored and investigated in real time (R6.12).

### Cons

- **Inter-process communication:** the services cannot share variables in memory, so every event must pass through PostgreSQL (ADR-0004).
- **Deployment overhead:** two services (plus the database) to build, configure, and monitor instead of one script.
- **Higher resource footprint:** separate processes use more RAM and CPU, which matters on small, low-cost VPS instances. Plan for at least 2 GB of RAM for the full stack.
- **The honeypot holds database credentials:** a compromised honeypot gets whatever its database role allows. ADR-0004 limits that role so it cannot read or delete history, but an attacker could still **flood or forge events**.

### Risks and mitigations

| Risk | Mitigation |
|---|---|
| Both services run as the same user, defeating isolation | Separate containers or OS users; verified at deployment |
| Honeypot can reach the dashboard API over the network | Dashboard bound to an internal network or `localhost`; no route from the honeypot's network |
| Compromised honeypot forges or floods events | Least-privilege DB role (ADR-0004); R8 rate limits; dashboard treats every recorded event as attacker-influenced data |
| Unrestricted outbound traffic from the honeypot | Host egress firewall allowing only PostgreSQL and the LLM API |
| Event delivery between services is lost | Events are durable rows in PostgreSQL; the dashboard recovers missed events by sequence number (R6.13) |

## Verification

- [ ] The honeypot and dashboard run as separate containers or OS users, neither as root.
- [ ] From inside the honeypot container, the dashboard API is unreachable.
- [ ] From inside the honeypot container, outbound connections other than PostgreSQL and the LLM API fail.
- [ ] The honeypot's environment contains no dashboard secrets.
- [ ] Killing the honeypot process leaves the dashboard running and serving recorded sessions.