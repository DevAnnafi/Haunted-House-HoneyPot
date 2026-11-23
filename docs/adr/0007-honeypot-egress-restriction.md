# ADR-0007: Honeypot Egress Restriction on the Host

- **Status:** Accepted
- **Date:** 2026-11-22
- **Project:** Haunted House Honeypot
- **Decision owner:** Annafi Islam

## Context

`product.md` sets a hard constraint: the honeypot may reach **only** PostgreSQL and the LLM API. Nothing an attacker does inside the fake shell may ever cause a real outbound connection, whether a download, a reverse shell, or a scan launched from our server. If the honeypot container were ever compromised, unrestricted egress would turn our server into part of someone's attack.

The first deployment does not use the LLM fallback, so for now the honeypot needs **no** internet access at all, only Postgres.

Two properties of Docker shape the options:

- **A container on an `internal: true` network cannot publish ports.** The honeypot must receive attackers on a published port, so it needs a normal bridge network, and a normal bridge network allows outbound traffic by default.
- **Docker has no built-in egress filtering by destination,** for either IP addresses or domains.

## Options considered

1. **Put the honeypot only on internal networks:** blocks all egress, but the honeypot can't publish its SSH port, so attackers can't reach it.
2. **An egress proxy container** (e.g. an allowlisting forward proxy) as the honeypot's only route out: supports a domain allowlist, which the LLM will need, but adds a service, and on its own doesn't stop direct connections that bypass the proxy.
3. **Host firewall rules in Docker's `DOCKER-USER` chain,** matching the honeypot network's subnet: allow replies to inbound connections, and drop every new outbound connection.

## Decision

**Enforce egress on the Linux host with `DOCKER-USER` iptables rules (option 3), and fail closed.**

- `honeypot_net` has a **fixed subnet** in `docker-compose.yml`, so the rules can match it exactly. It carries **ingress only**.
- The honeypot reaches Postgres only over **`db_net`** (`internal: true`), which never leaves Docker.
- `scripts/egress-firewall.sh` adds the rules in `DOCKER-USER`: allow `ESTABLISHED,RELATED` (replies to attackers' SSH connections), and drop new connections that originate from the honeypot subnet, whatever the protocol.
- An **`INPUT` rule** also drops new connections from the honeypot subnet to the **host itself**, so the container can't reach services running on the server (traffic to the host goes through `INPUT`, not `DOCKER-USER`).
- **DNS needs its own measure.** On user-defined networks, a container's lookups go to Docker's embedded resolver (`127.0.0.11`), which forwards them to upstream servers **from the host**, not from the container's subnet, so the `DOCKER-USER` rules never see them. `docker-compose.yml` therefore sets `dns: 192.0.2.1` for the honeypot, a reserved documentation address (TEST-NET-1) that never answers, so external lookups fail. The embedded resolver still answers for container names on Docker networks, so `postgres` keeps resolving over `db_net`.
- The script is **idempotent** (running it again leaves an identical ruleset), rejects malformed subnets, and refuses to run if Docker's network uses a different subnet than expected.

### Boot ordering

Testing found a race: Docker restarted the honeypot container at boot **before** the firewall unit ran, leaving it unfiltered for a few seconds. The fix:

- The systemd unit runs **before `docker.service`** and creates the `DOCKER-USER` chain itself if it doesn't exist yet. Docker keeps an existing `DOCKER-USER` chain and its rules, and adds its own jump to it.
- In this mode (`--before-docker`), the script skips the subnet check, because calling the `docker` CLI at that point would start Docker through `docker.socket` while Docker waits for this unit, a deadlock. The check still runs on a normal `apply`.
- The unit also starts after `ufw`, `firewalld`, and `netfilter-persistent`, so they can't remove its rules afterwards.
- **`TimeoutStartSec=60`:** the script waits for the iptables lock without a time limit, and oneshot units have no start timeout by default. Without this, a stuck lock would hang the boot indefinitely instead of failing visibly.

### Fail closed

The unit uses **`RequiredBy=docker.service`**: if the firewall script fails at boot, Docker does not start, and neither does the honeypot.

- This host runs **only** the honeypot stack, so a firewall failure stopping Docker is an acceptable outage.
- Running the honeypot without egress rules is not acceptable: it is exactly what the hard constraint forbids, and it could go unnoticed for hours.
- Administrator access is unaffected, because admin SSH is the host's own `sshd`, not a container.
- **Side effect:** because Docker requires the unit, **restarting or stopping the unit also restarts or stops Docker** and every container. To reapply rules (after a firewall reload or a script update), run the script directly instead, which leaves Docker alone. Never disable the unit to get the honeypot back up: that removes the protection this ADR exists for.

### When the LLM arrives

LLM egress will go through an **allowlisting proxy** (option 2) on its own network. The host rules stay in place, so the proxy becomes the only permitted route out, and direct connections remain blocked. That change will amend this ADR.

## Consequences

### Pros

- Blocks all outbound traffic from the honeypot, whatever protocol an attacker tries.
- Enforced outside the container: a compromised honeypot process can't change it.
- Closed at boot as well as during normal operation, and fails closed.
- Small and testable: one script and one systemd unit.

### Cons

- Linux-only (iptables), so it isn't active in local development on Windows.
- Depends on the subnet in `docker-compose.yml` and the script staying in sync; the script's check catches a mismatch.
- A firewall failure takes the whole stack down (by design).
- A `firewalld` reload removes the rules until the script is run again (Ubuntu doesn't use `firewalld` by default).
- Restarting the unit restarts Docker, so rules must be reapplied by running the script directly.
- DNS blocking depends on the `dns:` setting in `docker-compose.yml`, not on the firewall rules.

### Risks and mitigations

| Risk | Mitigation |
|---|---|
| Container unfiltered during boot | Unit runs before `docker.service` and creates `DOCKER-USER` itself |
| Firewall script fails at boot | `RequiredBy=docker.service`: the honeypot doesn't start (fail closed) |
| Compose subnet changes without the script | `apply` refuses to run on a subnet mismatch |
| Another firewall tool flushes the rules | Unit ordered after `ufw`, `firewalld`, and `netfilter-persistent`; verification after every reboot |
| DNS lookups bypass `DOCKER-USER` via Docker's resolver | `dns: 192.0.2.1` for the honeypot; verification checks that lookups fail |
| Container reaches services on the host | `INPUT` rule drops new connections from the honeypot subnet to the host |
| Stuck iptables lock hangs the boot | `TimeoutStartSec=60` makes the unit fail visibly (and Docker stays down) |
| Admin restarts the unit and takes Docker down | Docs say to run the script directly to reapply rules |
| CRLF line endings break the script on Linux | `.gitattributes` keeps `*.sh` at LF |
| LLM needs internet access later | Allowlisting proxy as the only route out; host rules stay |

## Verification

- [x] Running `apply` three times leaves an identical ruleset; `remove` cleans up completely.
- [x] With no `dockerd` running, `apply --before-docker` creates `DOCKER-USER` and the rules; `dockerd` keeps them when it starts (tested with Docker-in-Docker).
- [x] A container in the honeypot subnet can't reach `1.1.1.1:443`; a container on another network can.
- [x] The rules survive a `dockerd` restart.
- [x] Under real systemd with a stub `docker.service`: if the script errors, is missing, or hangs past the timeout, the unit fails and Docker doesn't start; after the cause is fixed, starting Docker runs the firewall first.
- [ ] On the real VPS: after a reboot, from inside the honeypot container, a TCP connection to `1.1.1.1:443` fails, DNS lookups of external names fail, and `postgres` still resolves.
- [ ] On the real VPS: from inside the honeypot container, connections to the host's own services fail.
- [ ] On the real VPS: `journalctl` shows the unit ran before `docker.service`.
- [ ] On the real VPS: if the unit is made to fail, Docker doesn't start.