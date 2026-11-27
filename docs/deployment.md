# Deployment

Production setup for the honeypot on a single Linux VPS. Commands are bash, run on the server
from the repository checkout unless noted.

> Other deployment steps (moving the admin sshd off port 22, dashboard users, judge access)
> are not written yet.

## Egress control (T9.6)

The honeypot container may open connections only to PostgreSQL. Every other outbound
connection is blocked: the internet, the LAN, and the host's own addresses. Replies to inbound
SSH connections still work. The first deployment does not use the LLM. LLM traffic will go
through an allowlisting proxy later (see `design.md`, Deployment).

### How it is enforced

- **PostgreSQL:** the honeypot reaches it over `db_net`. That network is `internal: true`, so
  its traffic never leaves Docker.
- **The firewall:** `honeypot_net` cannot be internal, because Docker publishes the SSH port
  through it. Compose gives it a fixed subnet, `172.30.250.0/24`.
  `scripts/egress-firewall.sh` sends all traffic from that subnet to a chain named
  `HONEYPOT_EGRESS`. The chain accepts `ESTABLISHED,RELATED` packets (replies to inbound SSH)
  and drops everything else. Two rules jump to that chain:
  - one in `DOCKER-USER`, for traffic Docker routes off the host;
  - one in `INPUT`, for connections to the host itself, which never pass `DOCKER-USER`.
- **IPv6:** `honeypot_net` does not enable IPv6, so the container should never send an IPv6
  packet. The script still builds the same structure with `ip6tables`, as a second layer: a
  `HONEYPOT_EGRESS` chain in the IPv6 tables, jumped to from `DOCKER-USER` and `INPUT`. What the
  jump rules match depends on the network:
  - **No IPv6 subnet (the normal case):** the rules match the honeypot's bridge interface,
    `-i honeypot0`, and the chain is a single `DROP`. All IPv6 traffic that enters the host
    from that bridge is dropped. There are no replies to allow, because no IPv6 connection to
    the container can exist.
  - **IPv6 subnet known** (you enabled IPv6 on the network, or set `HONEYPOT_NET_SUBNET6`): the
    rules match `-s <subnet>`, and the chain accepts `ESTABLISHED,RELATED` and drops the rest,
    like the IPv4 chain.

  The interface name is fixed in `docker-compose.yml` (`com.docker.network.bridge.name:
  honeypot0`), because at boot the network does not exist yet and the script cannot ask Docker
  for a generated `br-xxxx` name. `apply` reads the name and the IPv6 subnet from the Docker
  network when it exists, and refuses to run if the network's bridge name is not `honeypot0`.
  `apply --before-docker` can't ask Docker, so it uses the interface rule unless
  `HONEYPOT_NET_SUBNET6` is set.
- **DNS:** the firewall rules never see DNS. Docker's embedded resolver (`127.0.0.11`) makes
  outside lookups on the container's behalf. So the honeypot service sets `dns: 192.0.2.1`, an
  unroutable TEST-NET-1 address, in `docker-compose.yml`. Outside names fail to resolve.
  Container names such as `postgres` still resolve.

Requirements on the host:
- The `iptables` command must use the same backend as Docker (`iptables-nft` or
  `iptables-legacy`). Ubuntu 24.04 uses nft for both by default.
- Docker's experimental nftables firewall backend is not supported, because it never uses a
  `DOCKER-USER` chain. With that backend, the chain the script creates is never consulted
  and the rules have no effect. Verification check 1 below catches this.
- The `ip6tables` command must exist too. `apply` stops with an error if it is missing, so
  the unit fails and Docker does not start (fail closed).
- If you change the subnet or the bridge name in `docker-compose.yml`, change
  `HONEYPOT_NET_SUBNET` or `HONEYPOT_BRIDGE_IFACE` to match. The script refuses to run if the
  existing Docker network uses a different subnet or bridge name.
- **Upgrading a host that ran an earlier version:** its `honeypot_net` has a generated bridge
  name, so `apply` stops with `has bridge name '<generated>', not honeypot0`. Recreate the
  network: `docker compose down && docker compose up -d --build`, then run `apply` again.
  The IPv4 rules are unaffected by the name.

### Install

Install the script as a root-owned copy. The firewall then never runs a file that the deploy
user (or a later `git pull`) could change.

```bash
sudo install -o root -g root -m 0755 scripts/egress-firewall.sh /usr/local/sbin/honeypot-egress-firewall
```

Apply the rules before starting the stack, so the honeypot never runs without them. Then
apply again once the stack is up. The second run checks that the Docker network got the
expected subnet; the first run can't, because the network does not exist yet.

```bash
sudo /usr/local/sbin/honeypot-egress-firewall apply
docker compose up -d --build
sudo /usr/local/sbin/honeypot-egress-firewall apply
sudo /usr/local/sbin/honeypot-egress-firewall status
```

`apply` handles IPv4 and IPv6 together, and is idempotent: run it again and it reports
`IPv4: rules for -s 172.30.250.0/24 already in place` and `IPv6: rules for -i honeypot0 already
in place`, and changes nothing. If someone edits a chain, the next `apply` rebuilds it before
re-adding the jump rules. A jump rule that matches something else (for example after you
set `HONEYPOT_NET_SUBNET6`) is replaced. `remove` deletes the IPv4 and IPv6 rules and chains and
restores unrestricted egress. If any step of `apply` fails, it exits non-zero.

### Persist across reboots

iptables rules live in memory and are gone after a reboot. Don't save the whole ruleset with
`iptables-save` or `netfilter-persistent`: that also saves Docker's own rules, which then clash
with the ones Docker creates at startup. Instead, run the script from a systemd unit that
starts before Docker, so the rules exist before any container starts:

```bash
sudo tee /etc/systemd/system/honeypot-egress.service >/dev/null <<'EOF'
[Unit]
Description=Honeypot egress firewall (IPv4 and IPv6 DOCKER-USER and INPUT rules, T9.6)
# Runs before Docker starts, so no container ever runs without the rules.
Before=docker.service
# Host firewalls that rewrite INPUT start first, so they cannot remove the rule.
After=ufw.service firewalld.service netfilter-persistent.service
# Re-apply whenever Docker restarts.
PartOf=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
# --before-docker: Docker is not running yet, so don't call the docker CLI.
ExecStart=/usr/local/sbin/honeypot-egress-firewall apply --before-docker
# Oneshot units have no start timeout by default, and the script waits for the iptables
# lock. Fail (and keep Docker down) instead of hanging the boot forever.
TimeoutStartSec=60

[Install]
# Fail closed: Docker does not start unless this unit succeeded (see below).
RequiredBy=docker.service
EOF
sudo systemctl daemon-reload
sudo systemctl reenable honeypot-egress.service
sudo systemctl restart docker.service
systemctl status honeypot-egress.service docker.service --no-pager
```

`reenable` creates the link `docker.service.requires/honeypot-egress.service`, so Docker
requires this unit. It also removes the `WantedBy=` link if an earlier version of this unit was
enabled. `Before=` makes systemd finish this unit before it starts Docker. Restarting Docker
once runs both in that order now, without waiting for a reboot. Restarting Docker also restarts
the running containers.

#### Why it fails closed

If this unit fails, Docker does not start, so no container runs, including the honeypot.
This is on purpose. The host runs only the honeypot stack, so Docker failing to start costs an
outage of the honeypot and its database, and nothing else. Running the honeypot without egress
rules is not acceptable: an internet-facing deception host with open egress could be used to
reach other systems. Given the choice, the host stays down.

`RequiredBy=` has side effects:
- **Restart and stop:** `systemctl restart honeypot-egress.service` also restarts Docker and
  every container, and `systemctl stop honeypot-egress.service` also stops Docker. To re-apply
  the rules without touching Docker, run the script directly:
  `sudo /usr/local/sbin/honeypot-egress-firewall apply`.
- **Don't work around it:** don't disable the unit, or start Docker without it, to get the
  honeypot back up. Fix the cause instead.

How the ordering works:
- At boot, the `DOCKER-USER` chain does not exist yet, so `apply` creates it.
- When Docker starts, it keeps the existing chain and its rules, and adds its own jump from
  `FORWARD` to it. Then it starts the containers.
- `--before-docker` skips the script's check that the Docker network has the expected
  subnet. That check runs the `docker` CLI. At boot, the CLI would start Docker through
  `docker.socket` while Docker is waiting for this unit, and the two would wait on each other.
- Run `apply` without the flag once after a deployment (see Install) to run the subnet check.

After a reboot, check that the unit ran before Docker:

```bash
journalctl -b -o short-monotonic -u honeypot-egress.service -u docker.service | head -n 5
```

The `honeypot-egress` lines must come before Docker's first line.

#### When Docker does not start: diagnose

Symptoms: after a reboot or a `systemctl start docker`, the honeypot does not answer, and
`docker` commands fail with `Cannot connect to the Docker daemon`. `systemctl start docker`
prints `A dependency job for docker.service failed`.

1. Check both units:

   ```bash
   systemctl status honeypot-egress.service docker.service --no-pager
   ```

   If the firewall caused it, `honeypot-egress.service` is `failed (Result: exit-code)` and
   `docker.service` is `inactive (dead)`. Docker is not `failed`, so `systemctl --failed` lists
   only `honeypot-egress.service`. The last lines of the status output show the script's error.

2. Read this boot's log for both units, in order:

   ```bash
   journalctl -b -u honeypot-egress.service -u docker.service --no-pager
   ```

   A firewall failure looks like this:

   ```
   honeypot-egress-firewall[592]: egress-firewall: ERROR: <reason>
   systemd[1]: Failed to start honeypot-egress.service - Honeypot egress firewall ...
   systemd[1]: Dependency failed for docker.service - Docker Application Container Engine.
   systemd[1]: docker.service: Job docker.service/start failed with result 'dependency'.
   ```

   The `ERROR:` line names the cause. Every error the script reports starts with
   `egress-firewall: ERROR:`.
   - **`iptables not found` or `ip6tables not found`:** install the `iptables` package, which
     provides both.
   - **`HONEYPOT_BRIDGE_IFACE ...` or `HONEYPOT_NET_SUBNET6 ...`:** an invalid value was set,
     for example in a systemd drop-in.
   - **`HONEYPOT_NET_SUBNET ...`:** an invalid subnet was set, for example in a systemd
     drop-in. Fix it so it matches `docker-compose.yml`.
   - **`run as root`:** the unit was changed to run as another user. It must run as root.
   - **No `egress-firewall:` line at all, and `status=203/EXEC`:** the installed script is
     missing or not executable. Run the `install` command again.
   - **`Result: timeout`, and no `ERROR:` line:** the script was still waiting after 60
     seconds, usually because another tool held the iptables lock. Check for a stuck
     firewall tool (`ps aux | grep -E 'iptables|ufw|firewall'`), then retry (step 3).

3. Fix the cause, then start Docker. This runs the firewall unit first, and starts Docker only
   if the unit succeeds:

   ```bash
   sudo systemctl start docker.service
   systemctl is-active honeypot-egress.service docker.service   # both must print "active"
   ```

   Then run the verification below.

To test the script by itself without involving systemd, run
`sudo /usr/local/sbin/honeypot-egress-firewall apply --before-docker`. It prints the same
messages to the terminal.

Known gaps:
- **Firewall reloads:** `firewall-cmd --reload` (firewalld) flushes the rules. After any host
  firewall reload, run `sudo /usr/local/sbin/honeypot-egress-firewall apply`.
- **Script updates:** the unit runs the installed copy. After changing
  `scripts/egress-firewall.sh`, run the `install` command again, then
  `sudo /usr/local/sbin/honeypot-egress-firewall apply`. The next boot uses the new copy
  automatically.

### Verify (required after every deployment and every reboot)

Run each check from inside the running honeypot container. The image has no shell tools, so
the checks use its Python.

**1. A TCP connection to 1.1.1.1:443 must fail.**

```bash
docker compose exec -T honeypot python - <<'EOF'
import socket
try:
    socket.create_connection(("1.1.1.1", 443), timeout=5)
    print("FAIL: connected to 1.1.1.1:443, egress is OPEN")
except OSError as exc:
    print("OK: blocked:", type(exc).__name__)
EOF
```

Expected: `OK: blocked: TimeoutError` (the packets are dropped, so the attempt times out).

**2. DNS lookups must fail**, both through the container's resolver and directly to a public
resolver.

```bash
docker compose exec -T honeypot python - <<'EOF'
import socket
try:
    socket.getaddrinfo("example.com", 443)
    print("FAIL: example.com resolved, DNS is OPEN")
except socket.gaierror as exc:
    print("OK: lookup failed:", exc)
query = bytes.fromhex("123401000001000000000000076578616d706c6503636f6d0000010001")
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
try:
    s.sendto(query, ("8.8.8.8", 53))
    s.recv(512)
    print("FAIL: 8.8.8.8 answered, DNS is OPEN")
except OSError as exc:
    print("OK: direct query blocked:", type(exc).__name__)
EOF
```

Expected:
```
OK: lookup failed: [Errno -3] Temporary failure in name resolution
OK: direct query blocked: TimeoutError
```

**3. What must still work.**

```bash
docker compose exec -T honeypot python - <<'EOF'
import socket
socket.create_connection(("postgres", 5432), timeout=5)
print("OK: postgres reachable over db_net")
EOF
```

Then, from a machine outside the server, check that SSH still answers:
`ssh -p 22 root@<server>` must show a login prompt.

**4. An IPv6 connection must fail.** The container has no IPv6 address, so this fails at once
with `Network is unreachable`, or times out if an IPv6 route exists and the firewall drops it.
Either is a pass. A connection is the only failure.
```bash
docker compose exec -T honeypot python - <<'EOF'
import socket
try:
    socket.create_connection(("2606:4700:4700::1111", 443), timeout=5)
    print("FAIL: connected over IPv6, egress is OPEN")
except OSError as exc:
    print("OK: blocked:", type(exc).__name__, exc)
EOF
```
On the host, check the IPv6 rules are in place:
```bash
sudo ip6tables -S HONEYPOT_EGRESS      # normal case: -N HONEYPOT_EGRESS, -A HONEYPOT_EGRESS -j DROP
sudo ip6tables -S DOCKER-USER | grep HONEYPOT_EGRESS   # -A DOCKER-USER -i honeypot0 -j HONEYPOT_EGRESS
sudo ip6tables -S INPUT | grep HONEYPOT_EGRESS         # -A INPUT -i honeypot0 -j HONEYPOT_EGRESS
```
**5. The cloud metadata service must be unreachable.** On DigitalOcean, `169.254.169.254` serves
the droplet's metadata (user data, which can hold secrets, and the droplet's identity). The
container must not reach it. The IPv4 rules above cover it, because the connection is a new one
that starts in the honeypot subnet. This check proves it.
```bash
docker compose exec -T honeypot python - <<'EOF'
import socket
for port in (80, 443):
    try:
        socket.create_connection(("169.254.169.254", port), timeout=5)
        print(f"FAIL: connected to 169.254.169.254:{port}, metadata service is REACHABLE")
    except OSError as exc:
        print(f"OK: 169.254.169.254:{port} blocked:", type(exc).__name__)
EOF
```
Expected: `OK: ... blocked: TimeoutError` for both ports. For comparison, from the host itself,
`curl -s --max-time 5 http://169.254.169.254/metadata/v1/id` returns the droplet ID. Run it
outside the container, to confirm the service exists and that the block is the firewall's work.
If any check prints `FAIL`, run `sudo /usr/local/sbin/honeypot-egress-firewall status`. Then
check that `docker network inspect haunted-house-honeypot_honeypot_net` shows subnet
`172.30.250.0/24`, and keep the honeypot stopped (`docker compose stop honeypot`) until every
check passes.

### Verify the container's privileges (required after every deployment)

The egress rules assume the honeypot container cannot reach the host or change the network. These
checks read the settings Docker applied to the running container. Run them on the host, from the
repository checkout, after `docker compose up -d`. Each line must start with `OK`.

First, the compose file. This must print nothing: none of these keys appear in the resolved
configuration (a `grep` match would show the key and its line number).
```bash
docker compose config | grep -nE 'privileged|network_mode|pid:|ipc:|docker\.sock|enable_ipv6'
```
Then the running container:
```bash
C=$(docker compose ps -q honeypot)
[ -n "$C" ] || { echo "FAIL: honeypot container is not running"; exit 1; }
insp() { docker inspect -f "$1" "$C"; }
eq()   { if [ "$2" = "$3" ]; then echo "OK:   $1"; else echo "FAIL: $1 (got '$2', want '$3')"; fi; }
ne()   { if [ "$2" != "$3" ]; then echo "OK:   $1"; else echo "FAIL: $1 (got '$2')"; fi; }

# Not privileged, and not sharing the host's network, PID or IPC namespaces.
eq "not privileged"               "$(insp '{{.HostConfig.Privileged}}')" false
ne "network mode is not host"     "$(insp '{{.HostConfig.NetworkMode}}')" host
ne "PID namespace is not host"    "$(insp '{{.HostConfig.PidMode}}')" host
ne "IPC namespace is not host"    "$(insp '{{.HostConfig.IpcMode}}')" host

# No Docker socket in any mount form (Mounts, Binds, or HostConfig.Mounts).
eq "no docker.sock mount" \
  "$(insp '{{json .Mounts}} {{json .HostConfig.Binds}} {{json .HostConfig.Mounts}}' | grep -c 'docker\.sock' || true)" 0

# The host key is the only bind mount, and it is read-only. (A tmpfs on /tmp is not a bind.)
eq "one bind mount: the host key, read-only" \
  "$(insp '{{range .Mounts}}{{if eq .Type "bind"}}{{.Destination}} rw={{.RW}}{{"\n"}}{{end}}{{end}}')" \
  "/run/secrets/ssh_host_key rw=false"
eq "no named or anonymous volumes" \
  "$(insp '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}} {{end}}{{end}}')" ""
echo "host path of the key (should be outside the repo): $(insp '{{range .Mounts}}{{if eq .Type "bind"}}{{.Source}} {{end}}{{end}}')"

# Attached only to its two networks, neither network has IPv6, and the container has no IPv6 address.
eq "attached to exactly honeypot_net and db_net" \
  "$(insp '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}} {{end}}' | tr ' ' '\n' | sed '/^$/d' | sort | paste -sd' ')" \
  "haunted-house-honeypot_db_net haunted-house-honeypot_honeypot_net"
for n in $(insp '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}} {{end}}'); do
  eq "network $n: IPv6 disabled" "$(docker network inspect -f '{{.EnableIPv6}}' "$n")" false
  # An empty address prints as "" or "invalid IP", depending on the Docker version.
  eq "container has no IPv6 address on $n" \
    "$(insp "{{(index .NetworkSettings.Networks \"$n\").GlobalIPv6Address}}" | sed 's/^invalid IP$//')" ""
done
```
If a line prints `FAIL`, stop the honeypot (`docker compose stop honeypot`), fix the setting in
`docker-compose.yml`, recreate the container (`docker compose up -d --force-recreate honeypot`) and
run the checks again. `docker compose up -d` does not recreate a container whose configuration
did not change, so a changed setting is not applied until the container is recreated.