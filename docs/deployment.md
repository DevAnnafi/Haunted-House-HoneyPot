# Deployment

How to set up the honeypot on a fresh Ubuntu 24.04 VPS (a DigitalOcean Droplet), from first
login to a verified, running stack. Do the steps in order. Each step assumes the earlier ones are
done.

Conventions:

- Commands are bash, run on the server as an admin user with `sudo` rights. The admin user is
  **not** in the `docker` group, so every command that touches Docker, the firewall, system
  services or the secret files starts with `sudo`.
- The repository lives in `/opt/honeypot`. Run `cd /opt/honeypot` once per login session
  after step 4. It is the only command here without `sudo`, because `cd` is a shell builtin.
  `sudo` keeps your current directory, so `sudo docker compose ...` finds the compose file.
- Commands to run on your own computer (not the server) are marked as such.
- Placeholders in angle brackets, such as `<droplet-ip>`, are for you to replace.

| Step | What | Why this position |
|---|---|---|
| 1 | Prepare the server | packages the later steps use |
| 2 | Harden the admin sshd and move it off port 22, attach the Cloud Firewall | the honeypot needs port 22; the firewall keeps it closed until you go live |
| 3 | Install Docker Engine | |
| 4 | Clone the repository to `/opt/honeypot` | |
| 5 | Create the SSH host key | the honeypot refuses to start without it |
| 6 | Create the secret files | all secrets are generated on the server |
| 7 | Install the egress firewall | before any container exists |
| 8 | Start PostgreSQL only | the schema must exist before the honeypot starts |
| 9 | Create the schema with `scripts/init-db.sh` | |
| 10 | Start the full stack | |
| 11 | Verify egress | required after every deployment and reboot |
| 12 | Verify container privileges | required after every deployment |
| 13 | Pre-launch state and going live | |

The sections after step 13 explain how the egress firewall works and how to diagnose it.

## Step 1: Prepare the server

```bash
sudo apt-get update
sudo apt-get -y upgrade
sudo apt-get -y install git openssl iptables ca-certificates curl
```

`iptables` also provides `ip6tables`, which the egress firewall needs. If `apt` reports that a
reboot is required (`/var/run/reboot-required` exists), run `sudo reboot` now and log in again
before continuing.

## Step 2: Harden the admin sshd, move it off port 22, attach the Cloud Firewall

The honeypot publishes **host port 22** (`"22:2222"` in `docker-compose.yml`). The server's own
sshd must therefore leave port 22 before step 10, or the honeypot cannot bind it. Do this
now, while you are still logged in on port 22, and attach the Cloud Firewall straight after, so
the honeypot is never exposed before you decide.

Pick an admin SSH port, for example a number between 1024 and 65535 that nothing else uses. This
document calls it `<admin-port>`. Replace `<admin-port>` and `<admin-user>` with your values
everywhere they appear.

The admin sshd is hardened and moved in one step, with a drop-in file instead of editing the main
`/etc/ssh/sshd_config`.

**Before you start, make sure key login already works for `<admin-user>`.** The drop-in turns
passwords off, so a missing or wrong key means you cannot log in again except through the
Droplet Console. Check that you got in with a key (your `~/.ssh/authorized_keys` has your public
key) and that `<admin-user>` can use `sudo`.

```bash
sudo tee /etc/ssh/sshd_config.d/00-hardening.conf >/dev/null <<'EOF'
# Admin sshd for this server. The honeypot owns port 22.
Port <admin-port>
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
AllowUsers <admin-user>
EOF
sudo sshd -t
sudo sshd -T | grep -E '^(port|permitrootlogin|passwordauthentication|kbdinteractiveauthentication|authenticationmethods|allowusers) '
```

`sshd -t` must print nothing (the file is valid). The `sshd -T` lines show the settings sshd will
actually use, after all config files are combined. They must read `port <admin-port>`,
`permitrootlogin no`, `passwordauthentication no`, `kbdinteractiveauthentication no`,
`authenticationmethods publickey` and `allowusers <admin-user>`. If a value is different,
another file is overriding yours: fix that before you continue.

Then apply it:

```bash
sudo systemctl daemon-reload
sudo systemctl restart ssh.socket
sudo ss -ltnp | grep -E ':(22|<admin-port>)\b'
```

The `ss` output must show listeners on `<admin-port>` (IPv4 and IPv6) and none on port `22`.

**Why this moves the socket:** Ubuntu 24.04 starts sshd through a systemd socket (`ssh.socket`),
and the socket, not sshd, owns the listening port. Ubuntu ships a systemd generator
(`sshd-socket-generator`) that reads the `Port` (and `ListenAddress`) lines from the sshd
configuration when systemd reloads, and applies them to the socket. So `daemon-reload` makes
systemd re-read the `Port` from the drop-in, and `restart ssh.socket` re-binds the socket. You do
not need to write an `ssh.socket` override. Restarting the socket also restarts a running
`ssh.service` onto the new port, and your open session stays connected. Because the generator
runs on every boot, the port survives a reboot.

**Why the file is named `00-`:** `/etc/ssh/sshd_config` starts with
`Include /etc/ssh/sshd_config.d/*.conf`, and sshd reads the included files in alphabetical order.
For most settings, sshd uses the **first** value it reads and ignores later ones. Cloud images
can ship `/etc/ssh/sshd_config.d/50-cloud-init.conf`, which on some images sets
`PasswordAuthentication yes`. Our file must come before it, and `00-` sorts before `50-`. With a
name such as `99-hardening.conf`, the cloud-init value would win and passwords would stay
enabled. (`Port` is an exception: sshd collects every `Port` line, so the file name does not
matter for the port. It matters for all the other lines.) Don't edit `50-cloud-init.conf`:
cloud-init may rewrite it.

**Keep this login open.** Open a second terminal on your own computer and log in on the new port
with your key:

```bash
ssh -p <admin-port> <admin-user>@<droplet-ip>
```

Only when that works, continue. If it doesn't, fix it from the first terminal (for example
`sudo sshd -T` shows which value is wrong), or use the Droplet Console in the DigitalOcean control
panel. If `sudo ufw status` says `active`, also run `sudo ufw allow <admin-port>/tcp`. UFW is
inactive on a default DigitalOcean image.

Now create the **Cloud Firewall** in the DigitalOcean control panel (Networking, Firewalls,
Create Firewall) and attach it to the Droplet:

- **Inbound rules:** one rule only: type `Custom`, protocol `TCP`, port `<admin-port>`, source
  **your own IP address**. The form pre-fills an `SSH` rule for port 22: **delete it**. There is no
  inbound rule for port 22 at this point, so the Droplet does not answer on port 22 from the
  internet. That is the pre-launch state (step 13).
- **Outbound rules:** leave the default (allow all). The egress firewall in step 7 is what limits
  the honeypot container.

Check from your own computer that port 22 is closed and the admin port works:

```bash
nc -vz -w 5 <droplet-ip> 22              # must time out
nc -vz -w 5 <droplet-ip> <admin-port>    # must succeed
```

`nc` is not on every desktop. In Windows PowerShell, use `Test-NetConnection <droplet-ip> -Port 22`
(look at `TcpTestSucceeded`). From now on, use `ssh -p <admin-port>` for every login.

## Step 3: Install Docker Engine

This follows Docker's instructions for Ubuntu (docs.docker.com/engine/install/ubuntu). It
installs Docker Engine and the Compose plugin from Docker's apt repository.

```bash
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
sudo tee /etc/apt/sources.list.d/docker.sources >/dev/null <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF
sudo apt-get update
sudo apt-get -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo docker version --format 'server {{.Server.Version}}'
sudo docker compose version
```

Do not add your admin user to the `docker` group: membership gives root-equivalent access.

## Step 4: Clone the repository to /opt/honeypot

```bash
sudo git clone https://github.com/DevAnnafi/Haunted-House-HoneyPot.git /opt/honeypot
sudo git -C /opt/honeypot log -1 --oneline
cd /opt/honeypot
```

The checkout is owned by root. If the repository is private, give the server a read-only deploy
key first; do not paste a personal access token into a command.

## Step 5: Create the SSH host key

The honeypot presents this key to every client. A new key means returning visitors see a changed
host key, so generate it once, keep it, and never replace it casually.

```bash
sudo mkdir -p /etc/honeypot
sudo chmod 0750 /etc/honeypot
sudo test ! -e /etc/honeypot/ssh_host_key || echo "STOP: a host key already exists. Do not run the next command."
sudo ssh-keygen -t ed25519 -N "" -C "" -f /etc/honeypot/ssh_host_key
sudo chown 10001:10001 /etc/honeypot/ssh_host_key
sudo chmod 0400 /etc/honeypot/ssh_host_key
sudo ls -ln /etc/honeypot
sudo ssh-keygen -lf /etc/honeypot/ssh_host_key.pub
```

`10001` is the user and group the honeypot container runs as (`Dockerfile`). The private key is
owned by that uid with mode `0400`, so only the container user (and root) can read it. In
`sudo ls -ln` the key line must start with `-r--------` followed by `1 10001 10001`. The last
command prints the key's fingerprint; keep it to compare in step 13. `/etc/honeypot` is outside
the repository, so `git` never sees the key.

The `.env` file in the next step sets `HONEYPOT_HOST_KEY_FILE=/etc/honeypot/ssh_host_key`,
which tells `docker-compose.yml` which host file to mount (read-only) at
`/run/secrets/ssh_host_key` in the container.

## Step 6: Create the secret files

Three files hold the secrets. All are gitignored, owned by root, mode 600. Every secret is
generated on the server by `openssl rand` and goes straight into a file: nothing is printed,
and nothing travels through your terminal history.

| File | Read by | Contains |
|---|---|---|
| `.env` | the honeypot container (compose `env_file`) | HMAC secret, demo login, database URL, host key path |
| `postgres.env` | the postgres container | the PostgreSQL superuser password |
| `db-roles.env` | `scripts/init-db.sh` only (no container) | the three database role passwords |

The role passwords are in their own file so the honeypot container never receives the dashboard
passwords (ADR-0003). The `honeypot_writer` password is also inside `HONEYPOT_DATABASE_URL`
in `.env`, because the honeypot needs it. The block below generates it once and writes it to both.

All values are hex (`0-9a-f`, from `openssl rand -hex`), which is safe in a URL and in the
`.env` files. The HMAC secret must be hex (`honeypot/auth.py` calls `bytes.fromhex` on it): 64
characters here.

```bash
sudo bash -s <<'SCRIPT'
set -euo pipefail
umask 077
cd /opt/honeypot
for f in .env postgres.env db-roles.env; do
  [ ! -e "$f" ] || { echo "STOP: $f already exists. Delete it first if you mean to start over." >&2; exit 1; }
done
# Fresh secrets. Variables only; nothing is echoed.
HMAC_SECRET="$(openssl rand -hex 32)"
DEMO_USER="demo-$(openssl rand -hex 4)"
DEMO_PASS="$(openssl rand -hex 16)"
POSTGRES_PW="$(openssl rand -hex 24)"
WRITER_PW="$(openssl rand -hex 24)"
ADMIN_PW="$(openssl rand -hex 24)"
JUDGE_PW="$(openssl rand -hex 24)"
# Replace KEY=... in a copied example file. Fails if the key is missing, so a renamed
# variable can't leave a placeholder behind. Values are hex or fixed text, so they
# contain nothing that sed treats specially.
set_var() {
  grep -q "^$2=" "$1" || { echo "missing $2 in $1" >&2; exit 1; }
  sed -i "s|^$2=.*|$2=$3|" "$1"
}
cp .env.example .env
cp postgres.env.example postgres.env
set_var .env HONEYPOT_HMAC_SECRET "$HMAC_SECRET"
set_var .env HONEYPOT_DEMO_USERNAME "$DEMO_USER"
set_var .env HONEYPOT_DEMO_PASSWORD "$DEMO_PASS"
set_var .env HONEYPOT_DATABASE_URL "postgresql://honeypot_writer:${WRITER_PW}@postgres:5432/honeypot"
set_var .env HONEYPOT_HOST_KEY_FILE /etc/honeypot/ssh_host_key
set_var postgres.env POSTGRES_PASSWORD "$POSTGRES_PW"
printf '%s\n' \
  "HONEYPOT_WRITER_PASSWORD=${WRITER_PW}" \
  "DASHBOARD_ADMIN_PASSWORD=${ADMIN_PW}" \
  "DASHBOARD_JUDGE_PASSWORD=${JUDGE_PW}" > db-roles.env
chown root:root .env postgres.env db-roles.env
chmod 600 .env postgres.env db-roles.env
echo "secret files created"
SCRIPT
```

Check the result. Nothing in these checks prints a secret.

```bash
sudo ls -l /opt/honeypot/.env /opt/honeypot/postgres.env /opt/honeypot/db-roles.env
sudo grep -cE 'change-me|generate-with' /opt/honeypot/.env /opt/honeypot/postgres.env /opt/honeypot/db-roles.env
sudo awk -F= '/^HONEYPOT_HMAC_SECRET=/ {print "HMAC secret length:", length($2)}' /opt/honeypot/.env
sudo git -C /opt/honeypot status --short
```

Expected: each file shows `-rw------- 1 root root`; the `grep -c` counts are all `0` (no
placeholder left); the HMAC secret length is `64`; `git status` lists none of the three files
(they are gitignored).

The demo login is the account judges use. To copy it for the private Devpost form, show it once:

```bash
sudo grep -E '^HONEYPOT_DEMO_(USERNAME|PASSWORD)=' /opt/honeypot/.env
```

Then clear the terminal. Share it only through the private form. Never put any of these files,
or their values, in the repository, a chat, or a ticket. Back up `db-roles.env` and
`postgres.env` in a password manager: the dashboard service needs the role passwords later.

## Step 7: Install the egress firewall

Do this before any container exists. The honeypot container may open connections only to
PostgreSQL. Everything else outbound is blocked, for IPv4 and IPv6. See "Egress control" below
for how it works.

Install the script as a root-owned copy. The firewall then never runs a file that the deploy
user (or a later `git pull`) could change:

```bash
sudo install -o root -g root -m 0755 /opt/honeypot/scripts/egress-firewall.sh /usr/local/sbin/honeypot-egress-firewall
```

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
sudo systemctl status honeypot-egress.service docker.service --no-pager
sudo /usr/local/sbin/honeypot-egress-firewall status
```

`reenable` creates the link `docker.service.requires/honeypot-egress.service`, so Docker
requires this unit. It also removes the `WantedBy=` link if an earlier version of this unit was
enabled. `Before=` makes systemd finish this unit before it starts Docker. Restarting Docker
once runs both in that order now, without waiting for a reboot. Restarting Docker also restarts
any running containers; there are none yet.

Expected: both units are `active`, and `status` lists a `HONEYPOT_EGRESS` chain for IPv4
(accept `RELATED,ESTABLISHED`, then `DROP`) and for IPv6 (a single `DROP`). If the unit fails,
Docker does not start; see "When Docker does not start: diagnose" below.

## Step 8: Start PostgreSQL only

```bash
sudo docker compose up -d --wait postgres
sudo docker compose ps
sudo ss -ltn | grep -c ':5432 '
```

`--wait` returns when the container's health check (`pg_isready`) passes. `ps` shows `postgres`
as `healthy` with no host port: PostgreSQL has no `ports:` entry, so it is reachable only on
`db_net`. The `grep -c` count must be `0`: nothing on the host listens on 5432.

The first run pulls the `postgres:16` image and creates an empty `honeypot` database, with the
superuser `postgres` and the password from `postgres.env`.

## Step 9: Create the schema

`scripts/init-db.sh` applies `migrations/001_initial.sql` to the running postgres container. The
migration creates the tables, the `schema_owner` role (no login) and the three login roles
`honeypot_writer`, `dashboard_admin` and `dashboard_judge`, using the passwords in `db-roles.env`.

```bash
sudo bash /opt/honeypot/scripts/init-db.sh
```

Expected output, on success:

```
init-db: database is empty; applying 001_initial.sql
init-db: OK: migration applied: 5 tables, 4 roles; honeypot_writer, dashboard_admin and dashboard_judge can log in
init-db: next: sudo docker compose up -d --build
```

What the script does:

- **Refuses to run twice.** If the `public` schema already has any table, or any of the four
  roles exists, it prints `REFUSED`, changes nothing and exits with status 2. (To start over on a
  *test* host only, `sudo docker compose down -v` deletes the database volume. Never run it on a
  host with real data.)
- **Applies the migration in one transaction.** If it fails, nothing is applied.
- **Checks the result:** five tables, four roles, and each login role connects with its password.

How the passwords reach psql without ever being on a command line, and how that works with sudo:

1. **sudo does not pass your variables.** By default sudo resets the environment (`env_reset`),
   so a password exported in your own shell would not reach the script. Passing it as
   `sudo VAR=value script` would put it in the process list, your shell history and the sudo log.
   Neither is used.
2. **The script reads the file itself.** Run by sudo, it is root, and root can read
   `db-roles.env`. It refuses a file that is not owned by root with mode 600 or 400, or is a
   symbolic link. It parses the file instead of sourcing it: only the three expected
   `NAME=value` lines are accepted, and each value must be at least 16 URL-safe characters. Error
   messages name the line, never the value.
3. **Docker gets the names, not the values.** The script exports the three variables and runs
   `docker exec -e HONEYPOT_WRITER_PASSWORD -e DASHBOARD_ADMIN_PASSWORD -e DASHBOARD_JUDGE_PASSWORD ...`.
   With a name and no `=`, Docker copies the value from the script's environment into the
   container's `psql` process. The value is not an argument anywhere.
4. **psql reads them with `\getenv`.** A few lines piped to psql's standard input run
   `\getenv honeypot_writer_password HONEYPOT_WRITER_PASSWORD` (and the other two) before the
   migration, which expects those psql variables. The migration file is piped in too, because
   the repository is not mounted in the postgres container.
5. **Nothing secret is printed or logged.** psql runs quietly; the session turns off
   statement logging (`log_statement=none`, `log_min_error_statement=panic`), so a failing
   `CREATE ROLE` cannot write its password to the PostgreSQL log; and all of psql's output goes
   through a filter that replaces the three password values with `[redacted]`.

## Step 10: Start the full stack

```bash
sudo docker compose up -d --build
sudo docker compose ps
sudo docker compose logs --no-log-prefix --tail 20 honeypot
sudo /usr/local/sbin/honeypot-egress-firewall apply
sudo /usr/local/sbin/honeypot-egress-firewall status
```

The first `up` builds the honeypot image, which takes a few minutes. Both services must be
`running` (`postgres` also `healthy`), and the honeypot log must contain
`HONEYPOT LISTENING host=0.0.0.0 port=2222`. If it shows `CONFIG ERROR` or `DATABASE UNAVAILABLE`,
check `.env` (the database URL) and step 9.

`apply` now runs again with Docker up. This time it can check the Docker network: the subnet must
be `172.30.250.0/24` and the bridge name `honeypot0`. It must print `rules for ... already in
place` for IPv4 and IPv6 and change nothing. If it reports a mismatch, see "Requirements on the
host" below.

The honeypot is now listening on host port 22. The Cloud Firewall from step 2 still keeps the
internet away from it.

## Step 11: Verify egress

Run the checks in "Verify egress" below. **Every check must pass before you go live.**

## Step 12: Verify container privileges

Run the checks in "Verify the container's privileges" below. Every line must print `OK`.

## Step 13: Pre-launch state and going live

### Pre-launch: the honeypot is running and unreachable

Until you deliberately open it, the DigitalOcean Cloud Firewall from step 2 keeps **inbound port 22
closed** for the whole setup above. The honeypot already listens on host port 22, but the
Cloud Firewall drops traffic before it reaches the Droplet. So you can start the stack, run
every verification and test the honeypot yourself without exposing it to the internet.

From your own computer, check that the honeypot is still unreachable:

```bash
nc -vz -w 5 <droplet-ip> 22      # must time out
```

On the server, you can still try the honeypot through the loopback address, which the Cloud
Firewall does not filter. Show the demo login, then connect:

```bash
sudo grep -E '^HONEYPOT_DEMO_(USERNAME|PASSWORD)=' /opt/honeypot/.env
ssh -p 22 -o PubkeyAuthentication=no -o UserKnownHostsFile=/dev/null <demo-username>@127.0.0.1
```

`ssh` asks whether to trust the host key. Its `SHA256:` fingerprint must equal the one that
`sudo ssh-keygen -lf /etc/honeypot/ssh_host_key.pub` printed in step 5. Answer `yes`, enter the
demo password, look around, type `exit`. Then check that the session was recorded:

```bash
sudo docker compose exec -T postgres psql -U postgres -d honeypot -c 'SELECT count(*) AS sessions FROM sessions'
```

The count must be at least `1`.

### Going live

Going live is one change in the DigitalOcean control panel: add an **inbound rule to the Cloud
Firewall**: protocol `TCP`, port `22`, sources **All IPv4** and **All IPv6** (every address).
Keep the port `<admin-port>` rule restricted to your own IP. Only do this after steps 11 and 12 passed.

Then run the **external SSH check** from a computer outside the server's network (not the
server itself):

```bash
nc -vz -w 5 <droplet-ip> 22                     # must succeed now
ssh -p 22 -o PubkeyAuthentication=no <demo-username>@<droplet-ip>
```

The client must show a login prompt, accept the demo login and give a shell prompt, and show
the same host-key fingerprint as in step 5. The admin SSH port must still be limited to your IP:
`nc -vz -w 5 <droplet-ip> <admin-port>` must time out from any other address.

To go dark again, delete the port 22 rule from the Cloud Firewall. New connections stop
immediately; connections already open continue. To end them too:
`sudo docker compose stop honeypot`.

## Egress control (T9.6)

This section explains how the egress firewall works, and how to diagnose and operate it. The
install commands are in step 7, the checks in steps 11 and 12.

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
  and the rules have no effect. Verify egress check 1 below catches this.
- The `ip6tables` command must exist too. `apply` stops with an error if it is missing, so
  the unit fails and Docker does not start (fail closed).
- If you change the subnet or the bridge name in `docker-compose.yml`, change
  `HONEYPOT_NET_SUBNET` or `HONEYPOT_BRIDGE_IFACE` to match. The script refuses to run if the
  existing Docker network uses a different subnet or bridge name.
- **Upgrading a host that ran an earlier version:** its `honeypot_net` has a generated bridge
  name, so `apply` stops with `has bridge name '<generated>', not honeypot0`. Recreate the
  network: `sudo docker compose down && sudo docker compose up -d --build`, then run `apply` again.
  The IPv4 rules are unaffected by the name.

### Operating the script

The installed copy takes three actions:

```bash
sudo /usr/local/sbin/honeypot-egress-firewall apply     # add or repair the rules
sudo /usr/local/sbin/honeypot-egress-firewall status    # show the chains
sudo /usr/local/sbin/honeypot-egress-firewall remove    # delete the rules (restores open egress)
```

`apply` handles IPv4 and IPv6 together, and is idempotent: run it again and it reports
`IPv4: rules for -s 172.30.250.0/24 already in place` and `IPv6: rules for -i honeypot0 already
in place`, and changes nothing. If someone edits a chain, the next `apply` rebuilds it before
re-adding the jump rules. A jump rule that matches something else (for example after you
set `HONEYPOT_NET_SUBNET6`) is replaced. `remove` deletes the IPv4 and IPv6 rules and chains and
restores unrestricted egress. If any step of `apply` fails, it exits non-zero.

### Why it fails closed

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
sudo journalctl -b -o short-monotonic -u honeypot-egress.service -u docker.service | head -n 5
```

The `honeypot-egress` lines must come before Docker's first line.

### When Docker does not start: diagnose

Symptoms: after a reboot or a `systemctl start docker`, the honeypot does not answer, and
`docker` commands fail with `Cannot connect to the Docker daemon`. `systemctl start docker`
prints `A dependency job for docker.service failed`.

1. Check both units:

   ```bash
   sudo systemctl status honeypot-egress.service docker.service --no-pager
   ```

   If the firewall caused it, `honeypot-egress.service` is `failed (Result: exit-code)` and
   `docker.service` is `inactive (dead)`. Docker is not `failed`, so `systemctl --failed` lists
   only `honeypot-egress.service`. The last lines of the status output show the script's error.

2. Read this boot's log for both units, in order:

   ```bash
   sudo journalctl -b -u honeypot-egress.service -u docker.service --no-pager
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
   sudo systemctl is-active honeypot-egress.service docker.service   # both must print "active"
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

## Verify egress (required after every deployment and every reboot)

Run each check from `/opt/honeypot`, inside the running honeypot container. The image has no shell tools, so
the checks use its Python.

**1. A TCP connection to 1.1.1.1:443 must fail.**

```bash
sudo docker compose exec -T honeypot python - <<'EOF'
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
sudo docker compose exec -T honeypot python - <<'EOF'
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
sudo docker compose exec -T honeypot python - <<'EOF'
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
sudo docker compose exec -T honeypot python - <<'EOF'
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
sudo docker compose exec -T honeypot python - <<'EOF'
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
check that `sudo docker network inspect haunted-house-honeypot_honeypot_net` shows subnet
`172.30.250.0/24`, and keep the honeypot stopped (`sudo docker compose stop honeypot`) until every
check passes.

## Verify the container's privileges (required after every deployment)

The egress rules assume the honeypot container cannot reach the host or change the network. These
checks read the settings Docker applied to the running container. Run them on the host, from the
repository checkout, after `docker compose up -d`. Each line must start with `OK`.

First, the compose file. This must print nothing: none of these keys appear in the resolved
configuration (a `grep` match would show the key and its line number).
```bash
sudo docker compose config | grep -nE 'privileged|network_mode|pid:|ipc:|docker\.sock|enable_ipv6'
```
Then the running container:
```bash
C=$(sudo docker compose ps -q honeypot)
[ -n "$C" ] || { echo "FAIL: honeypot container is not running"; exit 1; }
insp() { sudo docker inspect -f "$1" "$C"; }
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
  eq "network $n: IPv6 disabled" "$(sudo docker network inspect -f '{{.EnableIPv6}}' "$n")" false
  # An empty address prints as "" or "invalid IP", depending on the Docker version.
  eq "container has no IPv6 address on $n" \
    "$(insp "{{(index .NetworkSettings.Networks \"$n\").GlobalIPv6Address}}" | sed 's/^invalid IP$//')" ""
done
```
If a line prints `FAIL`, stop the honeypot (`sudo docker compose stop honeypot`), fix the setting in
`docker-compose.yml`, recreate the container (`sudo docker compose up -d --force-recreate honeypot`) and
run the checks again. `sudo docker compose up -d` does not recreate a container whose configuration
did not change, so a changed setting is not applied until the container is recreated.