#!/usr/bin/env bash
# egress-firewall.sh: block outbound connections from the honeypot container (T9.6).
#
# The honeypot may reach only PostgreSQL, over db_net (an internal Docker network, so
# its traffic never leaves Docker and is not affected by these rules). honeypot_net is
# a normal bridge, needed only for the published SSH port. This script drops every NEW
# connection that starts inside honeypot_net's fixed subnet, so the container has no
# route out to the internet, the LAN, or the host. Replies to inbound SSH connections
# are ESTABLISHED and stay allowed.
#
# How it works: traffic from the subnet is sent to a private chain, HONEYPOT_EGRESS,
# that allows replies and drops everything else:
#
#   DOCKER-USER:      -s <subnet> -j HONEYPOT_EGRESS   traffic routed off the host
#   INPUT:            -s <subnet> -j HONEYPOT_EGRESS   traffic to the host's own addresses
#   HONEYPOT_EGRESS:  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
#                     -j DROP
#
# DOCKER-USER is the chain Docker evaluates before its own FORWARD rules and never
# rewrites. It does not see connections from the container to the host itself (for
# example the admin sshd on its new port, or anything bound to 0.0.0.0 on the host),
# which go through INPUT instead, so the same chain is also hooked into INPUT.
#
# Usage (as root, on the Linux Docker host):
#   bash scripts/egress-firewall.sh [apply|remove|status]     default: apply
#   bash scripts/egress-firewall.sh apply --before-docker      used by the systemd unit
#
# apply is idempotent. Running it again changes nothing when the rules are already
# right, and repairs the chain if it was edited. The jump rules are added only after
# the chain is complete, so the container is never briefly unprotected during an update.
#
# Boot order: the systemd unit in docs/deployment.md runs "apply --before-docker"
# before docker.service starts. If DOCKER-USER does not exist yet, apply creates it.
# Docker keeps an existing DOCKER-USER chain and its rules, and adds its FORWARD jump
# to it at startup, so the rules are in place before any container starts.
# --before-docker skips the Docker network cross-check. That check runs the docker
# CLI, which at boot would start docker.service through docker.socket while
# docker.service waits for this unit: a deadlock.
#
# Environment:
#   HONEYPOT_NET_SUBNET   IPv4 subnet of honeypot_net. Must equal the subnet in
#                         docker-compose.yml. Default 172.30.250.0/24.
#   HONEYPOT_NET_NAME     Docker network name, used only to cross-check the subnet.
#                         Default haunted-house-honeypot_honeypot_net.
#
# To change the subnet on a running host: run "remove", edit docker-compose.yml and
# the variable, recreate the network (docker compose down; docker compose up -d), then
# run "apply".
#
# Not covered: IPv6 (the compose file does not enable it on honeypot_net). DNS is
# handled in docker-compose.yml, not here: Docker's embedded resolver forwards lookups
# on the container's behalf, so the honeypot service sets an unroutable upstream DNS
# server. See docs/deployment.md.

set -euo pipefail

SUBNET="${HONEYPOT_NET_SUBNET:-172.30.250.0/24}"
NETWORK="${HONEYPOT_NET_NAME:-haunted-house-honeypot_honeypot_net}"
CHAIN="HONEYPOT_EGRESS"
# Chains that jump to $CHAIN for traffic from the subnet.
PARENTS=("DOCKER-USER" "INPUT")

log() { printf 'egress-firewall: %s\n' "$*"; }
die() { printf 'egress-firewall: ERROR: %s\n' "$*" >&2; exit 1; }

# -w waits for the xtables lock, which Docker also takes.
ipt() { iptables -w "$@"; }

validate_subnet() {
  local re='^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/([0-9]{1,2})$'
  [[ "$SUBNET" =~ $re ]] || die "HONEYPOT_NET_SUBNET must look like 172.30.250.0/24, got '$SUBNET'"
  local octet
  for octet in "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}"; do
    (( 10#$octet <= 255 )) || die "invalid address in HONEYPOT_NET_SUBNET: '$SUBNET'"
  done
  # A very short prefix would match most of the internet and cut off every container.
  (( 10#${BASH_REMATCH[5]} >= 16 && 10#${BASH_REMATCH[5]} <= 30 )) \
    || die "HONEYPOT_NET_SUBNET prefix length must be between 16 and 30, got '$SUBNET'"
}

check_docker_network_subnet() {
  # If the network already exists, its real subnet must match the one we are about to
  # filter. A mismatch would leave the container unfiltered while looking protected.
  command -v docker >/dev/null 2>&1 || return 0
  local actual
  actual="$(docker network inspect "$NETWORK" --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null)" \
    || { log "note: Docker network '$NETWORK' does not exist yet; skipping the subnet cross-check"; return 0; }
  local s
  for s in $actual; do
    if [ "$s" = "$SUBNET" ]; then
      return 0
    fi
  done
  die "Docker network '$NETWORK' uses subnet(s) '${actual% }', not $SUBNET. Fix docker-compose.yml or HONEYPOT_NET_SUBNET."
}

chain_exists() { ipt -n -L "$CHAIN" >/dev/null 2>&1; }

chain_is_correct() {
  # Exactly two rules, the ACCEPT first and the DROP last.
  local rules
  rules="$(ipt -S "$CHAIN")" || return 1
  [ "$(printf '%s\n' "$rules" | wc -l)" -eq 3 ] || return 1
  ipt -C "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || return 1
  ipt -C "$CHAIN" -j DROP 2>/dev/null || return 1
  [[ "$(printf '%s\n' "$rules" | sed -n 2p)" == *"-j ACCEPT" ]]
}

apply() {
  local before_docker="$1"
  validate_subnet
  if ! ipt -n -L DOCKER-USER >/dev/null 2>&1; then
    # Docker not started yet (boot), or not installed. Docker keeps this chain when it
    # starts and adds its own FORWARD jump to it.
    ipt -N DOCKER-USER
    log "created chain DOCKER-USER (Docker will hook it into FORWARD when it starts)"
  fi
  if [ "$before_docker" -eq 1 ]; then
    log "--before-docker: skipping the Docker network subnet cross-check"
  else
    check_docker_network_subnet
  fi

  if ! chain_exists; then
    ipt -N "$CHAIN"
  fi
  if ! chain_is_correct; then
    ipt -F "$CHAIN"
    ipt -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ipt -A "$CHAIN" -j DROP
    log "chain $CHAIN (re)built"
  fi

  # Insert at position 1: Docker leaves a final "-j RETURN" in DOCKER-USER, and rules
  # after it are never reached. In INPUT, position 1 puts it ahead of ufw or other
  # host firewall rules that might accept the traffic first.
  local parent added=0
  for parent in "${PARENTS[@]}"; do
    if ! ipt -C "$parent" -s "$SUBNET" -j "$CHAIN" 2>/dev/null; then
      ipt -I "$parent" 1 -s "$SUBNET" -j "$CHAIN"
      added=1
    fi
  done
  if [ "$added" -eq 1 ]; then
    log "traffic from $SUBNET now goes through $CHAIN: replies allowed, new connections dropped"
  else
    log "rules for $SUBNET already in place"
  fi
}

remove() {
  # Delete every jump to our chain, whatever subnet it names, then the chain itself.
  local parent jumps rule
  for parent in "${PARENTS[@]}"; do
    mapfile -t jumps < <(ipt -S "$parent" 2>/dev/null | grep -- " -j ${CHAIN}\$" || true)
    for rule in "${jumps[@]}"; do
      [ -n "$rule" ] || continue
      # shellcheck disable=SC2086  # word splitting of the saved rule is intended
      ipt ${rule/#-A /-D }
    done
  done
  if chain_exists; then
    ipt -F "$CHAIN"
    ipt -X "$CHAIN"
  fi
  log "removed: the honeypot container has unrestricted egress again"
}

status() {
  local parent
  for parent in "${PARENTS[@]}"; do
    ipt -n -v -L "$parent" --line-numbers
  done
  if chain_exists; then
    ipt -n -v -L "$CHAIN" --line-numbers
  else
    log "chain $CHAIN does not exist"
  fi
}

main() {
  local action="${1:-apply}"
  local before_docker=0
  if [ "$#" -gt 1 ]; then
    if [ "$#" -ne 2 ] || [ "$action" != "apply" ] || [ "$2" != "--before-docker" ]; then
      die "unexpected arguments. Usage: egress-firewall.sh [apply [--before-docker]|remove|status]"
    fi
    before_docker=1
  fi
  command -v iptables >/dev/null 2>&1 || die "iptables not found"
  [ "$(id -u)" -eq 0 ] || die "run as root (for example: sudo bash scripts/egress-firewall.sh)"
  case "$action" in
    apply) apply "$before_docker" ;;
    remove) remove ;;
    status) status ;;
    *) die "unknown action '$action'. Use apply, remove or status." ;;
  esac
}

main "$@"
