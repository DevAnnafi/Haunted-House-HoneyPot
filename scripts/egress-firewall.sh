#!/usr/bin/env bash
# egress-firewall.sh: block outbound connections from the honeypot container (T9.6).
#
# The honeypot may reach only PostgreSQL, over db_net (an internal Docker network, so
# its traffic never leaves Docker and is not affected by these rules). honeypot_net is
# a normal bridge, needed only for the published SSH port. This script drops every NEW
# connection that starts inside honeypot_net, so the container has no route out to the
# internet, the LAN, or the host. Replies to inbound SSH connections are ESTABLISHED
# and stay allowed.
#
# How it works: traffic from the network is sent to a private chain, HONEYPOT_EGRESS,
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
# IPv6: the same structure is built with ip6tables (a HONEYPOT_EGRESS chain in the ip6
# tables, jumped to from DOCKER-USER and INPUT). The compose file does not enable IPv6 on
# honeypot_net, so normally no IPv6 packet should ever come from the container. These
# rules make sure that stays true. Which packets they match depends on the network:
#
#   IPv6 subnet known   (the Docker network has one, or HONEYPOT_NET_SUBNET6 is set):
#       same as IPv4: jumps match "-s <subnet6>"; the chain accepts ESTABLISHED,RELATED
#       and drops the rest.
#   no IPv6 subnet      (the normal case):
#       jumps match "-i <bridge>", the honeypot's bridge interface, and the chain is a
#       single DROP. Every IPv6 packet that enters the host from that bridge is dropped,
#       replies included, because no IPv6 connection to the container can exist.
#
# The bridge name must be fixed, because at boot the network does not exist yet and the
# script cannot ask Docker for it. docker-compose.yml sets it with the driver option
# com.docker.network.bridge.name (default honeypot0, see HONEYPOT_BRIDGE_IFACE).
#
# Usage (as root, on the Linux Docker host):
#   bash scripts/egress-firewall.sh [apply|remove|status]     default: apply
#   bash scripts/egress-firewall.sh apply --before-docker      used by the systemd unit
#
# apply is idempotent. Running it again changes nothing when the rules are already
# right, and repairs a chain that was edited. A jump rule that matches something other
# than what is wanted now (for example after the mode above changed) is replaced; the new
# jump is added before the old one is deleted, so there is no gap. apply works on IPv4 and
# IPv6 together and checks its settings first, so a bad setting changes nothing. If either
# family fails, apply exits non-zero. remove deletes both families' rules and chains.
#
# Fail closed: apply needs both iptables and ip6tables and stops with an error if either
# is missing or any rule can not be added. At boot, the systemd unit then fails and Docker
# does not start (docs/deployment.md).
#
# Boot order: the systemd unit in docs/deployment.md runs "apply --before-docker"
# before docker.service starts. If DOCKER-USER does not exist yet, apply creates it.
# Docker keeps an existing DOCKER-USER chain and its rules, and adds its FORWARD jump
# to it at startup, so the rules are in place before any container starts.
# --before-docker skips the Docker network cross-checks. They run the docker CLI,
# which at boot would start docker.service through docker.socket while docker.service
# waits for this unit: a deadlock. In that mode IPv6 uses the interface rule unless
# HONEYPOT_NET_SUBNET6 is set.
#
# Environment:
#   HONEYPOT_NET_SUBNET   IPv4 subnet of honeypot_net. Must equal the subnet in
#                         docker-compose.yml. Default 172.30.250.0/24.
#   HONEYPOT_NET_SUBNET6  IPv6 subnet of honeypot_net, only if you enabled IPv6 on it.
#                         Default: none (use the interface rule).
#   HONEYPOT_BRIDGE_IFACE Bridge interface of honeypot_net. Must equal
#                         com.docker.network.bridge.name in docker-compose.yml.
#                         Default honeypot0.
#   HONEYPOT_NET_NAME     Docker network name, used only to cross-check the settings.
#                         Default haunted-house-honeypot_honeypot_net.
#
# To change the subnet or bridge name on a running host: run "remove", edit
# docker-compose.yml and the variable, recreate the network (docker compose down;
# docker compose up -d), then run "apply".
#
# DNS is handled in docker-compose.yml, not here: Docker's embedded resolver forwards
# lookups on the container's behalf, so the honeypot service sets an unroutable upstream
# DNS server. See docs/deployment.md.
set -euo pipefail
SUBNET="${HONEYPOT_NET_SUBNET:-172.30.250.0/24}"
SUBNET6="${HONEYPOT_NET_SUBNET6:-}"
BRIDGE="${HONEYPOT_BRIDGE_IFACE:-honeypot0}"
NETWORK="${HONEYPOT_NET_NAME:-haunted-house-honeypot_honeypot_net}"
CHAIN="HONEYPOT_EGRESS"
# Chains that jump to $CHAIN for traffic from the honeypot network.
PARENTS=("DOCKER-USER" "INPUT")
# The family being worked on. use_v4 and use_v6 set these; everything below reads them.
IPT="iptables"       # command name
FAMILY="IPv4"        # label for messages
MATCH=()             # how the jump rules identify the honeypot's traffic
ALLOW_REPLIES=1      # 1: chain accepts ESTABLISHED,RELATED, then drops. 0: drops everything.
CHANGED=0
log() { printf 'egress-firewall: %s\n' "$*"; }
die() { printf 'egress-firewall: ERROR: %s\n' "$*" >&2; exit 1; }
# -w waits for the xtables lock, which Docker also takes.
ipt() { "$IPT" -w "$@"; }
use_v4() {
  IPT="iptables"
  FAMILY="IPv4"
  MATCH=(-s "$SUBNET")
  ALLOW_REPLIES=1
}
# MODE6 is "subnet" or "bridge", chosen by resolve_v6.
MODE6="bridge"
use_v6() {
  IPT="ip6tables"
  FAMILY="IPv6"
  if [ "$MODE6" = "subnet" ]; then
    MATCH=(-s "$SUBNET6")
    ALLOW_REPLIES=1
  else
    MATCH=(-i "$BRIDGE")
    ALLOW_REPLIES=0
  fi
}
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
validate_subnet6() {
  local value="$1" name="$2"
  local re='^[0-9A-Fa-f:]*:[0-9A-Fa-f:]*/([0-9]{1,3})$'
  [[ "$value" =~ $re ]] || die "$name must look like fd00:30:250::/64, got '$value'"
  (( 10#${BASH_REMATCH[1]} >= 48 && 10#${BASH_REMATCH[1]} <= 120 )) \
    || die "$name prefix length must be between 48 and 120, got '$value'"
}
validate_bridge() {
  # Linux interface names are at most 15 characters. No spaces, slashes or leading dash,
  # so the value can never be read as an iptables option.
  [[ "$BRIDGE" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}$ ]] \
    || die "HONEYPOT_BRIDGE_IFACE must be a valid interface name (max 15 characters), got '$BRIDGE'"
}
# inspect_network: print the network's settings, or return 1 if it does not exist or the
# docker CLI is not usable. Output: line 1 = bridge name option, line 2 = all subnets.
inspect_network() {
  command -v docker >/dev/null 2>&1 || return 1
  docker network inspect "$NETWORK" --format \
    '{{index .Options "com.docker.network.bridge.name"}}{{"\n"}}{{range .IPAM.Config}}{{.Subnet}} {{end}}' \
    2>/dev/null
}
check_docker_network() {
  # If the network already exists, its real subnet must match the one we are about to
  # filter. A mismatch would leave the container unfiltered while looking protected.
  local info
  info="$(inspect_network)" \
    || { log "note: Docker network '$NETWORK' does not exist yet; skipping the network cross-check"; return 0; }
  local actual
  actual="$(printf '%s\n' "$info" | sed -n 2p)"
  local s found=0
  for s in $actual; do
    if [ "$s" = "$SUBNET" ]; then
      found=1
    fi
  done
  [ "$found" -eq 1 ] \
    || die "Docker network '$NETWORK' uses subnet(s) '${actual% }', not $SUBNET. Fix docker-compose.yml or HONEYPOT_NET_SUBNET."
}
# resolve_v6: choose MODE6 and check the IPv6 settings. Changes nothing.
resolve_v6() {
  local before_docker="$1"
  validate_bridge
  if [ -n "$SUBNET6" ]; then
    validate_subnet6 "$SUBNET6" HONEYPOT_NET_SUBNET6
  fi
  if [ "$before_docker" -eq 0 ]; then
    local info
    if info="$(inspect_network)"; then
      local actual_bridge actual_subnets s v6=() found=0
      actual_bridge="$(printf '%s\n' "$info" | sed -n 1p)"
      actual_subnets="$(printf '%s\n' "$info" | sed -n 2p)"
      # The interface rule is only as good as the name. A network created without the
      # fixed name has a random br-xxxx name, and the rule would match nothing.
      [ "$actual_bridge" = "$BRIDGE" ] \
        || die "Docker network '$NETWORK' has bridge name '${actual_bridge:-<generated>}', not $BRIDGE. Set com.docker.network.bridge.name in docker-compose.yml and recreate the network (docker compose down; docker compose up -d)."
      for s in $actual_subnets; do
        if [[ "$s" == *:* ]]; then
          v6+=("$s")
          if [ "$s" = "$SUBNET6" ]; then
            found=1
          fi
        fi
      done
      if [ -z "$SUBNET6" ] && [ "${#v6[@]}" -eq 1 ]; then
        SUBNET6="${v6[0]}"
        validate_subnet6 "$SUBNET6" "the network's IPv6 subnet"
      elif [ -z "$SUBNET6" ] && [ "${#v6[@]}" -gt 1 ]; then
        die "Docker network '$NETWORK' has several IPv6 subnets (${v6[*]}). Set HONEYPOT_NET_SUBNET6 to the one in use, or remove the others."
      elif [ -n "$SUBNET6" ] && [ "$found" -eq 0 ]; then
        die "Docker network '$NETWORK' has IPv6 subnet(s) '${v6[*]:-none}', not $SUBNET6. Fix docker-compose.yml or HONEYPOT_NET_SUBNET6."
      fi
    fi
  fi
  if [ -n "$SUBNET6" ]; then
    MODE6="subnet"
  else
    MODE6="bridge"
  fi
}
chain_exists() { ipt -n -L "$CHAIN" >/dev/null 2>&1; }
chain_is_correct() {
  # The accept-replies chain has an ACCEPT first and a DROP last. The drop-all chain has
  # only the DROP. Either way, nothing else.
  local rules lines want_lines
  rules="$(ipt -S "$CHAIN")" || return 1
  lines="$(printf '%s\n' "$rules" | wc -l)"
  ipt -C "$CHAIN" -j DROP 2>/dev/null || return 1
  if [ "$ALLOW_REPLIES" -eq 1 ]; then
    want_lines=3
    [ "$lines" -eq "$want_lines" ] || return 1
    ipt -C "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || return 1
    [[ "$(printf '%s\n' "$rules" | sed -n 2p)" == *"-j ACCEPT" ]]
  else
    want_lines=2
    [ "$lines" -eq "$want_lines" ]
  fi
}
build_chain() {
  ipt -F "$CHAIN"
  if [ "$ALLOW_REPLIES" -eq 1 ]; then
    ipt -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  fi
  ipt -A "$CHAIN" -j DROP
}
# delete_rules: delete each saved rule ("-A CHAIN ...") given as an argument.
delete_rules() {
  local rule
  for rule in "$@"; do
    [ -n "$rule" ] || continue
    # shellcheck disable=SC2086  # word splitting of the saved rule is intended
    ipt ${rule/#-A /-D }
  done
}
saved_jumps() {
  # Every rule in $1 that jumps to our chain, whatever it matches.
  ipt -S "$1" | grep -- " -j ${CHAIN}\$" || true
}
sync_jump() {
  # Make $1 hold exactly one jump to our chain, with the wanted match. Insert at
  # position 1: Docker leaves a final "-j RETURN" in DOCKER-USER, and rules after it
  # are never reached. In INPUT, position 1 puts it ahead of ufw or other host firewall
  # rules that might accept the traffic first.
  local parent="$1" jumps
  mapfile -t jumps < <(saved_jumps "$parent")
  if ipt -C "$parent" "${MATCH[@]}" -j "$CHAIN" 2>/dev/null; then
    [ "${#jumps[@]}" -eq 1 ] && return 0
    # The wanted jump exists, but so do others. Clear them all and add it again.
    delete_rules "${jumps[@]}"
    ipt -I "$parent" 1 "${MATCH[@]}" -j "$CHAIN"
  else
    # Add the new jump first, then delete the stale ones, so there is no gap.
    ipt -I "$parent" 1 "${MATCH[@]}" -j "$CHAIN"
    delete_rules "${jumps[@]}"
  fi
  CHANGED=1
}
apply_family() {
  if ! ipt -n -L DOCKER-USER >/dev/null 2>&1; then
    # Docker not started yet (boot), or not installed. Docker keeps this chain when it
    # starts and adds its own FORWARD jump to it.
    ipt -N DOCKER-USER
    log "$FAMILY: created chain DOCKER-USER (Docker will hook it into FORWARD when it starts)"
  fi
  if ! chain_exists; then
    ipt -N "$CHAIN"
  fi
  # The chain is made complete before any jump points at it, so the container is never
  # briefly unprotected during an update.
  if ! chain_is_correct; then
    build_chain
    log "$FAMILY: chain $CHAIN (re)built"
  fi
  CHANGED=0
  local parent
  for parent in "${PARENTS[@]}"; do
    sync_jump "$parent"
  done
  if [ "$CHANGED" -eq 1 ]; then
    if [ "$ALLOW_REPLIES" -eq 1 ]; then
      log "$FAMILY: traffic matching ${MATCH[*]} now goes through $CHAIN: replies allowed, new connections dropped"
    else
      log "$FAMILY: traffic matching ${MATCH[*]} now goes through $CHAIN: all of it dropped"
    fi
  else
    log "$FAMILY: rules for ${MATCH[*]} already in place"
  fi
}
apply() {
  local before_docker="$1"
  command -v ip6tables >/dev/null 2>&1 || die "ip6tables not found"
  # Check every setting before changing any rule.
  validate_subnet
  resolve_v6 "$before_docker"
  if [ "$before_docker" -eq 1 ]; then
    log "--before-docker: skipping the Docker network cross-checks"
  else
    check_docker_network
  fi
  use_v4
  apply_family
  use_v6
  apply_family
}
remove_family() {
  # Delete every jump to our chain, whatever it matches, then the chain itself.
  local parent jumps
  for parent in "${PARENTS[@]}"; do
    # The parent may not exist (for example DOCKER-USER when Docker never ran).
    ipt -n -L "$parent" >/dev/null 2>&1 || continue
    mapfile -t jumps < <(saved_jumps "$parent")
    delete_rules "${jumps[@]}"
  done
  if chain_exists; then
    ipt -F "$CHAIN"
    ipt -X "$CHAIN"
  fi
  log "$FAMILY: removed"
}
remove() {
  use_v4
  remove_family
  if command -v ip6tables >/dev/null 2>&1; then
    use_v6
    remove_family
  else
    log "note: ip6tables not found, so there are no IPv6 rules to remove"
  fi
  log "removed: the honeypot container has unrestricted egress again"
}
status_family() {
  local parent
  log "$FAMILY:"
  for parent in "${PARENTS[@]}"; do
    ipt -n -v -L "$parent" --line-numbers
  done
  if chain_exists; then
    ipt -n -v -L "$CHAIN" --line-numbers
  else
    log "$FAMILY: chain $CHAIN does not exist"
  fi
}
status() {
  use_v4
  status_family
  if command -v ip6tables >/dev/null 2>&1; then
    use_v6
    status_family
  else
    log "note: ip6tables not found"
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
