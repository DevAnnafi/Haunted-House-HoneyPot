#!/usr/bin/env bash
# init-db.sh: apply migrations/001_initial.sql to the running postgres container.
#
# Run once, on the Linux deployment host, after "docker compose up -d --wait postgres" and
# before the honeypot starts (docs/deployment.md):
#
#   sudo bash /opt/honeypot/scripts/init-db.sh
#
# What it does
#   1. Reads the three role passwords from db-roles.env (see below).
#   2. Refuses to continue if the database already has tables or any of the four roles.
#   3. Runs the migration as the PostgreSQL superuser inside the container, over the
#      container's local socket. The superuser password is not needed or used.
#   4. Checks that the five tables and four roles exist and that each login role can log
#      in with its password.
#
# How the passwords travel (they are never on a command line)
#   * The script runs as root through sudo. sudo resets the environment (env_reset), so a
#     variable exported in the admin's shell would not arrive. Passing them as
#     "sudo VAR=value ..." would put them in the process list, the shell history and the
#     sudo log. So the script reads them itself, from <repo>/db-roles.env, a file that only
#     root can read. It refuses to run if that file is not owned by root with mode 600 or 400.
#   * The file is parsed, not sourced: only the three expected NAME=value lines are accepted,
#     and each value must be at least 16 characters from A-Z a-z 0-9 . _ ~ - (safe in a URL).
#   * The script exports them. "docker exec -e NAME" (name only, no value) hands the
#     container's psql the value from the script's environment, so docker never sees the
#     value as an argument.
#   * Inside the container, a short script piped to psql's standard input runs
#     "\getenv honeypot_writer_password HONEYPOT_WRITER_PASSWORD" (and the other two), then
#     the migration, which reads those psql variables. The migration is piped in too,
#     because the postgres container does not have the repository mounted.
#
# Nothing secret is written to output
#   * psql runs with -q and no echo, and the server is told not to log statements
#     (log_statement=none, log_min_error_statement=panic) for this session, so a failing
#     CREATE ROLE cannot put its password in the server log.
#   * As a last guard, all of psql's output passes through a filter that replaces the three
#     password values with [redacted].
#
# Exit codes: 0 applied, 1 error, 2 refused because the database is already migrated.
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROLES_FILE="${ROOT}/db-roles.env"
MIGRATION="${ROOT}/migrations/001_initial.sql"
SERVICE="postgres"
SUPERUSER="postgres"
DATABASE="honeypot"
ROLES=(schema_owner honeypot_writer dashboard_admin dashboard_judge)
# Login roles and the variable holding each one's password.
LOGIN_ROLES=(honeypot_writer:HONEYPOT_WRITER_PASSWORD
  dashboard_admin:DASHBOARD_ADMIN_PASSWORD
  dashboard_judge:DASHBOARD_JUDGE_PASSWORD)
log() { printf 'init-db: %s\n' "$*"; }
die() { printf 'init-db: ERROR: %s\n' "$*" >&2; exit 1; }
# Error messages never include a value from db-roles.env, only the line number or name.
load_roles() {
  [ -e "$ROLES_FILE" ] || die "$ROLES_FILE not found. Create it as described in docs/deployment.md."
  [ ! -L "$ROLES_FILE" ] || die "$ROLES_FILE is a symbolic link; refusing to read it."
  [ -f "$ROLES_FILE" ] || die "$ROLES_FILE is not a regular file."
  # Start from nothing, so a variable left in the caller's environment is never used.
  unset HONEYPOT_WRITER_PASSWORD DASHBOARD_ADMIN_PASSWORD DASHBOARD_JUDGE_PASSWORD
  local owner mode
  read -r owner mode < <(stat -c '%u %a' "$ROLES_FILE")
  [ "$owner" = "0" ] || die "$ROLES_FILE must be owned by root (owner uid is $owner)."
  { [ "$mode" = "600" ] || [ "$mode" = "400" ]; } \
    || die "$ROLES_FILE must have mode 600 or 400 (it has $mode). Fix: sudo chmod 600 $ROLES_FILE"
  local line key value n=0
  local -A seen=()
  local re='^[A-Za-z0-9._~-]{16,}$'
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    [ -n "$line" ] || continue
    [[ "$line" != \#* ]] || continue
    [[ "$line" == *=* ]] || die "$ROLES_FILE line $n: expected NAME=value."
    key="${line%%=*}"
    value="${line#*=}"
    case "$key" in
      HONEYPOT_WRITER_PASSWORD | DASHBOARD_ADMIN_PASSWORD | DASHBOARD_JUDGE_PASSWORD) ;;
      *) die "$ROLES_FILE line $n: unexpected name '$key'." ;;
    esac
    [[ "$value" =~ $re ]] \
      || die "$ROLES_FILE line $n: $key must be at least 16 characters from A-Z a-z 0-9 . _ ~ - (no quotes, spaces or line-ending characters)."
    [ -z "${seen[$key]:-}" ] || die "$ROLES_FILE line $n: $key is set twice."
    seen[$key]=1
    export "$key=$value"
  done < "$ROLES_FILE"
  local pair var
  for pair in "${LOGIN_ROLES[@]}"; do
    var="${pair#*:}"
    [ -n "${!var:-}" ] || die "$ROLES_FILE does not set $var."
  done
}
redact() {
  # Replace each password value with [redacted]. The values come from the environment,
  # never from the command line.
  awk '
    BEGIN {
      n = split("HONEYPOT_WRITER_PASSWORD DASHBOARD_ADMIN_PASSWORD DASHBOARD_JUDGE_PASSWORD", names, " ")
      for (i = 1; i <= n; i++) secret[i] = ENVIRON[names[i]]
    }
    {
      for (i = 1; i <= n; i++) {
        s = secret[i]
        if (s == "") continue
        while ((p = index($0, s)) > 0)
          $0 = substr($0, 1, p - 1) "[redacted]" substr($0, p + length(s))
      }
      print
    }'
}
# Run psql in the container with no password variables.
psql_plain() {
  docker exec "$CID" psql -X -q -A -t -v ON_ERROR_STOP=1 -U "$SUPERUSER" -d "$DATABASE" "$@"
}
main() {
  [ "$(id -u)" -eq 0 ] || die "run as root: sudo bash scripts/init-db.sh"
  command -v docker >/dev/null 2>&1 || die "docker not found"
  command -v awk >/dev/null 2>&1 || die "awk not found"
  [ -f "$MIGRATION" ] || die "migration not found: $MIGRATION"
  load_roles
  cd "$ROOT"
  CID="$(docker compose ps -q "$SERVICE" 2>/dev/null || true)"
  [ -n "$CID" ] || die "the $SERVICE container is not running. Start it: sudo docker compose up -d --wait $SERVICE"
  [ "$(docker inspect -f '{{.State.Running}}' "$CID")" = "true" ] \
    || die "the $SERVICE container is not running. Start it: sudo docker compose up -d --wait $SERVICE"
  docker exec "$CID" pg_isready -q -U "$SUPERUSER" -d "$DATABASE" \
    || die "PostgreSQL is not accepting connections yet. Wait a few seconds and run this again."
  # Refuse to touch a database that already has anything of ours in it.
  local role_list existing
  role_list="'$(IFS=,; printf '%s' "${ROLES[*]}" | sed "s/,/','/g")'"
  existing="$(psql_plain -c "SELECT (SELECT count(*) FROM pg_tables WHERE schemaname = 'public') + (SELECT count(*) FROM pg_roles WHERE rolname IN ($role_list))")" \
    || die "could not query the database"
  [[ "$existing" =~ ^[0-9]+$ ]] || die "unexpected answer from the database"
  if [ "$existing" -ne 0 ]; then
    printf 'init-db: REFUSED: database "%s" already has tables in the public schema or one of the roles (%s).\n' \
      "$DATABASE" "${ROLES[*]}" >&2
    printf 'init-db: It looks migrated already. Nothing was changed. To start over on a test host, remove the volume (this deletes all data): sudo docker compose down -v\n' >&2
    exit 2
  fi
  log "database is empty; applying $(basename "$MIGRATION")"
  local status=0
  {
    printf '%s\n' '\set ON_ERROR_STOP on'
    printf '%s\n' '\getenv honeypot_writer_password HONEYPOT_WRITER_PASSWORD'
    printf '%s\n' '\getenv dashboard_admin_password DASHBOARD_ADMIN_PASSWORD'
    printf '%s\n' '\getenv dashboard_judge_password DASHBOARD_JUDGE_PASSWORD'
    cat "$MIGRATION"
  } | docker exec -i \
    -e HONEYPOT_WRITER_PASSWORD -e DASHBOARD_ADMIN_PASSWORD -e DASHBOARD_JUDGE_PASSWORD \
    -e "PGOPTIONS=-c log_statement=none -c log_min_error_statement=panic" \
    "$CID" psql -X -q -v ON_ERROR_STOP=1 -U "$SUPERUSER" -d "$DATABASE" 2>&1 \
    | redact || status=$?
  [ "$status" -eq 0 ] || die "the migration failed (exit status $status). It runs in one transaction, so nothing was applied."
  # Check the result.
  local tables roles
  tables="$(psql_plain -c "SELECT count(*) FROM pg_tables WHERE schemaname = 'public'")"
  roles="$(psql_plain -c "SELECT count(*) FROM pg_roles WHERE rolname IN ($role_list)")"
  [ "$tables" = "5" ] || die "expected 5 tables after the migration, found $tables"
  [ "$roles" = "4" ] || die "expected 4 roles after the migration, found $roles"
  # Each login role must accept its password. PGPASSWORD is passed by name only. The
  # connection goes to the container's own address, not the local socket, so the password
  # is really checked.
  local pair role var
  for pair in "${LOGIN_ROLES[@]}"; do
    role="${pair%%:*}"
    var="${pair#*:}"
    PGPASSWORD="${!var}" docker exec -e PGPASSWORD "$CID" \
      psql -X -q -A -t -h "$SERVICE" -U "$role" -d "$DATABASE" -c 'SELECT 1' >/dev/null 2>&1 \
      || die "role $role could not log in with the password from db-roles.env"
  done
  log "OK: migration applied: $tables tables, $roles roles; honeypot_writer, dashboard_admin and dashboard_judge can log in"
  log "next: sudo docker compose up -d --build"
}
main "$@"
