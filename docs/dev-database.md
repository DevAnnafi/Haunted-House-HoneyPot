# Local development database

How to run PostgreSQL in Docker on a Windows development machine, apply the schema, and run
`tests/test_migration.py` against it. All commands are PowerShell, run from the repository
root.

This is for development only. The production `docker-compose.yml` publishes no database port
(ADR-0004). `docker-compose.dev.yml` adds a port bound to `127.0.0.1` so tools on your own
machine can connect. Never pass `docker-compose.dev.yml` on the production server.

## Quick start: `scripts/dev-db.ps1`

Do steps 1–3 below once (`postgres.env`, `.env`, `HONEYPOT_HOST_KEY_FILE`). Then one command
does steps 4, 6 and 7:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\dev-db.ps1          # first time
powershell -ExecutionPolicy Bypass -File scripts\dev-db.ps1 -Reset   # start over
```

(`-ExecutionPolicy Bypass` applies to this one run only. If your policy already allows local
scripts, `.\scripts\dev-db.ps1` works too.)

The script:
1. **Starts Postgres:** only the `postgres` service, with both Compose files, and waits for
   its health check. It stops if the port is not bound to `127.0.0.1`.
2. **Applies the migration:** it generates new random passwords for `honeypot_writer`,
   `dashboard_admin` and `dashboard_judge`, and applies `migrations/001_initial.sql` inside
   the container.
3. **Writes the URL:** it sets `HONEYPOT_DATABASE_URL` in `.env` to
   `postgresql://honeypot_writer:<password>@127.0.0.1:<port>/honeypot`, using the port
   Compose actually published. It replaces any existing `HONEYPOT_DATABASE_URL` line and keeps
   every other line.
4. **Verifies:** it checks the four roles and five tables (as in step 7), a password login as
   `honeypot_writer`, and that the port answers from Windows. Then it prints the roles and
   tables.

`-Reset` runs `docker compose down -v` first. That deletes the dev database and all its data.

What to expect:
- **Errors:** it stops at the first failure with a `dev-db: ERROR:` line that names the cause
  and the step of this guide that fixes it, and exits with code 1.
- **Already migrated:** without `-Reset`, a second run stops with "the database is already
  migrated", because `001_initial.sql` runs only once. It does not change `.env` in that case.
- **Passwords:** they are never printed and never appear on a command line. They reach `psql`
  through environment variables, and the script clears those variables when it finishes.
  `.env` is the only place the `honeypot_writer` password is stored. The script refuses to
  write it if git does not ignore `.env`.
- **Dashboard passwords:** the `dashboard_admin` and `dashboard_judge` passwords are not saved.
  Set new ones with `ALTER ROLE ... PASSWORD` when the dashboard needs them.
- **Port setting:** if `DEV_POSTGRES_PORT` is set but Postgres is published on a different
  port, the script prints a warning and uses the real port.
- **Migration tests:** `tests/test_migration.py` needs a database that has not been migrated
  yet (see step 5). Run those tests before the script. Or empty the database with the
  commands under "Reset", run the tests, then run the script again.

The manual steps below do the same thing one command at a time.

## Prerequisites

- Docker Desktop with Compose v2 (`docker compose version`).
- The `psql` client on `PATH`, for `tests/test_migration.py` only. If PostgreSQL is installed
  but `psql` is not found, add its folder for the current session (adjust the version):

  ```powershell
  $env:Path += ";C:\Program Files\PostgreSQL\18\bin"
  psql --version
  ```

- A free host port. The override publishes `127.0.0.1:15432` by default, not PostgreSQL's
  usual 5432. On Windows, Hyper-V (used by Docker Desktop and WSL 2) reserves blocks of TCP
  ports in its excluded port ranges, and on this project's development machine that has
  included 5432. Docker cannot publish a reserved port. A locally installed PostgreSQL may
  also listen on 5432. The ranges are chosen at boot, so a port that works today can be
  reserved after a restart. To see the current ranges:

  ```powershell
  netsh interface ipv4 show excludedportrange protocol=tcp
  ```

  If 15432 is taken or reserved, set `DEV_POSTGRES_PORT` in step 3. The address stays
  `127.0.0.1`. The commands below read the port from Compose, so they need no change.

## 1. Create `postgres.env`

`postgres.env` holds the PostgreSQL superuser password. It is gitignored (`*.env`).

```powershell
Copy-Item postgres.env.example postgres.env
$pgpw = python -c "import secrets; print(secrets.token_urlsafe(32))"
(Get-Content postgres.env) -replace '^POSTGRES_PASSWORD=.*', "POSTGRES_PASSWORD=$pgpw" |
    Set-Content postgres.env -Encoding ascii
```

The generated password uses only letters, digits, `-` and `_`, so it is safe inside a
connection URL.

## 2. Create `.env` if it does not exist

Compose reads the honeypot service's `env_file: .env` while loading the file, even when only
Postgres starts, so the file must exist.

```powershell
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
```

## 3. Set `HONEYPOT_HOST_KEY_FILE` in `.env`

Compose requires it even when only Postgres starts. `docker-compose.yml` uses
`${HONEYPOT_HOST_KEY_FILE:?...}`, and Compose interpolates every service before it selects
which to start. Without it, every `docker compose` command fails with "required variable
HONEYPOT_HOST_KEY_FILE is missing a value". The value is a path only for the honeypot
service's bind mount. When only Postgres runs, the path does not have to exist, so a
placeholder is fine.

```powershell
if (-not (Select-String -Path .env -Pattern '^HONEYPOT_HOST_KEY_FILE=' -Quiet)) {
    Add-Content -Path .env -Value "`nHONEYPOT_HOST_KEY_FILE=/etc/honeypot/ssh_host_key"
}
```

Only if port 15432 is taken or reserved on your machine (see Prerequisites), also pick another
port, outside every range that `netsh` lists:

```powershell
Add-Content -Path .env -Value "DEV_POSTGRES_PORT=25432"
```

## 4. Start only Postgres

Both Compose files are passed on every command. `$dc` keeps them in one place for this
PowerShell session (open a new session and you must set it again).

```powershell
$dc = @('-f', 'docker-compose.yml', '-f', 'docker-compose.dev.yml')
docker compose @dc up -d --wait postgres
```

That expands to
`docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --wait postgres`. Naming
the `postgres` service means the honeypot image is not built or started. `--wait` returns once
the health check passes.

Check that it is published on loopback only:

```powershell
docker compose @dc ps
docker compose @dc port postgres 5432
```

`port` must print `127.0.0.1:<port>`, never `0.0.0.0`.

## 5. Run `tests/test_migration.py` (before applying the migration)

Run the tests while the database is still fresh. The tests create their own scratch database
and apply the migration there. The migration creates cluster-wide roles, so the test module
refuses to run if `honeypot_writer`, `dashboard_admin`, `dashboard_judge` or `schema_owner`
already exist. It fails with "roles already exist on this server". Applying the migration
(step 6) creates those roles, so after step 6 the tests fail until you reset the database
(see "Reset"). The tests drop the roles again when they finish, so the database is still fresh
afterwards.

The URL must use the superuser, as these tests create databases and roles. Use `127.0.0.1`
and not `localhost`, because the port is published on IPv4 only.

```powershell
$pgpw = (Select-String -Path postgres.env -Pattern '^POSTGRES_PASSWORD=(.*)$').Matches[0].Groups[1].Value
$port = (docker compose @dc port postgres 5432) -split ':' | Select-Object -Last 1
$env:DATABASE_URL = "postgresql://postgres:$pgpw@127.0.0.1:$port/honeypot"
pytest tests/test_migration.py -v
```

Without `DATABASE_URL` these tests are skipped. `DATABASE_URL` lasts only for the current
session. The same URL points at the dev database for any other tool.

## 6. Apply `migrations/001_initial.sql`

Run the migration once per database. It creates the roles and tables. The role passwords go
in as `psql -v` variables, the same way `tests/test_migration.py` and the header of
`001_initial.sql` do it. They are not written into the SQL.

Generate three passwords for this session. Save them somewhere private (a password manager or
a gitignored `*.env` file) if you will connect as these roles later.

```powershell
$env:HONEYPOT_WRITER_PASSWORD = python -c "import secrets; print(secrets.token_urlsafe(24))"
$env:DASHBOARD_ADMIN_PASSWORD = python -c "import secrets; print(secrets.token_urlsafe(24))"
$env:DASHBOARD_JUDGE_PASSWORD = python -c "import secrets; print(secrets.token_urlsafe(24))"
```

Pipe the file into `psql` inside the container (`-T` turns off the terminal so stdin works).
The first line makes Windows PowerShell send UTF-8, because the SQL file has non-ASCII
characters in its comments.

```powershell
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)
Get-Content migrations\001_initial.sql -Raw -Encoding utf8 |
    docker compose @dc exec -T postgres psql -U postgres -d honeypot --no-psqlrc `
        -v ON_ERROR_STOP=1 `
        -v "honeypot_writer_password=$env:HONEYPOT_WRITER_PASSWORD" `
        -v "dashboard_admin_password=$env:DASHBOARD_ADMIN_PASSWORD" `
        -v "dashboard_judge_password=$env:DASHBOARD_JUDGE_PASSWORD" `
        -f -
```

The output ends with `COMMIT`. If a password variable is missing or empty, the script prints
`ERROR: ...` and stops before changing anything. The values appear in the container's process
list while `psql` runs, which is acceptable for a throwaway development database and not for
production.

## 7. Verify the roles and tables

```powershell
docker compose @dc exec -T postgres psql -U postgres -d honeypot --no-psqlrc `
    -c "SELECT rolname, rolcanlogin, rolsuper FROM pg_roles WHERE rolname IN ('schema_owner','honeypot_writer','dashboard_admin','dashboard_judge') ORDER BY rolname" `
    -c "\dt"
```

Expected: four roles (`schema_owner` with `rolcanlogin = f`, the other three `t`, none a
superuser) and five tables owned by `schema_owner`: `dashboard_users`, `detections`, `events`,
`llm_usage`, `sessions`.

Check that a login role can connect with its password. `-h 127.0.0.1` forces a password
check, because the container accepts local socket connections without one.

```powershell
docker compose @dc exec -T -e "PGPASSWORD=$env:HONEYPOT_WRITER_PASSWORD" postgres `
    psql -h 127.0.0.1 -U honeypot_writer -d honeypot --no-psqlrc -tA -c "SELECT current_user"
```

Expected output: `honeypot_writer`. (`honeypot_writer` cannot `SELECT` from `events`. That is
the least-privilege design from ADR-0004, not a fault.)

## Reset

`down -v` stops the containers, removes the networks, and deletes the `postgres_data` volume.
All data and all four roles are gone. Run the same `up` again to get a fresh database with no
migration applied.

```powershell
docker compose @dc down -v
docker compose @dc up -d --wait postgres
```

Run `docker compose @dc down` without `-v` to stop everything and keep the data.

To run `tests/test_migration.py` again after applying the migration, reset first, run the
tests (step 5), then apply the migration again (step 6).

Do not run `down -v` on the production host. It deletes the production database.
