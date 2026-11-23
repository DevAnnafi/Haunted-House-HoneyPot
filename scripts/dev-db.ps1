<#
.SYNOPSIS
    Start the local development PostgreSQL, apply migrations/001_initial.sql, and write
    HONEYPOT_DATABASE_URL into .env. Development only; never run this on the server.

.DESCRIPTION
    Does steps 4, 6 and 7 of docs/dev-database.md in one go:
      1. Starts only the postgres service with docker-compose.yml + docker-compose.dev.yml,
         published on 127.0.0.1 (port from DEV_POSTGRES_PORT in .env, default 15432;
         see docker-compose.dev.yml for why it isn't 5432).
      2. Generates new random passwords for honeypot_writer, dashboard_admin and
         dashboard_judge, and applies migrations/001_initial.sql inside the container.
      3. Writes HONEYPOT_DATABASE_URL (honeypot_writer, published port) into .env.
      4. Verifies the roles, the tables, a password login as honeypot_writer, and that the
         published port answers.

    Passwords are never printed and never appear on a command line: they reach psql
    through environment variables (docker compose exec -e NAME) and psql's \getenv.
    The dashboard_admin and dashboard_judge passwords are not saved anywhere.

    Steps 1-3 of docs/dev-database.md (postgres.env, .env, HONEYPOT_HOST_KEY_FILE) must
    be done first. The script stops with an error at the first failure.

.PARAMETER Reset
    Run "docker compose down -v" first. This DELETES the dev database volume and all data
    in it, so the migration can be applied to an empty database.

.EXAMPLE
    .\scripts\dev-db.ps1
.EXAMPLE
    .\scripts\dev-db.ps1 -Reset
#>
[CmdletBinding()]
param(
    [switch]$Reset
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
# PowerShell 7.3+: don't turn native stderr/exit codes into exceptions; exit codes are
# checked explicitly below. Harmless on Windows PowerShell 5.1.
$PSNativeCommandUseErrorActionPreference = $false

$RepoRoot = Split-Path -Parent $PSScriptRoot
$Compose = @('compose', '-f', 'docker-compose.yml', '-f', 'docker-compose.dev.yml')
$Roles = @('dashboard_admin', 'dashboard_judge', 'honeypot_writer', 'schema_owner')
$RoleList = "'dashboard_admin','dashboard_judge','honeypot_writer','schema_owner'"
$ExpectedRoles = @(
    'dashboard_admin:true:false',
    'dashboard_judge:true:false',
    'honeypot_writer:true:false',
    'schema_owner:false:false'
)
$ExpectedTables = @('dashboard_users', 'detections', 'events', 'llm_usage', 'sessions')
# Names of the temporary environment variables that carry the passwords to the container.
$PasswordVars = [ordered]@{
    honeypot_writer_password = 'DEVDB_HONEYPOT_WRITER_PASSWORD'
    dashboard_admin_password = 'DEVDB_DASHBOARD_ADMIN_PASSWORD'
    dashboard_judge_password = 'DEVDB_DASHBOARD_JUDGE_PASSWORD'
}

function Write-Step([string]$Message) {
    Write-Host "dev-db: $Message" -ForegroundColor Cyan
}

function Stop-WithError([string]$Message) {
    throw [System.InvalidOperationException]::new($Message)
}

function Invoke-Docker {
    <# Runs docker with the given arguments. Returns stdout; stderr goes to the console.
       Throws if docker exits non-zero. #>
    param(
        [Parameter(Mandatory)][string]$Step,
        [Parameter(Mandatory)][string[]]$Arguments,
        [string]$InputText,
        [string]$Hint = ''
    )
    # Windows PowerShell 5.1 can turn native stderr into errors; keep it plain output.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        if ($PSBoundParameters.ContainsKey('InputText')) {
            $output = $InputText | & docker @Arguments
        }
        else {
            $output = & docker @Arguments
        }
        $code = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previous
    }
    if ($code -ne 0) {
        $message = "$Step failed (exit code $code). See the output above."
        if ($Hint) { $message += " $Hint" }
        Stop-WithError $message
    }
    return @($output | Where-Object { $_ -ne $null } | ForEach-Object { "$_".TrimEnd() })
}

function Invoke-Psql {
    <# Runs SQL (from stdin) with psql inside the postgres container as the superuser. #>
    param(
        [Parameter(Mandatory)][string]$Step,
        [Parameter(Mandatory)][string]$Sql,
        [string[]]$EnvNames = @(),
        [string[]]$PsqlArgs = @('-U', 'postgres', '-d', 'honeypot')
    )
    $arguments = $Compose + @('exec', '-T')
    foreach ($name in $EnvNames) {
        # "-e NAME" without a value passes the variable from this process's environment,
        # so the value never appears on a command line.
        $arguments += @('-e', $name)
    }
    # VERBOSITY=terse: error messages without the "LINE n:" excerpt, which for a failed
    # CREATE ROLE could show the password.
    $arguments += @('postgres', 'psql', '-X', '-q', '-t', '-A', '-v', 'ON_ERROR_STOP=1', '-v', 'VERBOSITY=terse') + $PsqlArgs + @('-f', '-')
    return Invoke-Docker -Step $Step -Arguments $arguments -InputText $Sql
}

function New-Password {
    # 32 random bytes as URL-safe base64 (43 characters: letters, digits, - and _),
    # so the password needs no escaping inside a connection URL.
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Read-DotEnv([string]$Path) {
    <# Minimal KEY=VALUE reader, enough for the checks below. #>
    $values = @{}
    foreach ($line in [System.IO.File]::ReadAllLines($Path)) {
        $trimmed = $line.Trim()
        if ($trimmed -eq '' -or $trimmed.StartsWith('#')) { continue }
        if ($trimmed -match '^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$') {
            $value = $Matches[2].Trim()
            if ($value.Length -ge 2 -and ($value[0] -eq '"' -or $value[0] -eq "'") -and $value[-1] -eq $value[0]) {
                $value = $value.Substring(1, $value.Length - 2)
            }
            $values[$Matches[1]] = $value
        }
    }
    return $values
}

function Set-DotEnvValue([string]$Path, [string]$Name, [string]$Value) {
    <# Replaces the active NAME= line (or appends one), keeps every other line, and writes
       the file back as UTF-8 without BOM through a temporary file. #>
    $raw = [System.IO.File]::ReadAllText($Path)
    $newline = if ($raw.Contains("`r`n")) { "`r`n" } else { "`n" }
    $lines = [System.Collections.Generic.List[string]]::new()
    if ($raw.Length -gt 0) {
        $lines.AddRange([string[]]($raw -split "\r?\n"))
        if ($lines[$lines.Count - 1] -eq '') { $lines.RemoveAt($lines.Count - 1) }
    }
    $pattern = '^\s*(?:export\s+)?' + [regex]::Escape($Name) + '\s*='
    $entry = "$Name=$Value"
    $replaced = $false
    for ($i = $lines.Count - 1; $i -ge 0; $i--) {
        if ($lines[$i] -match $pattern) {
            if ($replaced) { $lines.RemoveAt($i) } else { $lines[$i] = $entry; $replaced = $true }
        }
    }
    # Walking backwards keeps the last NAME= line (the one dotenv would use) and drops the rest.
    if (-not $replaced) { $lines.Add($entry) }
    $temp = "$Path.dev-db.tmp"
    [System.IO.File]::WriteAllText($temp, ($lines -join $newline) + $newline, [System.Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temp -Destination $Path -Force
}

function Assert-Prerequisites {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Stop-WithError 'docker was not found on PATH. Install Docker Desktop (docs/dev-database.md, Prerequisites).'
    }
    $null = Invoke-Docker -Step 'docker compose version' -Arguments @('compose', 'version') `
        -Hint 'Docker Compose v2 is required, and Docker Desktop must be running.'

    $pgEnv = Join-Path $RepoRoot 'postgres.env'
    if (-not (Test-Path -LiteralPath $pgEnv -PathType Leaf)) {
        Stop-WithError 'postgres.env not found. Create it first (docs/dev-database.md, step 1).'
    }
    $pgPassword = (Read-DotEnv $pgEnv)['POSTGRES_PASSWORD']
    if (-not $pgPassword -or $pgPassword.StartsWith('generate-with:')) {
        Stop-WithError 'POSTGRES_PASSWORD in postgres.env is empty or still the placeholder. Set it first (docs/dev-database.md, step 1).'
    }

    $dotEnv = Join-Path $RepoRoot '.env'
    if (-not (Test-Path -LiteralPath $dotEnv -PathType Leaf)) {
        Stop-WithError '.env not found. Create it first (docs/dev-database.md, step 2).'
    }
    $values = Read-DotEnv $dotEnv
    if (-not $values['HONEYPOT_HOST_KEY_FILE'] -and -not $env:HONEYPOT_HOST_KEY_FILE) {
        Stop-WithError 'HONEYPOT_HOST_KEY_FILE is not set in .env; Compose requires it even when only Postgres starts (docs/dev-database.md, step 3).'
    }
    $port = if ($env:DEV_POSTGRES_PORT) { $env:DEV_POSTGRES_PORT } else { $values['DEV_POSTGRES_PORT'] }
    if ($port) {
        $parsed = 0
        if (-not [int]::TryParse($port, [ref]$parsed) -or $parsed -lt 1 -or $parsed -gt 65535) {
            Stop-WithError "DEV_POSTGRES_PORT must be a port number from 1 to 65535, got '$port'."
        }
    }

    # .env will hold a password: refuse to write it into a file git would commit.
    if (Get-Command git -ErrorAction SilentlyContinue) {
        $previous = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try { & git -C $RepoRoot check-ignore -q .env 2>$null; $code = $LASTEXITCODE }
        finally { $ErrorActionPreference = $previous }
        if ($code -eq 1) {
            Stop-WithError '.env is not ignored by git. Fix .gitignore before writing a password into it.'
        }
    }
}

$savedEnv = @{}
foreach ($name in @($PasswordVars.Values) + @('PGPASSWORD')) {
    $savedEnv[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
$savedOutputEncoding = $OutputEncoding
$exitCode = 0
Push-Location -LiteralPath $RepoRoot
try {
    Assert-Prerequisites

    if ($Reset) {
        Write-Step 'Reset: docker compose down -v (deletes the dev database volume)'
        $null = Invoke-Docker -Step 'docker compose down -v' -Arguments ($Compose + @('down', '-v'))
    }

    Write-Step 'Starting postgres (docker-compose.yml + docker-compose.dev.yml)'
    $null = Invoke-Docker -Step 'Starting postgres' `
        -Arguments ($Compose + @('up', '-d', '--wait', '--wait-timeout', '120', 'postgres')) `
        -Hint 'If the port is already in use, set DEV_POSTGRES_PORT in .env to a free port (docs/dev-database.md, step 3).'

    $published = @(Invoke-Docker -Step 'Reading the published port' -Arguments ($Compose + @('port', 'postgres', '5432')))
    $binding = ($published | Select-Object -First 1)
    if (-not $binding -or $binding -notmatch '^127\.0\.0\.1:(\d+)$') {
        Stop-WithError "postgres is published on '$binding', not on 127.0.0.1. Check docker-compose.dev.yml; stop the container with: docker compose -f docker-compose.yml -f docker-compose.dev.yml down"
    }
    $port = [int]$Matches[1]
    Write-Step "postgres is healthy on 127.0.0.1:$port"
    $wantedPort = if ($env:DEV_POSTGRES_PORT) { $env:DEV_POSTGRES_PORT } else { (Read-DotEnv (Join-Path $RepoRoot '.env'))['DEV_POSTGRES_PORT'] }
    if ($wantedPort -and [int]$wantedPort -ne $port) {
        Write-Warning "DEV_POSTGRES_PORT is $wantedPort, but postgres is published on $port, so docker-compose.dev.yml is not using DEV_POSTGRES_PORT. HONEYPOT_DATABASE_URL uses the real port, $port."
    }

    $existing = @(Invoke-Psql -Step 'Checking for existing roles' -Sql "SELECT count(*) FROM pg_roles WHERE rolname IN ($RoleList);")
    $existingCount = [int]($existing | Select-Object -Last 1)
    if ($existingCount -ne 0) {
        Stop-WithError "the database is already migrated ($existingCount of 4 roles exist), and 001_initial.sql runs only once. Run again with -Reset to start from an empty database (this deletes all data in it)."
    }

    Write-Step 'Generating role passwords and applying migrations/001_initial.sql'
    foreach ($name in $PasswordVars.Values) {
        [Environment]::SetEnvironmentVariable($name, (New-Password), 'Process')
    }
    $header = ($PasswordVars.Keys | ForEach-Object { "\getenv $_ $($PasswordVars[$_])" }) -join "`n"
    $migration = [System.IO.File]::ReadAllText((Join-Path $RepoRoot 'migrations\001_initial.sql'), [System.Text.Encoding]::UTF8)
    # The SQL file has non-ASCII characters in comments; send UTF-8 to docker.
    $OutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $migrationOutput = @(Invoke-Psql -Step 'Applying migrations/001_initial.sql' -Sql ($header + "`n" + $migration) `
            -EnvNames @($PasswordVars.Values))
    # The migration's own guards print "ERROR: ..." and \quit with exit code 0.
    $guardError = $migrationOutput | Where-Object { $_ -like 'ERROR:*' } | Select-Object -First 1
    if ($guardError) {
        Stop-WithError "the migration stopped before changing anything: $guardError"
    }

    $writerPassword = [Environment]::GetEnvironmentVariable($PasswordVars['honeypot_writer_password'], 'Process')
    $url = "postgresql://honeypot_writer:$writerPassword@127.0.0.1:$port/honeypot"
    Set-DotEnvValue -Path (Join-Path $RepoRoot '.env') -Name 'HONEYPOT_DATABASE_URL' -Value $url
    Write-Step "Wrote HONEYPOT_DATABASE_URL to .env (honeypot_writer@127.0.0.1:$port/honeypot)"

    Write-Step 'Verifying'
    $roles = @(Invoke-Psql -Step 'Listing roles' -Sql "SELECT rolname || ':' || rolcanlogin::text || ':' || rolsuper::text FROM pg_roles WHERE rolname IN ($RoleList) ORDER BY rolname;")
    if (($roles -join ',') -ne ($ExpectedRoles -join ',')) {
        Stop-WithError "unexpected roles after the migration: '$($roles -join ', ')'. Expected: '$($ExpectedRoles -join ', ')'."
    }
    $tables = @(Invoke-Psql -Step 'Listing tables' -Sql "SELECT tablename || ':' || tableowner FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename;")
    $expectedTableRows = $ExpectedTables | ForEach-Object { "${_}:schema_owner" }
    if (($tables -join ',') -ne ($expectedTableRows -join ',')) {
        Stop-WithError "unexpected tables after the migration: '$($tables -join ', ')'. Expected: '$($expectedTableRows -join ', ')'."
    }
    # Log in over TCP inside the container so the password is actually checked.
    [Environment]::SetEnvironmentVariable('PGPASSWORD', $writerPassword, 'Process')
    $who = @(Invoke-Psql -Step 'Logging in as honeypot_writer' -Sql 'SELECT current_user;' `
            -EnvNames @('PGPASSWORD') -PsqlArgs @('-h', '127.0.0.1', '-U', 'honeypot_writer', '-d', 'honeypot'))
    if (($who | Select-Object -Last 1) -ne 'honeypot_writer') {
        Stop-WithError "login as honeypot_writer returned '$($who -join ' ')'."
    }
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        if (-not $client.ConnectAsync('127.0.0.1', $port).Wait(5000)) {
            Stop-WithError "127.0.0.1:$port does not answer from this machine."
        }
    }
    catch [System.AggregateException] {
        Stop-WithError "127.0.0.1:$port does not answer from this machine: $($_.Exception.InnerException.Message)"
    }
    finally { $client.Dispose() }

    Write-Host ''
    Write-Host 'Roles (name, can log in, superuser):'
    $roles | ForEach-Object { Write-Host "  $($_ -replace ':', '  ')" }
    Write-Host 'Tables (name, owner):'
    $tables | ForEach-Object { Write-Host "  $($_ -replace ':', '  ')" }
    Write-Host 'Login as honeypot_writer with the new password: OK'
    Write-Host "Published port 127.0.0.1:${port}: OK"
    Write-Host ''
    Write-Step 'Done. HONEYPOT_DATABASE_URL in .env points at this database.'
    Write-Host 'The dashboard_admin and dashboard_judge passwords were not saved. Set new ones with ALTER ROLE when the dashboard needs them.'
}
catch {
    Write-Host "dev-db: ERROR: $($_.Exception.Message)" -ForegroundColor Red
    $exitCode = 1
}
finally {
    foreach ($name in $savedEnv.Keys) {
        [Environment]::SetEnvironmentVariable($name, $savedEnv[$name], 'Process')
    }
    $OutputEncoding = $savedOutputEncoding
    Pop-Location
}
exit $exitCode
