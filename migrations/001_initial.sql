-- 001_initial.sql: initial schema, roles, and grants (T5.1).
-- Follows design.md "Data Models" and ADR-0004. Requires PostgreSQL 15 or newer.
--
-- HOW TO RUN (once per database, as a superuser, because it creates roles and uses SET ROLE):
--
--   psql -v ON_ERROR_STOP=1 \
--        -v honeypot_writer_password="$HONEYPOT_WRITER_PASSWORD" \
--        -v dashboard_admin_password="$DASHBOARD_ADMIN_PASSWORD" \
--        -v dashboard_judge_password="$DASHBOARD_JUDGE_PASSWORD" \
--        -h <host> -U <superuser> -d <database> -f migrations/001_initial.sql
--
-- Required psql variables (all non-empty; supply them from environment variables, never
-- hardcode them or commit them):
--   honeypot_writer_password   password for the honeypot_writer login role
--   dashboard_admin_password   password for the dashboard_admin login role
--   dashboard_judge_password   password for the dashboard_judge login role
--
-- Notes:
--   * schema_owner is NOLOGIN. It owns every table and is only reached through
--     SET ROLE inside this migration, so it never has a password or a network login.
--   * Roles are cluster-wide. Existing roles are left untouched (their passwords are
--     not changed) so the role part of this file can be re-read safely, but the table
--     part is not idempotent: run it once.
--   * CREATE ROLE ... PASSWORD can leak the password into server logs if log_statement
--     is 'ddl' or 'all'. Keep log_statement at 'none' or 'mod' while migrating.
--   * No triggers: the honeypot sends NOTIFY itself (IDs only, ADR-0004).
--   * No dashboard_users rows are inserted here (no secrets in migrations). Create the
--     first admin account out of band.

\set ON_ERROR_STOP on

-- Fail early, before opening the transaction, if a password variable is missing or empty.
\if :{?honeypot_writer_password}
  \if :{?dashboard_admin_password}
    \if :{?dashboard_judge_password}
      \set passwords_defined true
    \endif
  \endif
\endif
\if :{?passwords_defined}
\else
  \echo 'ERROR: set honeypot_writer_password, dashboard_admin_password and dashboard_judge_password with -v'
  \quit
\endif

SELECT (:'honeypot_writer_password' = ''
        OR :'dashboard_admin_password' = ''
        OR :'dashboard_judge_password' = '') AS password_empty \gset
\if :password_empty
  \echo 'ERROR: role passwords must not be empty'
  \quit
\endif

BEGIN;

-- ---------------------------------------------------------------------------
-- Roles (ADR-0004). Every attribute is set explicitly.
-- ---------------------------------------------------------------------------

SELECT 'CREATE ROLE schema_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'schema_owner')
\gexec

SELECT format(
    'CREATE ROLE honeypot_writer LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
    :'honeypot_writer_password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'honeypot_writer')
\gexec

SELECT format(
    'CREATE ROLE dashboard_admin LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
    :'dashboard_admin_password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'dashboard_admin')
\gexec

SELECT format(
    'CREATE ROLE dashboard_judge LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
    :'dashboard_judge_password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'dashboard_judge')
\gexec

-- ---------------------------------------------------------------------------
-- Lock down the public schema, then let each role use it (no CREATE for anyone but
-- schema_owner). Objects schema_owner creates later get no implicit PUBLIC access.
-- ---------------------------------------------------------------------------

REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO schema_owner;
GRANT USAGE ON SCHEMA public TO honeypot_writer, dashboard_admin, dashboard_judge;

ALTER DEFAULT PRIVILEGES FOR ROLE schema_owner REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE schema_owner REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE schema_owner REVOKE ALL ON FUNCTIONS FROM PUBLIC;

-- Everything below is created, and therefore owned, by schema_owner.
-- SET LOCAL reverts automatically at COMMIT or ROLLBACK.
SET LOCAL ROLE schema_owner;

-- ---------------------------------------------------------------------------
-- Tables
-- ---------------------------------------------------------------------------

CREATE TABLE sessions (
    session_id        UUID PRIMARY KEY,
    client_ip         INET        NOT NULL,
    client_port       INTEGER     NOT NULL,
    client_version    TEXT,
    started_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at          TIMESTAMPTZ,
    username          TEXT,
    auth_succeeded    BOOLEAN     NOT NULL DEFAULT FALSE,
    final_haunt_level SMALLINT    NOT NULL DEFAULT 0,
    end_reason        TEXT
);

CREATE TABLE events (
    session_id  UUID        NOT NULL REFERENCES sessions (session_id) ON DELETE CASCADE,
    seq         INTEGER     NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    event_type  TEXT        NOT NULL,
    payload     JSONB       NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (session_id, seq),
    CONSTRAINT events_seq_nonnegative CHECK (seq >= 0),
    CONSTRAINT events_event_type_valid CHECK (event_type IN (
        'connect', 'auth_attempt', 'command', 'output', 'haunt_level', 'haunt_event',
        'llm_request', 'detection', 'forward_denied', 'limit_rejected', 'truncated',
        'disconnect'
    ))
);

CREATE TABLE detections (
    detection_id BIGSERIAL   PRIMARY KEY,
    session_id   UUID        NOT NULL REFERENCES sessions (session_id) ON DELETE CASCADE,
    event_seq    INTEGER     NOT NULL,
    rule_id      TEXT        NOT NULL,
    technique_id TEXT        NOT NULL,
    detected_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE llm_usage (
    day                DATE    PRIMARY KEY,
    request_count      INTEGER NOT NULL DEFAULT 0,
    estimated_cost_usd NUMERIC NOT NULL DEFAULT 0,
    CONSTRAINT llm_usage_request_count_nonnegative CHECK (request_count >= 0)
);

CREATE TABLE dashboard_users (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL,
    CONSTRAINT dashboard_users_role_valid CHECK (role IN ('admin', 'judge'))
);

CREATE INDEX sessions_started_at_idx ON sessions (started_at);
CREATE INDEX detections_session_id_idx ON detections (session_id);

-- ---------------------------------------------------------------------------
-- Grants (ADR-0004). Anything not granted here is denied.
-- ---------------------------------------------------------------------------

-- honeypot_writer: append-only on history; narrow close-out UPDATE; owns the LLM counter.
GRANT INSERT ON sessions, events, detections TO honeypot_writer;
GRANT UPDATE (ended_at, final_haunt_level, end_reason) ON sessions TO honeypot_writer;
-- Needed so "UPDATE sessions ... WHERE session_id = ..." can read its WHERE column.
-- PostgreSQL requires SELECT on any column an UPDATE reads. This exposes only the UUID.
GRANT SELECT (session_id) ON sessions TO honeypot_writer;
GRANT SELECT, INSERT, UPDATE ON llm_usage TO honeypot_writer;
GRANT USAGE ON SEQUENCE detections_detection_id_seq TO honeypot_writer;

-- dashboard_judge: read-only on recordings.
GRANT SELECT ON sessions, events, detections TO dashboard_judge;

-- dashboard_admin: read everything the dashboard needs; delete recordings (R5.9).
-- Deleting a session cascades to events and detections through the foreign keys.
GRANT SELECT ON sessions, events, detections, llm_usage, dashboard_users TO dashboard_admin;
GRANT DELETE ON sessions TO dashboard_admin;

COMMIT;
