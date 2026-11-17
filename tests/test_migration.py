"""Tests for migrations/001_initial.sql against a real PostgreSQL server (T5.1, ADR-0004).

Runs only when DATABASE_URL is set. DATABASE_URL must point at a DISPOSABLE PostgreSQL server
as a superuser (the CI service container does), because the migration creates cluster-wide
roles. Each run creates a scratch database, applies the migration with psql, and drops the
scratch database and the four roles afterwards. If any of the four roles already exists, the
tests fail instead of touching them.

All passwords below are obviously fake and exist only for the lifetime of the test run.
"""

import os
import shutil
import subprocess
import uuid
from collections.abc import Callable, Iterator
from datetime import date
from pathlib import Path

import psycopg
import pytest
from psycopg import errors, sql
from psycopg.conninfo import make_conninfo

DATABASE_URL = os.environ.get("DATABASE_URL")

pytestmark = pytest.mark.skipif(
    not DATABASE_URL,
    reason="DATABASE_URL is not set; migration tests need a disposable PostgreSQL server "
    "(superuser URL) and the psql client",
)

MIGRATION = Path(__file__).resolve().parent.parent / "migrations" / "001_initial.sql"
ROLES = ("honeypot_writer", "dashboard_admin", "dashboard_judge", "schema_owner")
PASSWORDS = {
    "honeypot_writer": "test-only-writer-pw",
    "dashboard_admin": "test-only-admin-pw",
    "dashboard_judge": "test-only-judge-pw",
}
TABLES = ("sessions", "events", "detections", "llm_usage", "dashboard_users")

ConnectFn = Callable[[str], psycopg.Connection]


def _drop_roles(admin_conninfo: str) -> None:
    with psycopg.connect(admin_conninfo, autocommit=True) as conn:
        for role in ROLES:
            conn.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))


@pytest.fixture(scope="module")
def migrated() -> Iterator[ConnectFn]:
    """Apply the migration to a scratch database; yield connect(role) ('postgres' = superuser)."""
    assert DATABASE_URL is not None
    psql = shutil.which("psql")
    if psql is None:
        pytest.fail("DATABASE_URL is set but the psql client is not on PATH")

    admin_conninfo = make_conninfo(DATABASE_URL)
    scratch_db = f"hp_migration_test_{uuid.uuid4().hex[:12]}"

    with psycopg.connect(admin_conninfo, autocommit=True) as conn:
        existing = conn.execute(
            "SELECT rolname FROM pg_roles WHERE rolname = ANY(%s)", (list(ROLES),)
        ).fetchall()
        if existing:
            pytest.fail(
                f"roles already exist on this server: {sorted(r[0] for r in existing)}. "
                "Point DATABASE_URL at a disposable server; these tests drop the roles."
            )
        conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(scratch_db)))

    scratch_conninfo = make_conninfo(admin_conninfo, dbname=scratch_db)
    try:
        result = subprocess.run(
            [
                psql,
                "--no-psqlrc",
                "-v",
                "ON_ERROR_STOP=1",
                "-v",
                f"honeypot_writer_password={PASSWORDS['honeypot_writer']}",
                "-v",
                f"dashboard_admin_password={PASSWORDS['dashboard_admin']}",
                "-v",
                f"dashboard_judge_password={PASSWORDS['dashboard_judge']}",
                "-d",
                scratch_conninfo,
                "-f",
                str(MIGRATION),
            ],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert result.returncode == 0, (
            f"psql failed ({result.returncode}):\n{result.stdout}\n{result.stderr}"
        )

        def connect(role: str) -> psycopg.Connection:
            if role == "postgres":
                return psycopg.connect(scratch_conninfo, autocommit=True)
            return psycopg.connect(
                make_conninfo(scratch_conninfo, user=role, password=PASSWORDS[role]),
                autocommit=True,
            )

        yield connect
    finally:
        with psycopg.connect(admin_conninfo, autocommit=True) as conn:
            conn.execute(
                sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(
                    sql.Identifier(scratch_db)
                )
            )
        _drop_roles(admin_conninfo)


@pytest.fixture
def writer(migrated: ConnectFn) -> Iterator[psycopg.Connection]:
    with migrated("honeypot_writer") as conn:
        yield conn


@pytest.fixture
def judge(migrated: ConnectFn) -> Iterator[psycopg.Connection]:
    with migrated("dashboard_judge") as conn:
        yield conn


@pytest.fixture
def admin(migrated: ConnectFn) -> Iterator[psycopg.Connection]:
    with migrated("dashboard_admin") as conn:
        yield conn


def insert_session(conn: psycopg.Connection) -> uuid.UUID:
    session_id = uuid.uuid4()
    conn.execute(
        "INSERT INTO sessions (session_id, client_ip, client_port) VALUES (%s, %s, %s)",
        (session_id, "203.0.113.9", 40000),
    )
    return session_id


def insert_event(conn: psycopg.Connection, session_id: uuid.UUID, seq: int = 0) -> None:
    conn.execute(
        "INSERT INTO events (session_id, seq, occurred_at, event_type, payload) "
        "VALUES (%s, %s, now(), 'connect', '{}'::jsonb)",
        (session_id, seq),
    )


def insert_detection(conn: psycopg.Connection, session_id: uuid.UUID, event_seq: int = 0) -> None:
    conn.execute(
        "INSERT INTO detections (session_id, event_seq, rule_id, technique_id) "
        "VALUES (%s, %s, 'RULE-TEST', 'T0000')",
        (session_id, event_seq),
    )


def count(conn: psycopg.Connection, table: str, session_id: uuid.UUID) -> int:
    row = conn.execute(
        sql.SQL("SELECT count(*) FROM {} WHERE session_id = %s").format(sql.Identifier(table)),
        (session_id,),
    ).fetchone()
    assert row is not None
    return row[0]


# ---------------------------------------------------------------------------
# honeypot_writer
# ---------------------------------------------------------------------------


def test_adr4_writer_can_insert_sessions_events_and_detections(writer, admin):
    session_id = insert_session(writer)
    insert_event(writer, session_id)
    insert_detection(writer, session_id)

    assert count(admin, "sessions", session_id) == 1
    assert count(admin, "events", session_id) == 1
    assert count(admin, "detections", session_id) == 1


@pytest.mark.parametrize(
    "statement",
    [
        "SELECT * FROM events",
        "SELECT * FROM detections",
        "UPDATE events SET payload = '{}'::jsonb",
        "UPDATE detections SET rule_id = 'x'",
        "DELETE FROM events",
        "DELETE FROM detections",
    ],
)
def test_adr4_writer_cannot_select_update_or_delete_history_tables(writer, statement):
    with pytest.raises(errors.InsufficientPrivilege):
        writer.execute(statement)


def test_adr4_writer_cannot_delete_sessions(writer):
    session_id = insert_session(writer)
    with pytest.raises(errors.InsufficientPrivilege):
        writer.execute("DELETE FROM sessions WHERE session_id = %s", (session_id,))


def test_adr4_writer_can_update_only_the_three_close_columns_on_sessions(writer, admin):
    session_id = insert_session(writer)

    cur = writer.execute(
        "UPDATE sessions SET ended_at = now(), final_haunt_level = 3, end_reason = 'disconnect' "
        "WHERE session_id = %s",
        (session_id,),
    )
    assert cur.rowcount == 1
    row = admin.execute(
        "SELECT final_haunt_level, end_reason, ended_at IS NOT NULL FROM sessions "
        "WHERE session_id = %s",
        (session_id,),
    ).fetchone()
    assert row == (3, "disconnect", True)


@pytest.mark.parametrize(
    "assignment",
    [
        "session_id = gen_random_uuid()",
        "client_ip = '198.51.100.1'",
        "client_port = 1",
        "client_version = 'x'",
        "started_at = now()",
        "username = 'x'",
        "auth_succeeded = TRUE",
    ],
)
def test_adr4_writer_cannot_update_other_sessions_columns(writer, assignment):
    session_id = insert_session(writer)
    with pytest.raises(errors.InsufficientPrivilege):
        writer.execute(
            f"UPDATE sessions SET {assignment} WHERE session_id = %s",
            (session_id,),
        )


def test_adr4_writer_can_select_only_session_id_from_sessions(writer):
    session_id = insert_session(writer)
    row = writer.execute(
        "SELECT session_id FROM sessions WHERE session_id = %s", (session_id,)
    ).fetchone()
    assert row == (session_id,)
    for column in ("client_ip", "username", "end_reason"):
        with pytest.raises(errors.InsufficientPrivilege):
            writer.execute(sql.SQL("SELECT {} FROM sessions").format(sql.Identifier(column)))


def test_adr4_writer_can_read_and_update_llm_usage(writer):
    day = date(2031, 1, 2)
    writer.execute(
        "INSERT INTO llm_usage (day, request_count, estimated_cost_usd) VALUES (%s, 1, 0.01)",
        (day,),
    )
    assert writer.execute(
        "SELECT request_count FROM llm_usage WHERE day = %s", (day,)
    ).fetchone() == (1,)

    # The atomic upsert from design.md ("llm_usage"), which needs INSERT, SELECT and UPDATE.
    row = writer.execute(
        "INSERT INTO llm_usage (day, request_count, estimated_cost_usd) VALUES (%s, 1, 0.01) "
        "ON CONFLICT (day) DO UPDATE SET request_count = llm_usage.request_count + 1, "
        "estimated_cost_usd = llm_usage.estimated_cost_usd + 0.01 "
        "RETURNING request_count",
        (day,),
    ).fetchone()
    assert row == (2,)

    with pytest.raises(errors.InsufficientPrivilege):
        writer.execute("DELETE FROM llm_usage WHERE day = %s", (day,))


def test_adr4_writer_has_no_access_to_dashboard_users(writer):
    with pytest.raises(errors.InsufficientPrivilege):
        writer.execute("SELECT * FROM dashboard_users")
    with pytest.raises(errors.InsufficientPrivilege):
        writer.execute("INSERT INTO dashboard_users VALUES ('x', 'hash', 'admin')")


# ---------------------------------------------------------------------------
# dashboard_judge
# ---------------------------------------------------------------------------


def test_adr4_judge_can_select_sessions_events_and_detections(writer, judge):
    session_id = insert_session(writer)
    insert_event(writer, session_id)
    insert_detection(writer, session_id)

    assert count(judge, "sessions", session_id) == 1
    assert count(judge, "events", session_id) == 1
    assert count(judge, "detections", session_id) == 1


@pytest.mark.parametrize("table", ["llm_usage", "dashboard_users"])
def test_adr4_judge_cannot_select_llm_usage_or_dashboard_users(judge, table):
    with pytest.raises(errors.InsufficientPrivilege):
        judge.execute(sql.SQL("SELECT * FROM {}").format(sql.Identifier(table)))


@pytest.mark.parametrize("table", TABLES)
def test_adr4_judge_cannot_insert_update_or_delete_anything(judge, table):
    with pytest.raises(errors.InsufficientPrivilege):
        judge.execute(sql.SQL("DELETE FROM {}").format(sql.Identifier(table)))
    with pytest.raises(errors.InsufficientPrivilege):
        judge.execute(
            {
                "sessions": "UPDATE sessions SET end_reason = 'x'",
                "events": "UPDATE events SET event_type = 'connect'",
                "detections": "UPDATE detections SET rule_id = 'x'",
                "llm_usage": "UPDATE llm_usage SET request_count = 0",
                "dashboard_users": "UPDATE dashboard_users SET role = 'admin'",
            }[table]
        )
    insert = {
        "sessions": "INSERT INTO sessions (session_id, client_ip, client_port) "
        "VALUES (gen_random_uuid(), '203.0.113.9', 1)",
        "events": "INSERT INTO events (session_id, seq, occurred_at, event_type) "
        "VALUES (gen_random_uuid(), 0, now(), 'connect')",
        "detections": "INSERT INTO detections (session_id, event_seq, rule_id, technique_id) "
        "VALUES (gen_random_uuid(), 0, 'r', 't')",
        "llm_usage": "INSERT INTO llm_usage (day) VALUES (current_date)",
        "dashboard_users": "INSERT INTO dashboard_users VALUES ('x', 'hash', 'judge')",
    }[table]
    with pytest.raises(errors.InsufficientPrivilege):
        judge.execute(insert)


# ---------------------------------------------------------------------------
# dashboard_admin
# ---------------------------------------------------------------------------


def test_adr4_admin_delete_session_cascades_to_events_and_detections(writer, admin):
    doomed = insert_session(writer)
    survivor = insert_session(writer)
    for session_id in (doomed, survivor):
        insert_event(writer, session_id, 0)
        insert_event(writer, session_id, 1)
        insert_detection(writer, session_id, 0)

    cur = admin.execute("DELETE FROM sessions WHERE session_id = %s", (doomed,))
    assert cur.rowcount == 1

    assert count(admin, "sessions", doomed) == 0
    assert count(admin, "events", doomed) == 0
    assert count(admin, "detections", doomed) == 0
    # Other sessions are untouched.
    assert count(admin, "sessions", survivor) == 1
    assert count(admin, "events", survivor) == 2
    assert count(admin, "detections", survivor) == 1


def test_adr4_admin_can_select_all_tables_but_not_modify_them(admin):
    for table in TABLES:
        admin.execute(sql.SQL("SELECT * FROM {}").format(sql.Identifier(table))).fetchall()

    with pytest.raises(errors.InsufficientPrivilege):
        admin.execute("UPDATE sessions SET end_reason = 'x'")
    with pytest.raises(errors.InsufficientPrivilege):
        admin.execute("DELETE FROM events")
    with pytest.raises(errors.InsufficientPrivilege):
        admin.execute("INSERT INTO dashboard_users VALUES ('x', 'hash', 'admin')")


# ---------------------------------------------------------------------------
# Constraints (superuser connection; roles above deliberately cannot write these)
# ---------------------------------------------------------------------------


def test_r5_constraints_reject_bad_values(migrated, writer):
    session_id = insert_session(writer)
    with migrated("postgres") as su:
        with pytest.raises(errors.CheckViolation):
            su.execute(
                "INSERT INTO events (session_id, seq, occurred_at, event_type) "
                "VALUES (%s, 0, now(), 'not_an_event_type')",
                (session_id,),
            )
        with pytest.raises(errors.CheckViolation):
            su.execute(
                "INSERT INTO events (session_id, seq, occurred_at, event_type) "
                "VALUES (%s, -1, now(), 'connect')",
                (session_id,),
            )
        with pytest.raises(errors.CheckViolation):
            su.execute("INSERT INTO dashboard_users VALUES ('u', 'h', 'owner')")
        with pytest.raises(errors.CheckViolation):
            su.execute("INSERT INTO llm_usage (day, request_count) VALUES (current_date, -1)")

    insert_event(writer, session_id, 0)
    with pytest.raises(errors.UniqueViolation):
        insert_event(writer, session_id, 0)
