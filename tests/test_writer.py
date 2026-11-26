"""Tests for honeypot/writer.py against a real PostgreSQL server (ADR-0004, R5).

The database tests run only when DATABASE_URL is set, exactly like test_migration.py:
DATABASE_URL must point at a DISPOSABLE PostgreSQL server as a superuser, because the
migration creates cluster-wide roles. Each module run creates a scratch database, applies
migrations/001_initial.sql with psql, connects as ``honeypot_writer`` (the role the real
writer uses), reads results back as ``dashboard_admin``, and drops the scratch database and
the four roles afterwards. If any of the four roles already exists, the tests fail instead
of touching them.

The PoolTimeout test needs no database and always runs (it takes about 10 seconds because
``open_pool`` waits 10 seconds for the pool to fill).

All passwords below are obviously fake and exist only for the lifetime of the test run.
"""

import asyncio
import json
import logging
import os
import shutil
import socket
import subprocess
import uuid
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from psycopg import AsyncConnection, Connection, sql
from psycopg.conninfo import make_conninfo
from psycopg_pool import PoolTimeout

from honeypot.recorder import Recorder
from honeypot.writer import open_pool, run_writer
from shared.events import EndReason, EventRow, EventType, utc_now_ms

DATABASE_URL = os.environ.get("DATABASE_URL")

requires_database = pytest.mark.skipif(
    not DATABASE_URL,
    reason="DATABASE_URL is not set; writer tests need a disposable PostgreSQL server "
    "(superuser URL) and the psql client",
)

MIGRATION = Path(__file__).resolve().parent.parent / "migrations" / "001_initial.sql"
ROLES = ("honeypot_writer", "dashboard_admin", "dashboard_judge", "schema_owner")
PASSWORDS = {
    "honeypot_writer": "test-only-writer-pw",
    "dashboard_admin": "test-only-admin-pw",
    "dashboard_judge": "test-only-judge-pw",
}
CHANNEL = "honeypot_events"
NOTIFY_TIMEOUT = 5.0


@dataclass(frozen=True)
class Database:
    """Connection strings for the scratch database, one per role."""

    writer: str
    admin: str


def _drop_roles(admin_conninfo: str) -> None:
    with Connection.connect(admin_conninfo, autocommit=True) as conn:
        for role in ROLES:
            conn.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))


@pytest.fixture(scope="module")
def database() -> Iterator[Database]:
    """Apply the migration to a scratch database; yield connection strings per role."""
    assert DATABASE_URL is not None
    psql = shutil.which("psql")
    if psql is None:
        pytest.fail("DATABASE_URL is set but the psql client is not on PATH")

    admin_conninfo = make_conninfo(DATABASE_URL)
    scratch_db = f"hp_writer_test_{uuid.uuid4().hex[:12]}"

    with Connection.connect(admin_conninfo, autocommit=True) as conn:
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

        yield Database(
            writer=make_conninfo(
                scratch_conninfo, user="honeypot_writer", password=PASSWORDS["honeypot_writer"]
            ),
            admin=make_conninfo(
                scratch_conninfo, user="dashboard_admin", password=PASSWORDS["dashboard_admin"]
            ),
        )
    finally:
        with Connection.connect(admin_conninfo, autocommit=True) as conn:
            conn.execute(
                sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(
                    sql.Identifier(scratch_db)
                )
            )
        _drop_roles(admin_conninfo)


@dataclass
class Harness:
    recorder: Recorder
    database: Database
    listener: AsyncConnection

    async def drain(self) -> None:
        """Wait until the writer has handled every item queued so far."""
        await asyncio.wait_for(self.recorder.queue.join(), timeout=10)

    async def notifications(self, count: int) -> list[Any]:
        """Collect exactly ``count`` notifications from the LISTEN connection."""
        received: list[Any] = []
        async for note in self.listener.notifies(timeout=NOTIFY_TIMEOUT, stop_after=count):
            received.append(note)
        return received

    async def fetch(self, query: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
        """Read as dashboard_admin; the writer role has no SELECT on events."""
        async with await AsyncConnection.connect(self.database.admin, autocommit=True) as conn:
            cursor = await conn.execute(query, params)
            return await cursor.fetchall()


@pytest.fixture
async def harness(database: Database) -> AsyncIterator[Harness]:
    """A Recorder feeding run_writer on a pool that connects as honeypot_writer."""
    recorder = Recorder()
    pool = await open_pool(database.writer)
    listener = await AsyncConnection.connect(database.admin, autocommit=True)
    writer_task: asyncio.Task[None] | None = None
    try:
        await listener.execute(sql.SQL("LISTEN {}").format(sql.Identifier(CHANNEL)))
        writer_task = asyncio.create_task(run_writer(recorder, pool))
        yield Harness(recorder=recorder, database=database, listener=listener)
        # The writer must still be running at the end of every test.
        assert not writer_task.done()
    finally:
        if writer_task is not None:
            writer_task.cancel()
            await asyncio.gather(writer_task, return_exceptions=True)
        await listener.close()
        await pool.close()


def _start(recorder: Recorder, client_version: str | None = "SSH-2.0-test") -> uuid.UUID:
    session_id = uuid.uuid4()
    recorder.start(session_id, "203.0.113.7", 40022, client_version)
    return session_id


# ---------------------------------------------------------------------------
# Session row (R5.2)
# ---------------------------------------------------------------------------


@requires_database
async def test_r5_2_authenticated_session_row_is_written(harness: Harness) -> None:
    before = utc_now_ms()
    session_id = _start(harness.recorder)
    harness.recorder.authenticated(session_id, "root")
    await harness.drain()

    rows = await harness.fetch(
        "SELECT host(client_ip), client_port, client_version, username, auth_succeeded,"
        " started_at, ended_at, final_haunt_level, end_reason"
        " FROM sessions WHERE session_id = %s",
        (session_id,),
    )
    assert len(rows) == 1
    ip, port, version, username, auth_succeeded, started_at, ended_at, haunt, reason = rows[0]
    assert ip == "203.0.113.7"
    assert port == 40022
    assert version == "SSH-2.0-test"
    assert username == "root"
    assert auth_succeeded is True
    # R5.12: UTC with millisecond precision, taken when the session started.
    assert started_at.utcoffset() == timedelta(0)
    assert started_at.microsecond % 1000 == 0
    assert before <= started_at <= utc_now_ms()
    # Not closed yet.
    assert ended_at is None
    assert haunt == 0
    assert reason is None


@requires_database
async def test_r5_2_unauthenticated_session_row_has_null_username(harness: Harness) -> None:
    session_id = _start(harness.recorder, client_version=None)
    harness.recorder.end(session_id, EndReason.DISCONNECT, 0)
    await harness.drain()

    rows = await harness.fetch(
        "SELECT username, auth_succeeded, client_version, end_reason FROM sessions"
        " WHERE session_id = %s",
        (session_id,),
    )
    assert rows == [(None, False, None, "disconnect")]


# ---------------------------------------------------------------------------
# Events and NOTIFY (R5.8, ADR-0004)
# ---------------------------------------------------------------------------


@requires_database
async def test_r5_8_events_are_written_in_order_with_id_only_notifications(
    harness: Harness,
) -> None:
    recorder = harness.recorder
    session_id = _start(recorder)
    # The first event is buffered before authentication; the writer must still insert the
    # session row first or the foreign key rejects the event.
    assert recorder.record(session_id, EventType.CONNECT, {"banner": "SSH-2.0-test"})
    recorder.authenticated(session_id, "root")
    assert recorder.record(session_id, EventType.COMMAND, {"input": "ls -la", "n": 1})
    assert recorder.record(
        session_id, EventType.OUTPUT, {"text": "a\x00b", "nested": {"k": [1, None, True]}}
    )
    await harness.drain()

    rows = await harness.fetch(
        "SELECT seq, event_type, payload, occurred_at FROM events"
        " WHERE session_id = %s ORDER BY seq",
        (session_id,),
    )
    assert [(r[0], r[1], r[2]) for r in rows] == [
        (0, "connect", {"banner": "SSH-2.0-test"}),
        (1, "command", {"input": "ls -la", "n": 1}),
        # safe_text turned the NUL into visible text before it reached the database.
        (2, "output", {"text": "a\\x00b", "nested": {"k": [1, None, True]}}),
    ]
    for _, _, _, occurred_at in rows:
        assert occurred_at.utcoffset() == timedelta(0)
        assert occurred_at.microsecond % 1000 == 0

    notes = await harness.notifications(3)
    assert [n.channel for n in notes] == [CHANNEL] * 3
    payloads = [json.loads(n.payload) for n in notes]
    # IDs only, never event contents.
    assert payloads == [{"session_id": str(session_id), "seq": seq} for seq in (0, 1, 2)]
    assert all(list(p) == ["session_id", "seq"] for p in payloads)


@requires_database
async def test_r5_8_session_row_and_close_out_do_not_notify(harness: Harness) -> None:
    session_id = _start(harness.recorder)
    harness.recorder.authenticated(session_id, "root")
    harness.recorder.end(session_id, EndReason.DISCONNECT, 0)
    await harness.drain()
    # Follow with one event on a second session; its notification must be the first one
    # received, proving the row insert and close-out above sent none.
    second = _start(harness.recorder)
    harness.recorder.authenticated(second, "root")
    harness.recorder.record(second, EventType.CONNECT, {})
    await harness.drain()

    notes = await harness.notifications(1)
    assert [json.loads(n.payload) for n in notes] == [{"session_id": str(second), "seq": 0}]


# ---------------------------------------------------------------------------
# Close-out (R5.2)
# ---------------------------------------------------------------------------


@requires_database
async def test_r5_2_close_out_updates_only_the_closing_columns(harness: Harness) -> None:
    recorder = harness.recorder
    session_id = _start(recorder)
    recorder.authenticated(session_id, "root")
    assert recorder.record(session_id, EventType.COMMAND, {"input": "id"})
    recorder.end(session_id, EndReason.IDLE, 4)
    await harness.drain()

    rows = await harness.fetch(
        "SELECT started_at, ended_at, final_haunt_level, end_reason, username, auth_succeeded"
        " FROM sessions WHERE session_id = %s",
        (session_id,),
    )
    assert len(rows) == 1
    started_at, ended_at, haunt, reason, username, auth_succeeded = rows[0]
    assert ended_at is not None
    assert ended_at.utcoffset() == timedelta(0)
    assert ended_at.microsecond % 1000 == 0
    assert started_at <= ended_at <= datetime.now(UTC)
    assert haunt == 4
    assert reason == "idle"
    assert (username, auth_succeeded) == ("root", True)
    count = await harness.fetch("SELECT count(*) FROM events WHERE session_id = %s", (session_id,))
    assert count == [(1,)]


# ---------------------------------------------------------------------------
# Failing insert (R5.11)
# ---------------------------------------------------------------------------


@requires_database
async def test_r5_11_failing_insert_marks_session_failed_and_writer_keeps_running(
    harness: Harness, caplog: pytest.LogCaptureFixture
) -> None:
    recorder = harness.recorder
    first = _start(recorder)
    recorder.authenticated(first, "root")
    assert recorder.record(first, EventType.COMMAND, {"input": "whoami"})  # seq 0
    await harness.drain()

    # Queue a second row with the same (session_id, seq): the primary key rejects it.
    duplicate = EventRow(
        session_id=first,
        seq=0,
        occurred_at=utc_now_ms(),
        event_type=EventType.COMMAND,
        payload={"input": "duplicate"},
    )
    with caplog.at_level(logging.ERROR, logger="honeypot.writer"):
        recorder.queue.put_nowait(duplicate)
        await harness.drain()

    failures = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    assert failures == [f"RECORDER WRITE FAILED session_id={first}"]

    # mark_failed ran: the session refuses further events and closes as recording_failure.
    assert recorder.record(first, EventType.COMMAND, {"input": "after failure"}) is False
    recorder.end(first, EndReason.DISCONNECT, 2)
    await harness.drain()
    closed = await harness.fetch(
        "SELECT end_reason, final_haunt_level FROM sessions WHERE session_id = %s", (first,)
    )
    assert closed == [("recording_failure", 2)]

    # The duplicate was rejected whole: the original row is unchanged, and no row was added.
    events = await harness.fetch(
        "SELECT seq, payload FROM events WHERE session_id = %s ORDER BY seq", (first,)
    )
    assert events == [(0, {"input": "whoami"})]

    # The writer is still running: another session is recorded normally afterwards.
    second = _start(recorder)
    recorder.authenticated(second, "admin")
    assert recorder.record(second, EventType.COMMAND, {"input": "uname -a"})
    recorder.end(second, EndReason.DISCONNECT, 0)
    await harness.drain()
    rows = await harness.fetch(
        "SELECT s.username, s.end_reason, e.seq, e.payload FROM sessions s"
        " JOIN events e USING (session_id) WHERE s.session_id = %s",
        (second,),
    )
    assert rows == [("admin", "disconnect", 0, {"input": "uname -a"})]

    # Only the two successful event inserts notified; the failed insert rolled back.
    notes = await harness.notifications(2)
    assert [json.loads(n.payload) for n in notes] == [
        {"session_id": str(first), "seq": 0},
        {"session_id": str(second), "seq": 0},
    ]


# ---------------------------------------------------------------------------
# open_pool
# ---------------------------------------------------------------------------


def _closed_local_port() -> int:
    """A port nothing listens on: bind to port 0, note it, release it."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def test_r5_11_open_pool_raises_pool_timeout_for_unreachable_database() -> None:
    port = _closed_local_port()
    url = (
        f"postgresql://honeypot_writer:fake-password@127.0.0.1:{port}/nodb"
        "?connect_timeout=2&sslmode=disable"
    )
    with pytest.raises(PoolTimeout):
        await open_pool(url)
