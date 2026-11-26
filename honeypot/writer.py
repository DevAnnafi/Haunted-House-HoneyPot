import json
import logging

from psycopg import AsyncConnection
from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

from honeypot.recorder import Recorder
from shared.events import EventRow, QueueItem, SessionClose, SessionRow

log = logging.getLogger(__name__)


async def open_pool(database_url: str) -> AsyncConnectionPool:
    pool = AsyncConnectionPool(database_url, min_size=1, max_size=4, open=False)

    try:
        await pool.open(wait=True, timeout=10)
    except Exception:
        await pool.close()
        raise

    return pool


async def run_writer(recorder: Recorder, pool: AsyncConnectionPool) -> None:
    while True:
        item = await recorder.queue.get()

        try:
            async with pool.connection(timeout=5) as conn:
                await _write(conn, item)
        except Exception:
            log.exception("RECORDER WRITE FAILED session_id=%s", item.session_id)
            recorder.mark_failed(item.session_id)

        finally:
            recorder.queue.task_done()


async def _write(conn: AsyncConnection, item: QueueItem) -> None:
    if isinstance(item, SessionRow):
        await conn.execute(
            "INSERT INTO sessions (session_id, client_ip, client_port, client_version,"
            " started_at, username, auth_succeeded)"
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (
                item.session_id,
                item.client_ip,
                item.client_port,
                item.client_version,
                item.started_at,
                item.username,
                item.auth_succeeded,
            ),
        )
    elif isinstance(item, EventRow):
        await conn.execute(
            "INSERT INTO events (session_id, seq, occurred_at, event_type, payload)"
            " VALUES (%s, %s, %s, %s, %s)",
            (
                item.session_id,
                item.seq,
                item.occurred_at,
                item.event_type,
                Jsonb(item.payload),
            ),
        )
        await conn.execute(
            "SELECT pg_notify('honeypot_events', %s)",
            (json.dumps({"session_id": str(item.session_id), "seq": item.seq}),),
        )
    elif isinstance(item, SessionClose):
        await conn.execute(
            "UPDATE sessions SET ended_at = %s, final_haunt_level = %s,"
            " end_reason = %s WHERE session_id = %s",
            (item.ended_at, item.final_haunt_level, item.end_reason, item.session_id),
        )
