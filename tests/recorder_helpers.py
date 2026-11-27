"""Shared helpers for tests that inspect what a Recorder put on its queue."""

import asyncio
from typing import Any

from honeypot.recorder import Recorder
from shared.events import EventRow, EventType, QueueItem, SessionClose, SessionRow


async def collect_session(recorder: Recorder, timeout: float = 10.0) -> list[QueueItem]:
    """Read the queue until the SessionClose arrives (the server ended the session)."""
    items: list[QueueItem] = []
    while True:
        item = await asyncio.wait_for(recorder.queue.get(), timeout)
        items.append(item)
        if isinstance(item, SessionClose):
            return items


def drain(recorder: Recorder) -> list[QueueItem]:
    """Everything currently on the queue, without waiting."""
    items: list[QueueItem] = []
    while not recorder.queue.empty():
        items.append(recorder.queue.get_nowait())
    return items


def events_of(items: list[QueueItem]) -> list[tuple[EventType, dict[str, Any]]]:
    """(event_type, payload) of every event, in queue order."""
    return [(i.event_type, i.payload) for i in items if isinstance(i, EventRow)]


def session_row(items: list[QueueItem]) -> SessionRow:
    rows = [i for i in items if isinstance(i, SessionRow)]
    assert len(rows) == 1
    return rows[0]


def session_close(items: list[QueueItem]) -> SessionClose:
    closes = [i for i in items if isinstance(i, SessionClose)]
    assert len(closes) == 1
    return closes[0]
