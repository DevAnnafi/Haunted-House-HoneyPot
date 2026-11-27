import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID

from shared.events import (
    EndReason,
    EventRow,
    EventType,
    QueueItem,
    SessionClose,
    SessionRow,
    utc_now_ms,
)

log = logging.getLogger(__name__)


@dataclass
class _SessionState:
    session_id: UUID
    client_ip: str
    client_port: int
    client_version: str | None
    started_at: datetime
    next_seq: int = 0
    recorded_bytes: int = 0
    inserted: bool = False
    fail_reason: EndReason | None = None
    buffer: list[EventRow] = field(default_factory=list)


def safe_text(text: str) -> str:
    return text.encode("utf-8", "backslashreplace").decode("utf-8").replace("\x00", "\\x00")


class Recorder:
    def __init__(self, max_queue: int = 10_000, session_cap_bytes: int = 10 * 1024 * 1024) -> None:
        self.queue: asyncio.Queue[QueueItem] = asyncio.Queue(maxsize=max_queue)
        self._sessions: dict[UUID, _SessionState] = {}
        self._session_cap_bytes = session_cap_bytes

    def start(
        self,
        session_id: UUID,
        client_ip: str,
        client_port: int,
        client_version: str | None,
    ) -> None:
        self._sessions[session_id] = _SessionState(
            session_id=session_id,
            client_ip=client_ip,
            client_port=client_port,
            client_version=client_version,
            started_at=utc_now_ms(),
        )

    def set_client_version(self, session_id: UUID, client_version: str | None) -> None:
        state = self._sessions.get(session_id)
        if state is not None:
            state.client_version = client_version

    def record(self, session_id: UUID, event_type: EventType, payload: dict[str, Any]) -> bool:
        state = self._sessions.get(session_id)

        if state is None:
            return False

        if state.fail_reason is not None:
            return False

        clean = {
            key: safe_text(value) if isinstance(value, str) else value
            for key, value in payload.items()
        }

        # tests/test_shell.py recorded_size() mirrors this rule; keep them in sync
        size = len(json.dumps(clean, ensure_ascii=False).encode("utf-8"))

        if state.recorded_bytes + size > self._session_cap_bytes:
            state.fail_reason = EndReason.RECORDING_CAP
            return False

        row = EventRow(
            session_id=session_id,
            seq=state.next_seq,
            occurred_at=utc_now_ms(),
            event_type=event_type,
            payload=clean,
        )

        state.next_seq += 1
        state.recorded_bytes += size

        if not state.inserted:
            state.buffer.append(row)
            return True

        try:
            self.queue.put_nowait(row)
        except asyncio.QueueFull:
            state.fail_reason = EndReason.RECORDING_FAILURE
            return False

        return True

    def _flush(self, state: _SessionState, username: str | None, auth_succeeded: bool) -> None:
        row = SessionRow(
            session_id=state.session_id,
            client_ip=state.client_ip,
            client_port=state.client_port,
            client_version=state.client_version,
            started_at=state.started_at,
            username=safe_text(username) if username is not None else None,
            auth_succeeded=auth_succeeded,
        )
        state.inserted = True
        try:
            self.queue.put_nowait(row)
            for event in state.buffer:
                self.queue.put_nowait(event)
        except asyncio.QueueFull:
            state.fail_reason = EndReason.RECORDING_FAILURE
        state.buffer.clear()

    def authenticated(self, session_id: UUID, username: str) -> None:
        state = self._sessions.get(session_id)
        if state is None or state.inserted:
            return
        self._flush(state, username, auth_succeeded=True)

    def end(self, session_id: UUID, end_reason: EndReason, final_haunt_level: int) -> None:
        state = self._sessions.pop(session_id, None)
        if state is None:
            return
        if not state.inserted:
            self._flush(state, username=None, auth_succeeded=False)
        close = SessionClose(
            session_id=session_id,
            ended_at=utc_now_ms(),
            final_haunt_level=final_haunt_level,
            end_reason=state.fail_reason or end_reason,
        )
        try:
            self.queue.put_nowait(close)
        except asyncio.QueueFull:
            log.error("RECORDER CLOSE DROPPED session_id=%s", session_id)

    def mark_failed(self, session_id: UUID) -> None:
        state = self._sessions.get(session_id)
        if state is not None and state.fail_reason is None:
            state.fail_reason = EndReason.RECORDING_FAILURE
