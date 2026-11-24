from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID


class EventType(StrEnum):
    # Must match the events_event_type_valid CHECK in 001_initial.sql exactly.
    CONNECT = "connect"
    AUTH_ATTEMPT = "auth_attempt"
    COMMAND = "command"
    OUTPUT = "output"
    HAUNT_LEVEL = "haunt_level"
    HAUNT_EVENT = "haunt_event"
    LLM_REQUEST = "llm_request"
    DETECTION = "detection"
    FORWARD_DENIED = "forward_denied"
    LIMIT_REJECTED = "limit_rejected"
    TRUNCATED = "truncated"
    DISCONNECT = "disconnect"


class EndReason(StrEnum):
    DISCONNECT = "disconnect"
    IDLE = "idle"
    LIFETIME = "lifetime"
    RECORDING_CAP = "recording_cap"
    RECORDING_FAILURE = "recording_failure"
    AUTH_FAILURES = "auth_failures"
    LIMIT = "limit"


@dataclass(frozen=True)
class SessionRow:
    """One INSERT into sessions, made once authentication is decided."""

    session_id: UUID
    client_ip: str
    client_port: int
    client_version: str | None
    started_at: datetime
    username: str | None
    auth_succeeded: bool


@dataclass(frozen=True)
class EventRow:
    """One INSERT into events."""

    session_id: UUID
    seq: int
    occurred_at: datetime
    event_type: EventType
    payload: dict[str, Any]


@dataclass(frozen=True)
class SessionClose:
    """The close-out UPDATE on sessions (the only columns the writer may update)."""

    session_id: UUID
    ended_at: datetime
    final_haunt_level: int
    end_reason: EndReason


QueueItem = SessionRow | EventRow | SessionClose


def utc_now_ms() -> datetime:
    """The current UTC time, rounded down to whole milliseconds (R5.12)."""
    now = datetime.now(UTC)
    return now.replace(microsecond=now.microsecond // 1000 * 1000)
