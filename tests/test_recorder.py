"""Tests for honeypot/recorder.py. No database: the recorder only fills an asyncio.Queue."""

import logging
from uuid import UUID, uuid4

import pytest
from hypothesis import given
from hypothesis import strategies as st

from honeypot.recorder import Recorder
from shared.events import (
    EndReason,
    EventRow,
    EventType,
    QueueItem,
    SessionClose,
    SessionRow,
)


def _new(max_queue: int = 1000, cap: int = 10 * 1024 * 1024) -> tuple[Recorder, UUID]:
    rec = Recorder(max_queue=max_queue, session_cap_bytes=cap)
    sid = uuid4()
    rec.start(sid, "203.0.113.7", 40000, "SSH-2.0-test")
    return rec, sid


def _drain(rec: Recorder) -> list[QueueItem]:
    items: list[QueueItem] = []
    while not rec.queue.empty():
        items.append(rec.queue.get_nowait())
    return items


# --- R5.8 / pre-auth buffering -------------------------------------------------


def test_r5_8_nothing_enqueued_before_authenticated() -> None:
    rec, sid = _new()
    assert rec.record(sid, EventType.CONNECT, {"n": 1}) is True
    assert rec.record(sid, EventType.AUTH_ATTEMPT, {"n": 2}) is True
    assert rec.queue.qsize() == 0


def test_r5_8_session_row_first_then_buffered_events_in_order() -> None:
    rec, sid = _new()
    rec.record(sid, EventType.CONNECT, {"n": 0})
    rec.record(sid, EventType.AUTH_ATTEMPT, {"n": 1})
    rec.authenticated(sid, "root")
    items = _drain(rec)
    assert len(items) == 3
    row = items[0]
    assert isinstance(row, SessionRow)
    assert row.username == "root"
    assert row.auth_succeeded is True
    assert row.session_id == sid
    events = items[1:]
    assert all(isinstance(e, EventRow) for e in events)
    assert [e.payload["n"] for e in events if isinstance(e, EventRow)] == [0, 1]
    assert [e.event_type for e in events if isinstance(e, EventRow)] == [
        EventType.CONNECT,
        EventType.AUTH_ATTEMPT,
    ]


def test_r5_8_events_after_auth_are_enqueued_immediately() -> None:
    rec, sid = _new()
    rec.authenticated(sid, "root")
    assert rec.queue.qsize() == 1
    assert rec.record(sid, EventType.COMMAND, {"n": 0}) is True
    assert rec.queue.qsize() == 2


# --- R5.8 sequence numbers -----------------------------------------------------


def test_r5_8_seq_starts_at_zero_and_increments_by_one() -> None:
    rec, sid = _new()
    for i in range(5):
        rec.record(sid, EventType.COMMAND, {"i": i})
    rec.authenticated(sid, "root")
    for i in range(5, 8):
        rec.record(sid, EventType.COMMAND, {"i": i})
    seqs = [item.seq for item in _drain(rec) if isinstance(item, EventRow)]
    assert seqs == list(range(8))


# --- Ending without auth -------------------------------------------------------


def test_r5_2_end_without_auth_flushes_row_events_then_close() -> None:
    rec, sid = _new()
    rec.record(sid, EventType.CONNECT, {"n": 0})
    rec.record(sid, EventType.DISCONNECT, {"n": 1})
    rec.end(sid, EndReason.DISCONNECT, 0)
    items = _drain(rec)
    assert len(items) == 4
    row = items[0]
    assert isinstance(row, SessionRow)
    assert row.auth_succeeded is False
    assert row.username is None
    assert [i.seq for i in items[1:3] if isinstance(i, EventRow)] == [0, 1]
    assert isinstance(items[1], EventRow)
    assert isinstance(items[2], EventRow)
    close = items[3]
    assert isinstance(close, SessionClose)
    assert close.end_reason == EndReason.DISCONNECT
    assert close.final_haunt_level == 0


def test_r5_2_end_after_auth_carries_reason_and_haunt_level() -> None:
    rec, sid = _new()
    rec.authenticated(sid, "root")
    rec.end(sid, EndReason.IDLE, 3)
    items = _drain(rec)
    assert isinstance(items[0], SessionRow)
    close = items[-1]
    assert isinstance(close, SessionClose)
    assert close.end_reason == EndReason.IDLE
    assert close.final_haunt_level == 3


# --- Size cap ------------------------------------------------------------------


def test_r5_10_cap_exceeded_fails_and_stays_failed() -> None:
    rec, sid = _new(cap=40)
    rec.authenticated(sid, "root")
    assert rec.record(sid, EventType.COMMAND, {"a": "x"}) is True
    assert rec.record(sid, EventType.COMMAND, {"a": "y" * 100}) is False
    # Even a tiny payload that would have fit is refused afterwards.
    assert rec.record(sid, EventType.COMMAND, {}) is False
    assert rec.record(sid, EventType.COMMAND, {"a": "z"}) is False
    rec.end(sid, EndReason.DISCONNECT, 1)
    items = _drain(rec)
    events = [i for i in items if isinstance(i, EventRow)]
    assert len(events) == 1
    close = items[-1]
    assert isinstance(close, SessionClose)
    assert close.end_reason == EndReason.RECORDING_CAP


def test_r5_10_cap_exceeded_pre_auth_is_reported_on_close() -> None:
    rec, sid = _new(cap=10)
    assert rec.record(sid, EventType.COMMAND, {"a": "x" * 50}) is False
    rec.end(sid, EndReason.DISCONNECT, 0)
    items = _drain(rec)
    assert isinstance(items[0], SessionRow)
    assert isinstance(items[-1], SessionClose)
    assert items[-1].end_reason == EndReason.RECORDING_CAP
    assert not any(isinstance(i, EventRow) for i in items)


# --- R5.11 fail closed ---------------------------------------------------------


def test_r5_11_full_queue_fails_closed_with_recording_failure() -> None:
    rec, sid = _new(max_queue=1)
    rec.authenticated(sid, "root")  # SessionRow fills the queue
    assert rec.queue.qsize() == 1
    assert rec.record(sid, EventType.COMMAND, {"n": 0}) is False
    # Later records are refused too.
    assert rec.record(sid, EventType.COMMAND, {"n": 1}) is False
    # Make room so the close can be enqueued and inspected.
    _drain(rec)
    rec.end(sid, EndReason.DISCONNECT, 0)
    items = _drain(rec)
    assert len(items) == 1
    close = items[0]
    assert isinstance(close, SessionClose)
    assert close.end_reason == EndReason.RECORDING_FAILURE


def test_r5_11_mark_failed_sets_recording_failure() -> None:
    rec, sid = _new()
    rec.authenticated(sid, "root")
    rec.mark_failed(sid)
    assert rec.record(sid, EventType.COMMAND, {"n": 0}) is False
    rec.end(sid, EndReason.DISCONNECT, 0)
    close = _drain(rec)[-1]
    assert isinstance(close, SessionClose)
    assert close.end_reason == EndReason.RECORDING_FAILURE


def test_r5_11_mark_failed_does_not_overwrite_existing_reason() -> None:
    rec, sid = _new(cap=10)
    rec.authenticated(sid, "root")
    assert rec.record(sid, EventType.COMMAND, {"a": "x" * 50}) is False
    rec.mark_failed(sid)
    rec.end(sid, EndReason.DISCONNECT, 0)
    close = _drain(rec)[-1]
    assert isinstance(close, SessionClose)
    assert close.end_reason == EndReason.RECORDING_CAP


def test_r5_11_dropped_close_is_logged_and_session_is_removed(
    caplog: pytest.LogCaptureFixture,
) -> None:
    rec, sid = _new(max_queue=1)
    rec.authenticated(sid, "root")  # SessionRow fills the queue
    assert rec.queue.full()

    with caplog.at_level(logging.ERROR, logger="honeypot.recorder"):
        rec.end(sid, EndReason.DISCONNECT, 0)  # must not raise

    messages = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    assert messages == [f"RECORDER CLOSE DROPPED session_id={sid}"]
    # Only the original SessionRow is in the queue; the close was dropped.
    items = _drain(rec)
    assert len(items) == 1
    assert isinstance(items[0], SessionRow)
    # The session is gone even though the close was dropped.
    assert rec.record(sid, EventType.COMMAND, {"n": 0}) is False


# --- Safe text -----------------------------------------------------------------


def test_r5_3_safe_text_escapes_nul_and_lone_surrogates_in_payload() -> None:
    rec, sid = _new()
    rec.authenticated(sid, "root")
    assert rec.record(sid, EventType.COMMAND, {"cmd": "a\x00b\udc80c"}) is True
    event = _drain(rec)[1]
    assert isinstance(event, EventRow)
    assert event.payload["cmd"] == "a\\x00b\\udc80c"
    # The stored text must be encodable as UTF-8 without NUL.
    event.payload["cmd"].encode("utf-8")


def test_r5_4_safe_text_escapes_username() -> None:
    rec, sid = _new()
    rec.authenticated(sid, "ro\x00ot\udc80")
    row = _drain(rec)[0]
    assert isinstance(row, SessionRow)
    assert row.username == "ro\\x00ot\\udc80"


def test_r5_3_safe_text_leaves_non_string_values_unchanged() -> None:
    rec, sid = _new()
    rec.authenticated(sid, "root")
    payload = {"i": 7, "f": 1.5, "b": True, "n": None, "l": [1, "x"], "d": {"k": "v"}}
    assert rec.record(sid, EventType.COMMAND, payload) is True
    event = _drain(rec)[1]
    assert isinstance(event, EventRow)
    assert event.payload == payload


def test_r5_3_safe_text_leaves_ordinary_text_unchanged() -> None:
    rec, sid = _new()
    rec.authenticated(sid, "root")
    rec.record(sid, EventType.COMMAND, {"cmd": "ls -la /tmp é👻"})
    event = _drain(rec)[1]
    assert isinstance(event, EventRow)
    assert event.payload["cmd"] == "ls -la /tmp é👻"


# --- Unknown sessions ----------------------------------------------------------


def test_r5_11_unknown_session_record_returns_false() -> None:
    rec = Recorder()
    assert rec.record(uuid4(), EventType.COMMAND, {"n": 0}) is False
    assert rec.queue.qsize() == 0


def test_r5_11_unknown_session_other_calls_are_noops() -> None:
    rec = Recorder()
    sid = uuid4()
    rec.authenticated(sid, "root")
    rec.end(sid, EndReason.DISCONNECT, 0)
    rec.mark_failed(sid)
    assert rec.queue.qsize() == 0


def test_r5_11_record_after_end_returns_false() -> None:
    rec, sid = _new()
    rec.end(sid, EndReason.DISCONNECT, 0)
    _drain(rec)
    assert rec.record(sid, EventType.COMMAND, {"n": 0}) is False


# --- Repeated calls ------------------------------------------------------------


def test_r5_2_authenticated_twice_enqueues_row_once() -> None:
    rec, sid = _new()
    rec.record(sid, EventType.CONNECT, {"n": 0})
    rec.authenticated(sid, "root")
    rec.authenticated(sid, "admin")
    items = _drain(rec)
    rows = [i for i in items if isinstance(i, SessionRow)]
    assert len(rows) == 1
    assert rows[0].username == "root"
    assert len([i for i in items if isinstance(i, EventRow)]) == 1


def test_r5_2_end_twice_is_harmless() -> None:
    rec, sid = _new()
    rec.authenticated(sid, "root")
    rec.end(sid, EndReason.DISCONNECT, 1)
    rec.end(sid, EndReason.IDLE, 2)
    items = _drain(rec)
    closes = [i for i in items if isinstance(i, SessionClose)]
    assert len(closes) == 1
    assert closes[0].end_reason == EndReason.DISCONNECT


# --- Property test -------------------------------------------------------------

_payloads = st.dictionaries(
    st.text(max_size=5),
    st.one_of(st.text(max_size=20), st.integers(), st.none()),
    max_size=3,
)


@given(
    payloads=st.lists(_payloads, max_size=30),
    auth_at=st.one_of(st.none(), st.integers(min_value=0, max_value=30)),
    end_after=st.booleans(),
)
def test_r5_8_seq_is_gapless_and_session_row_comes_first(
    payloads: list[dict[str, object]], auth_at: int | None, end_after: bool
) -> None:
    rec, sid = _new()
    for index, payload in enumerate(payloads):
        if auth_at is not None and index == auth_at:
            rec.authenticated(sid, "root")
        assert rec.record(sid, EventType.COMMAND, payload) is True
    if auth_at is not None and auth_at >= len(payloads):
        rec.authenticated(sid, "root")
    if end_after:
        rec.end(sid, EndReason.DISCONNECT, 0)

    items = _drain(rec)
    if auth_at is None and not end_after:
        # Never flushed: everything is still buffered, nothing is enqueued.
        assert items == []
        return

    events = [i for i in items if isinstance(i, EventRow)]
    assert [e.seq for e in events] == list(range(len(payloads)))
    assert isinstance(items[0], SessionRow)
    assert sum(isinstance(i, SessionRow) for i in items) == 1
