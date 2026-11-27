import asyncio
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import asyncssh

from honeypot.auth import AuthPolicy
from honeypot.limits import AdmissionController
from honeypot.recorder import Recorder
from shared.events import EndReason, EventType

log = logging.getLogger(__name__)
MAX_FAILED_ATTEMPTS = 5


class HoneypotServer(asyncssh.SSHServer):
    def __init__(
        self,
        auth: AuthPolicy,
        admission: AdmissionController,
        recorder: Recorder,
        idle_timeout: float,
        session_lifetime: float,
    ) -> None:
        super().__init__()
        self._auth = auth
        self._admission = admission
        self._recorder = recorder
        self._conn: asyncssh.SSHServerConnection | None = None
        self._client_ip: str | None = None
        self._admitted = False
        self._failed_attempts = 0
        self._session_id: UUID | None = None
        self._end_reason: EndReason | None = None
        self._idle_timeout = idle_timeout
        self._session_lifetime = session_lifetime
        self._idle_timer: asyncio.TimerHandle | None = None
        self._lifetime_timer: asyncio.TimerHandle | None = None
        self._closed = False

    def _record(self, event_type: EventType, payload: dict[str, Any]) -> None:
        # Fail closed (R5.11): a session that can't be recorded is ended.
        if self._session_id is None:
            return
        if not self._recorder.record(self._session_id, event_type, payload):
            if self._conn is not None:
                self._conn.close()

    def _expire(self, reason: EndReason) -> None:
        log.info("SESSION TIMEOUT ip=%s reason=%s", self._client_ip, reason)
        if self._end_reason is None:
            self._end_reason = reason
        if self._conn is not None:
            self._conn.close()

    def _touch(self) -> None:
        # Any client activity restarts the idle timer (R8.4). Once the connection
        # is gone, activity reported late by the shell must not start a new timer.
        if self._closed:
            return
        if self._idle_timer is not None:
            self._idle_timer.cancel()
        self._idle_timer = asyncio.get_running_loop().call_later(
            self._idle_timeout, self._expire, EndReason.IDLE
        )

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self._conn = conn
        peer = conn.get_extra_info("peername")
        self._client_ip = peer[0]

        if not self._admission.try_acquire(self._client_ip):
            log.warning("ADMISSION REJECTED ip=%s", self._client_ip)
            conn.close()
            return

        self._admitted = True
        log.info("ADMISSION ACCEPTED ip=%s", self._client_ip)

        # The lifetime limit counts from acceptance and never resets (R8.5).
        self._lifetime_timer = asyncio.get_running_loop().call_later(
            self._session_lifetime, self._expire, EndReason.LIFETIME
        )
        self._touch()

        self._session_id = uuid4()
        # The shell reads both: the session ID for recording, and touch to report
        # activity so an active interactive session isn't closed as idle.
        conn.set_extra_info(session_id=self._session_id, touch=self._touch)
        self._recorder.start(self._session_id, self._client_ip, peer[1], None)
        self._record(EventType.CONNECT, {})

    def connection_lost(self, exc: Exception | None) -> None:
        self._closed = True
        for timer in (self._idle_timer, self._lifetime_timer):
            if timer is not None:
                timer.cancel()
        self._idle_timer = None
        self._lifetime_timer = None
        if self._admitted:
            self._admission.release(self._client_ip)
            self._admitted = False
        if self._session_id is not None:
            reason = self._end_reason or EndReason.DISCONNECT
            self._recorder.end(self._session_id, reason, 0)
            self._session_id = None

    def begin_auth(self, username: str) -> bool:
        # The client's version string only arrives during the handshake.
        if self._session_id is not None and self._conn is not None:
            version = self._conn.get_extra_info("client_version")
            self._recorder.set_client_version(self._session_id, version)
        return True

    def password_auth_supported(self) -> bool:
        # AsyncSSH routes keyboard-interactive password responses
        # through validate_password(), sharing the same failure counter.
        return True

    def validate_password(self, username: str, password: str) -> bool:
        self._touch()
        success = self._auth.check(username, password)
        result = "SUCCESS" if success else "FAILED"
        fingerprint = self._auth.fingerprint(password)

        log.info(
            "AUTH %s ip=%s username=%r fingerprint=%s",
            result,
            self._client_ip,
            username,
            fingerprint,
        )
        # Never the password itself (ADR-0002).
        self._record(
            EventType.AUTH_ATTEMPT,
            {
                "username": username,
                "result": "success" if success else "failure",
                "fingerprint": fingerprint,
            },
        )

        if success:
            if self._session_id is not None:
                self._recorder.authenticated(self._session_id, username)
            return True

        self._failed_attempts += 1
        if self._failed_attempts >= MAX_FAILED_ATTEMPTS:
            log.warning(
                "AUTH LIMIT ip=%s failures=%d closing",
                self._client_ip,
                self._failed_attempts,
            )
            self._end_reason = EndReason.AUTH_FAILURES
            if self._conn is not None:
                self._conn.close()
        return False

    def connection_requested(
        self, dest_host: str, dest_port: int, orig_host: str, orig_port: int
    ) -> bool:
        log.warning(
            "FORWARD DENIED type=local ip=%s dest=%r:%s",
            self._client_ip,
            dest_host,
            dest_port,
        )
        self._record(
            EventType.FORWARD_DENIED,
            {"type": "local", "dest_host": dest_host, "dest_port": dest_port},
        )
        return False

    def server_requested(self, listen_host: str, listen_port: int) -> bool:
        log.warning(
            "FORWARD DENIED type=remote ip=%s listen=%r:%s",
            self._client_ip,
            listen_host,
            listen_port,
        )
        self._record(
            EventType.FORWARD_DENIED,
            {"type": "remote", "listen_host": listen_host, "listen_port": listen_port},
        )
        return False

    def unix_connection_requested(self, dest_path: str) -> bool:
        log.warning("FORWARD DENIED type=unix-local ip=%s dest=%r", self._client_ip, dest_path)
        self._record(EventType.FORWARD_DENIED, {"type": "unix-local", "dest_path": dest_path})
        return False

    def unix_server_requested(self, listen_path: str) -> bool:
        log.warning(
            "FORWARD DENIED type=unix-remote ip=%s listen=%r",
            self._client_ip,
            listen_path,
        )
        self._record(
            EventType.FORWARD_DENIED,
            {"type": "unix-remote", "listen_path": listen_path},
        )
        return False


async def create_honeypot_server(
    auth: AuthPolicy,
    admission: AdmissionController,
    host: str,
    port: int,
    host_key_path: Path,
    process_factory: Callable,
    recorder: Recorder,
    login_timeout: float = 15.0,
    idle_timeout: float = 300.0,
    session_lifetime: float = 1800.0,
) -> asyncssh.SSHAcceptor:
    return await asyncssh.create_server(
        lambda: HoneypotServer(auth, admission, recorder, idle_timeout, session_lifetime),
        host,
        port,
        server_host_keys=[str(host_key_path)],
        process_factory=process_factory,
        agent_forwarding=False,
        x11_forwarding=False,
        sftp_factory=None,
        allow_scp=False,
        login_timeout=login_timeout,
        rdns_lookup=False,
        max_line_length=4096,
        server_version="OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
    )
