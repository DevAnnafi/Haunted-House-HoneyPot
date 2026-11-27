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

    def _record(self, event_type: EventType, payload: dict[str, Any]) -> None:
        # Fail closed (R5.11): a session that can't be recorded is ended.
        if self._session_id is None:
            return
        if not self._recorder.record(self._session_id, event_type, payload):
            if self._conn is not None:
                self._conn.close()

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

        self._session_id = uuid4()
        conn.set_extra_info(session_id=self._session_id)
        self._recorder.start(self._session_id, self._client_ip, peer[1], None)
        self._record(EventType.CONNECT, {})

    def connection_lost(self, exc: Exception | None) -> None:
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
) -> asyncssh.SSHAcceptor:
    return await asyncssh.create_server(
        lambda: HoneypotServer(auth, admission, recorder),
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
