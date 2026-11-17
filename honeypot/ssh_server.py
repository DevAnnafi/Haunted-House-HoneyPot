import logging
from collections.abc import Callable
from pathlib import Path

import asyncssh

from honeypot.auth import AuthPolicy
from honeypot.limits import AdmissionController

log = logging.getLogger(__name__)
MAX_FAILED_ATTEMPTS = 5


class HoneypotServer(asyncssh.SSHServer):
    def __init__(
        self,
        auth: AuthPolicy,
        admission: AdmissionController,
    ) -> None:
        super().__init__()
        self._auth = auth
        self._admission = admission
        self._conn = None
        self._client_ip = None
        self._admitted = False
        self._failed_attempts = 0

    def connection_made(
        self,
        conn: asyncssh.SSHServerConnection,
    ) -> None:
        self._conn = conn
        peer = conn.get_extra_info("peername")
        self._client_ip = peer[0]

        if not self._admission.try_acquire(self._client_ip):
            log.warning(
                "ADMISSION REJECTED ip=%s",
                self._client_ip,
            )
            self._conn.close()
            return

        self._admitted = True
        log.info(
            "ADMISSION ACCEPTED ip=%s",
            self._client_ip,
        )

    def connection_lost(self, exc: Exception | None) -> None:
        if self._admitted:
            self._admission.release(self._client_ip)
            self._admitted = False

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        # AsyncSSH routes keyboard-interactive password responses
        # through validate_password(), sharing the same failure counter.
        return True

    def validate_password(
        self,
        username: str,
        password: str,
    ) -> bool:
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

        if not success:
            self._failed_attempts += 1

            if self._failed_attempts >= MAX_FAILED_ATTEMPTS:
                log.warning(
                    "AUTH LIMIT ip=%s failures=%d closing",
                    self._client_ip,
                    self._failed_attempts,
                )
                self._conn.close()

        return success

    def connection_requested(
        self, dest_host: str, dest_port: int, orig_host: str, orig_port: int
    ) -> bool:
        log.warning(
            "FORWARD DENIED type=local ip=%s dest=%r:%s",
            self._client_ip,
            dest_host,
            dest_port,
        )
        return False

    def server_requested(self, listen_host: str, listen_port: int) -> bool:
        log.warning(
            "FORWARD DENIED type=remote ip=%s listen=%r:%s",
            self._client_ip,
            listen_host,
            listen_port,
        )
        return False

    def unix_connection_requested(self, dest_path: str) -> bool:
        log.warning("FORWARD DENIED type=unix-local ip=%s dest=%r", self._client_ip, dest_path)
        return False

    def unix_server_requested(self, listen_path: str) -> bool:
        log.warning("FORWARD DENIED type=unix-remote ip=%s listen=%r", self._client_ip, listen_path)
        return False


async def create_honeypot_server(
    auth: AuthPolicy,
    admission: AdmissionController,
    host: str,
    port: int,
    host_key_path: Path,
    process_factory: Callable,
) -> asyncssh.SSHAcceptor:
    return await asyncssh.create_server(
        lambda: HoneypotServer(auth, admission),
        host,
        port,
        server_host_keys=[str(host_key_path)],
        process_factory=process_factory,
        agent_forwarding=False,
        x11_forwarding=False,
        sftp_factory=None,
        allow_scp=False,
        login_timeout=15,
        rdns_lookup=False,
        max_line_length=4096,
        server_version="OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
    )
