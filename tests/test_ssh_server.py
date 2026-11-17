"""Tests for honeypot/ssh_server.py (T1.7).

Satisfies R1.1, R1.5, R1.6, R1.9, R1.10, R1.13, R8.2, R8.7 (R8.8 skipped until T1.10).

All secrets, keys, and credentials here are generated per test or obviously fake.
No real .env, host key, or config/credentials.toml is read.
"""

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import asyncssh
import pytest
from hypothesis import given
from hypothesis import strategies as st

from honeypot.auth import AuthPolicy
from honeypot.limits import AdmissionController
from honeypot.ssh_server import MAX_FAILED_ATTEMPTS, HoneypotServer, create_honeypot_server

# Obviously fake test-only values.
FAKE_SECRET_HEX = "deadbeef" * 8
DEMO_USER = "demo-user"
DEMO_PASS = "demo-pass-not-real"
LISTED_USER = "root"
LISTED_PASS = "123456"
CREDENTIALS_TOML = f'[[credentials]]\nusername = "{LISTED_USER}"\npassword = "{LISTED_PASS}"\n'
EXPECTED_SERVER_VERSION = "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"
LOOPBACK = "127.0.0.1"
CLIENT_TIMEOUT = 10.0


def make_policy(directory: Path) -> AuthPolicy:
    path = directory / "credentials.toml"
    path.write_text(CREDENTIALS_TOML, encoding="utf-8")
    return AuthPolicy(path, FAKE_SECRET_HEX, DEMO_USER, DEMO_PASS)


def write_host_key(directory: Path) -> Path:
    key_path = directory / "test_host_key"
    key = asyncssh.generate_private_key("ssh-ed25519")
    key.write_private_key(str(key_path))
    return key_path


async def echo_process_factory(process: asyncssh.SSHServerProcess) -> None:
    process.stdout.write(f"you ran: {process.command}\n")
    process.exit(0)


@asynccontextmanager
async def running_server(
    tmp_path: Path, admission: AdmissionController | None = None
) -> AsyncIterator[tuple[int, AdmissionController]]:
    admission = admission if admission is not None else AdmissionController()
    acceptor = await create_honeypot_server(
        make_policy(tmp_path),
        admission,
        LOOPBACK,
        0,
        write_host_key(tmp_path),
        echo_process_factory,
    )
    try:
        port = acceptor.get_port()
        yield port, admission
    finally:
        acceptor.close()
        await acceptor.wait_closed()


async def connect(
    port: int, username: str = LISTED_USER, password: str = LISTED_PASS
) -> asyncssh.SSHClientConnection:
    # Explicit options so the client never reads the developer's ~/.ssh or agent.
    return await asyncio.wait_for(
        asyncssh.connect(
            LOOPBACK,
            port,
            username=username,
            password=password,
            known_hosts=None,
            client_keys=None,
            agent_path=None,
            config=None,
            preferred_auth="password",
        ),
        CLIENT_TIMEOUT,
    )


# ---------------------------------------------------------------------------
# Integration tests (asyncssh client against a real server on port 0)
# ---------------------------------------------------------------------------


async def test_r1_1_r1_9_listed_credentials_log_in_and_exec_returns_output(tmp_path):
    async with running_server(tmp_path) as (port, _admission):
        async with await connect(port) as conn:
            result = await asyncio.wait_for(conn.run("whoami", check=False), CLIENT_TIMEOUT)
            assert result.stdout == "you ran: whoami\n"
            assert result.exit_status == 0


async def test_r1_6_wrong_password_is_rejected(tmp_path):
    async with running_server(tmp_path) as (port, _admission):
        with pytest.raises(asyncssh.PermissionDenied):
            await connect(port, LISTED_USER, "not-the-password")


async def test_r1_13_server_advertises_configured_openssh_version(tmp_path):
    async with running_server(tmp_path) as (port, _admission):
        async with await connect(port) as conn:
            version = conn.get_extra_info("server_version")
            assert version == f"SSH-2.0-{EXPECTED_SERVER_VERSION}"
            assert "asyncssh" not in version.lower()


def forward_denied_messages(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.levelno == logging.WARNING and r.getMessage().startswith("FORWARD DENIED")
    ]


async def test_r1_10_local_port_forwarding_is_refused(tmp_path, caplog):
    caplog.set_level(logging.DEBUG, logger="honeypot.ssh_server")
    async with running_server(tmp_path) as (port, _admission):
        async with await connect(port) as conn:
            # Direct channel open is refused by the server.
            with pytest.raises(asyncssh.ChannelOpenError):
                await asyncio.wait_for(conn.open_connection(LOOPBACK, 9), CLIENT_TIMEOUT)

            # forward_local_port opens a client-side listener; the server refusal shows up
            # when something connects through it: the tunnel closes with no data.
            listener = await conn.forward_local_port(LOOPBACK, 0, LOOPBACK, 9)
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(LOOPBACK, listener.get_port()), CLIENT_TIMEOUT
                )
                try:
                    data = await asyncio.wait_for(reader.read(1), CLIENT_TIMEOUT)
                    assert data == b""
                finally:
                    writer.close()
            finally:
                listener.close()
                await listener.wait_closed()

    # One denial per attempt (direct open, then the tunnel), each with client IP and target.
    expected = f"FORWARD DENIED type=local ip={LOOPBACK} dest='{LOOPBACK}':9"
    assert forward_denied_messages(caplog) == [expected, expected]


async def test_r1_10_remote_port_forwarding_is_refused(tmp_path, caplog):
    caplog.set_level(logging.DEBUG, logger="honeypot.ssh_server")
    async with running_server(tmp_path) as (port, _admission):
        async with await connect(port) as conn:
            with pytest.raises(asyncssh.ChannelListenError):
                await asyncio.wait_for(
                    conn.forward_remote_port("0.0.0.0", 2222, LOOPBACK, 9), CLIENT_TIMEOUT
                )

    assert forward_denied_messages(caplog) == [
        f"FORWARD DENIED type=remote ip={LOOPBACK} listen='0.0.0.0':2222"
    ]


async def test_r1_11_sftp_is_refused(tmp_path):
    async with running_server(tmp_path) as (port, _admission):
        async with await connect(port) as conn:
            with pytest.raises(asyncssh.Error):
                await asyncio.wait_for(conn.start_sftp_client(), CLIENT_TIMEOUT)


async def test_r1_11_scp_is_refused(tmp_path):
    commands: list[str] = []

    async def recording_factory(process: asyncssh.SSHServerProcess) -> None:
        commands.append(process.command)
        process.exit(1)

    acceptor = await create_honeypot_server(
        make_policy(tmp_path),
        AdmissionController(),
        LOOPBACK,
        0,
        write_host_key(tmp_path),
        recording_factory,
    )
    try:
        async with await connect(acceptor.get_port()) as conn:
            with pytest.raises(asyncssh.Error):
                await asyncio.wait_for(
                    asyncssh.scp((conn, "/etc/passwd"), str(tmp_path / "copy")), CLIENT_TIMEOUT
                )
    finally:
        acceptor.close()
        await acceptor.wait_closed()
    # No local file was produced.
    assert not (tmp_path / "copy").exists()


async def test_r1_12_agent_forwarding_request_creates_no_agent_channel(tmp_path):
    seen: list[str | None] = []

    async def recording_factory(process: asyncssh.SSHServerProcess) -> None:
        seen.append(process.channel.get_agent_path())
        process.exit(0)

    acceptor = await create_honeypot_server(
        make_policy(tmp_path),
        AdmissionController(),
        LOOPBACK,
        0,
        write_host_key(tmp_path),
        recording_factory,
    )
    try:
        async with await asyncssh.connect(
            LOOPBACK,
            acceptor.get_port(),
            username=LISTED_USER,
            password=LISTED_PASS,
            known_hosts=None,
            client_keys=None,
            config=None,
            preferred_auth="password",
            # Never a real agent: point at a path that does not exist.
            agent_path=str(tmp_path / "no-such-agent.sock"),
            agent_forwarding=True,
        ) as conn:
            result = await asyncio.wait_for(conn.run("true", check=False), CLIENT_TIMEOUT)
            assert result.exit_status == 0
    finally:
        acceptor.close()
        await acceptor.wait_closed()
    assert seen == [None]


async def test_r1_12_x11_forwarding_request_is_refused(tmp_path):
    seen: list[str | None] = []

    async def recording_factory(process: asyncssh.SSHServerProcess) -> None:
        seen.append(process.channel.get_x11_display())
        process.exit(0)

    acceptor = await create_honeypot_server(
        make_policy(tmp_path),
        AdmissionController(),
        LOOPBACK,
        0,
        write_host_key(tmp_path),
        recording_factory,
    )
    try:
        async with await connect(acceptor.get_port()) as conn:
            with pytest.raises(asyncssh.ChannelOpenError):
                await asyncio.wait_for(
                    conn.run(
                        "true",
                        x11_forwarding=True,
                        x11_display=":0",
                        # Hermetic: never read the developer's real Xauthority file.
                        x11_auth_path=str(tmp_path / "Xauthority"),
                    ),
                    CLIENT_TIMEOUT,
                )
    finally:
        acceptor.close()
        await acceptor.wait_closed()
    # The refused request means no session ever started, so no X11 display was granted.
    assert seen == []


async def test_r8_2_second_connection_refused_then_accepted_after_first_closes(tmp_path):
    admission = AdmissionController(per_ip_limit=1)
    async with running_server(tmp_path, admission) as (port, _admission):
        first = await connect(port)
        try:
            with pytest.raises((asyncssh.Error, OSError)):
                await connect(port)
        finally:
            first.close()
            await first.wait_closed()

        # Release happens server-side when the first connection is lost; poll briefly.
        accepted = None
        for _ in range(50):
            try:
                accepted = await connect(port)
                break
            except (asyncssh.Error, OSError):
                await asyncio.sleep(0.05)
        assert accepted is not None, "slot was not released after the first connection closed"
        try:
            result = await asyncio.wait_for(accepted.run("id", check=False), CLIENT_TIMEOUT)
            assert result.stdout == "you ran: id\n"
        finally:
            accepted.close()
            await accepted.wait_closed()


async def test_r8_2_refused_connection_never_releases_a_slot(tmp_path):
    class SpyAdmission(AdmissionController):
        def __init__(self) -> None:
            super().__init__(per_ip_limit=1)
            self.released: list[str] = []

        def release(self, ip: str) -> None:
            self.released.append(ip)
            super().release(ip)

    admission = SpyAdmission()
    async with running_server(tmp_path, admission) as (port, _admission):
        first = await connect(port)
        try:
            assert admission._open_per_ip == {LOOPBACK: 1}
            assert admission._open_total == 1

            with pytest.raises((asyncssh.Error, OSError)):
                await connect(port)
            # Let the server finish tearing down the refused connection (in-process loop).
            await asyncio.sleep(0.2)

            assert admission.released == []
            assert admission._open_per_ip == {LOOPBACK: 1}
            assert admission._open_total == 1
        finally:
            first.close()
            await first.wait_closed()


# ---------------------------------------------------------------------------
# Unit tests (HoneypotServer methods with a fake connection)
# ---------------------------------------------------------------------------


class FakeConn:
    def __init__(self) -> None:
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1

    def get_extra_info(self, name: str, default=None):
        if name == "peername":
            return (LOOPBACK, 12345)
        return default


@pytest.fixture(scope="module")
def module_policy(tmp_path_factory) -> AuthPolicy:
    return make_policy(tmp_path_factory.mktemp("policy"))


def make_server(policy: AuthPolicy) -> tuple[HoneypotServer, FakeConn]:
    server = HoneypotServer(policy, AdmissionController())
    conn = FakeConn()
    server.connection_made(conn)
    assert conn.close_calls == 0
    return server, conn


def test_r8_7_five_failed_attempts_close_the_connection(module_policy):
    server, conn = make_server(module_policy)
    for _ in range(MAX_FAILED_ATTEMPTS):
        assert server.validate_password("attacker", "wrong") is False
    assert MAX_FAILED_ATTEMPTS == 5
    assert conn.close_calls == 1


def test_r8_7_four_failed_attempts_do_not_close_the_connection(module_policy):
    server, conn = make_server(module_policy)
    for _ in range(MAX_FAILED_ATTEMPTS - 1):
        assert server.validate_password("attacker", "wrong") is False
    assert conn.close_calls == 0


def test_r1_5_attempts_logged_with_fingerprint_and_never_the_password(module_policy, caplog):
    secret_password = "hunter2-attacker-guess"
    other_password = "another-secret-guess"
    server, _conn = make_server(module_policy)

    with caplog.at_level(logging.DEBUG, logger="honeypot.ssh_server"):
        caplog.clear()
        assert server.validate_password("mallory", secret_password) is False
        assert server.validate_password(LISTED_USER, LISTED_PASS) is True
        assert server.validate_password("mallory", other_password) is False

    auth_records = [r for r in caplog.records if r.getMessage().startswith("AUTH ")]
    messages = [r.getMessage() for r in auth_records]
    fp = module_policy.fingerprint
    assert messages == [
        f"AUTH FAILED ip={LOOPBACK} username='mallory' fingerprint={fp(secret_password)}",
        f"AUTH SUCCESS ip={LOOPBACK} username='root' fingerprint={fp(LISTED_PASS)}",
        f"AUTH FAILED ip={LOOPBACK} username='mallory' fingerprint={fp(other_password)}",
    ]

    # No password in any record: formatted message, raw args, or the rendered log text.
    for password in (secret_password, other_password, LISTED_PASS):
        assert password not in caplog.text
        for record in caplog.records:
            assert password not in record.getMessage()
            assert password not in repr(record.args)
            assert password not in repr(record.msg)


class _ListHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


@given(username=st.text())
def test_r1_5_auth_log_messages_are_single_line_for_any_username(module_policy, username):
    handler = _ListHandler()
    logger = logging.getLogger("honeypot.ssh_server")
    old_level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        server, _conn = make_server(module_policy)
        server.validate_password(username, "wrong")
    finally:
        logger.removeHandler(handler)
        logger.setLevel(old_level)

    auth_messages = [m for m in handler.messages if m.startswith("AUTH ")]
    assert len(auth_messages) == 1
    for message in auth_messages:
        assert "\n" not in message
        assert "\r" not in message
        assert "\x1b" not in message


@pytest.mark.skip(
    reason="R8.8: login_timeout is hard-coded to 15 s in create_honeypot_server; it becomes "
    "configurable in T1.10, then test that a short timeout closes an idle unauthenticated "
    "connection."
)
async def test_r8_8_setup_timeout_closes_unauthenticated_connection(tmp_path):
    raise AssertionError("unreachable until T1.10")
