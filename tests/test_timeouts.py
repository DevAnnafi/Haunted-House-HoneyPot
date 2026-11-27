"""Idle and lifetime timeout tests (R8.4, R8.5) with real connections and short timeouts.

Each test starts a real server through create_honeypot_server on port 0 with a temporary
host key, as in test_shell.py. Credentials and keys are generated per test or obviously
fake; no real .env, host key or config/credentials.toml is read.
"""

import asyncio
import contextlib
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from functools import partial
from pathlib import Path

import asyncssh
import pytest

from honeypot.auth import AuthPolicy
from honeypot.limits import AdmissionController
from honeypot.recorder import Recorder
from honeypot.shell import handle_process
from honeypot.ssh_server import create_honeypot_server
from honeypot.vfs import load_template
from shared.events import EndReason, SessionClose
from tests.recorder_helpers import collect_session, drain, session_close

# Obviously fake test-only values.
FAKE_SECRET_HEX = "deadbeef" * 8
DEMO_USER = "demo-user"
DEMO_PASS = "demo-pass-not-real"
LISTED_USER = "root"
LISTED_PASS = "123456"
CREDENTIALS_TOML = f'[[credentials]]\nusername = "{LISTED_USER}"\npassword = "{LISTED_PASS}"\n'
LOOPBACK = "127.0.0.1"
CLIENT_TIMEOUT = 10.0
ROOT_PROMPT = "root@web-prod-01:~# "

# Short timeouts so the tests stay fast. The activity interval must be well under IDLE.
IDLE = 1.0
LONG = 60.0  # a limit that must never fire during the test
ACTIVITY_INTERVAL = 0.3
# Slack for event-loop and timer jitter when comparing elapsed times.
SLACK = 0.5

BASE_ROOT = load_template(Path("config/fs_template.toml"))


def make_policy(directory: Path) -> AuthPolicy:
    path = directory / "credentials.toml"
    path.write_text(CREDENTIALS_TOML, encoding="utf-8")
    return AuthPolicy(path, FAKE_SECRET_HEX, DEMO_USER, DEMO_PASS)


def write_host_key(directory: Path) -> Path:
    key_path = directory / "test_host_key"
    key = asyncssh.generate_private_key("ssh-ed25519")
    key.write_private_key(str(key_path))
    return key_path


@asynccontextmanager
async def running_server(
    tmp_path: Path, recorder: Recorder, idle_timeout: float, session_lifetime: float
) -> AsyncIterator[int]:
    acceptor = await create_honeypot_server(
        make_policy(tmp_path),
        AdmissionController(),
        LOOPBACK,
        0,
        write_host_key(tmp_path),
        partial(handle_process, base_root=BASE_ROOT, recorder=recorder),
        recorder,
        idle_timeout=idle_timeout,
        session_lifetime=session_lifetime,
    )
    try:
        yield acceptor.get_port()
    finally:
        acceptor.close()
        await acceptor.wait_closed()


async def connect(port: int) -> asyncssh.SSHClientConnection:
    # Explicit options so the client never reads the developer's ~/.ssh or agent.
    return await asyncio.wait_for(
        asyncssh.connect(
            LOOPBACK,
            port,
            username=LISTED_USER,
            password=LISTED_PASS,
            known_hosts=None,
            client_keys=None,
            agent_path=None,
            config=None,
            preferred_auth="password",
            keepalive_interval=0,
        ),
        CLIENT_TIMEOUT,
    )


async def read_prompt(process: asyncssh.SSHClientProcess) -> None:
    prompt = await asyncio.wait_for(process.stdout.readuntil(" "), CLIENT_TIMEOUT)
    assert prompt == ROOT_PROMPT


async def keep_doing(action, interval: float = ACTIVITY_INTERVAL) -> None:
    """Call ``action`` every ``interval`` seconds until cancelled or the connection is gone."""
    while True:
        try:
            action()
        except (asyncssh.Error, OSError):
            return
        await asyncio.sleep(interval)


async def stop(task: asyncio.Task) -> None:
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


def no_close_yet(recorder: Recorder) -> None:
    """Assert that the session has not been ended. Consumes what is on the queue."""
    items = drain(recorder)
    assert [i for i in items if isinstance(i, SessionClose)] == []


# ---------------------------------------------------------------------------
# R8.4: idle timeout
# ---------------------------------------------------------------------------


async def test_r8_4_idle_interactive_shell_closes_with_idle(tmp_path):
    recorder = Recorder()
    async with running_server(tmp_path, recorder, IDLE, LONG) as port:
        async with await connect(port) as conn:
            process = await conn.create_process()
            try:
                await read_prompt(process)
                start = time.monotonic()
                items = await collect_session(recorder, CLIENT_TIMEOUT)
                elapsed = time.monotonic() - start
                assert session_close(items).end_reason == EndReason.IDLE
                assert elapsed >= IDLE - SLACK
                await asyncio.wait_for(conn.wait_closed(), CLIENT_TIMEOUT)
            finally:
                process.close()


async def test_r8_4_logged_in_connection_with_no_channel_closes_with_idle(tmp_path):
    recorder = Recorder()
    async with running_server(tmp_path, recorder, IDLE, LONG) as port:
        async with await connect(port) as conn:
            # Authenticated, but never opens a session channel.
            items = await collect_session(recorder, CLIENT_TIMEOUT)
            assert session_close(items).end_reason == EndReason.IDLE
            await asyncio.wait_for(conn.wait_closed(), CLIENT_TIMEOUT)


async def test_r8_4_terminal_resize_resets_the_idle_timer(tmp_path):
    recorder = Recorder()
    async with running_server(tmp_path, recorder, IDLE, LONG) as port:
        async with await connect(port) as conn:
            process = await conn.create_process(term_type="xterm", term_size=(80, 24))
            try:
                await read_prompt(process)
                sizes = iter(range(100, 10_000))
                resizer = asyncio.create_task(
                    keep_doing(lambda: process.change_terminal_size(next(sizes), 30))
                )
                try:
                    # More than two idle periods of resizing and nothing else.
                    await asyncio.sleep(IDLE * 2.5)
                    no_close_yet(recorder)
                finally:
                    await stop(resizer)
                # Once the resizing stops, the idle timer runs out.
                items = await collect_session(recorder, CLIENT_TIMEOUT)
                assert session_close(items).end_reason == EndReason.IDLE
            finally:
                process.close()


async def test_r8_4_ctrl_c_resets_the_idle_timer(tmp_path):
    recorder = Recorder()
    async with running_server(tmp_path, recorder, IDLE, LONG) as port:
        async with await connect(port) as conn:
            process = await conn.create_process()
            try:
                await read_prompt(process)
                breaker = asyncio.create_task(keep_doing(lambda: process.send_break(100)))
                try:
                    await asyncio.sleep(IDLE * 2.5)
                    no_close_yet(recorder)
                finally:
                    await stop(breaker)
                items = await collect_session(recorder, CLIENT_TIMEOUT)
                assert session_close(items).end_reason == EndReason.IDLE
            finally:
                process.close()


# ---------------------------------------------------------------------------
# R8.5: session lifetime
# ---------------------------------------------------------------------------


async def test_r8_5_regular_input_keeps_the_session_open_until_the_lifetime_limit(tmp_path):
    lifetime = IDLE * 3
    recorder = Recorder()
    async with running_server(tmp_path, recorder, IDLE, lifetime) as port:
        async with await connect(port) as conn:
            process = await conn.create_process()
            try:
                await read_prompt(process)
                start = time.monotonic()
                typist = asyncio.create_task(keep_doing(lambda: process.stdin.write("whoami\n")))
                try:
                    items = await collect_session(recorder, CLIENT_TIMEOUT)
                finally:
                    await stop(typist)
                elapsed = time.monotonic() - start
                # LIFETIME, not IDLE: the input kept the idle timer from firing.
                assert session_close(items).end_reason == EndReason.LIFETIME
                # It outlasted the idle timeout and was cut off near the lifetime limit.
                assert elapsed > IDLE
                assert elapsed >= lifetime - SLACK
                await asyncio.wait_for(conn.wait_closed(), CLIENT_TIMEOUT)
            finally:
                process.close()


# ---------------------------------------------------------------------------
# R8.4 and R8.5: no timer fires after the connection is closed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("how", ["exit", "client_close"])
async def test_r8_5_no_timer_fires_after_the_connection_is_closed(tmp_path, caplog, how):
    idle, lifetime = 0.4, 0.8
    recorder = Recorder()
    caplog.set_level(logging.DEBUG, logger="honeypot")
    loop = asyncio.get_running_loop()
    loop_errors: list[dict] = []
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, context: loop_errors.append(context))
    try:
        async with running_server(tmp_path, recorder, idle, lifetime) as port:
            conn = await connect(port)
            try:
                process = await conn.create_process()
                await read_prompt(process)
                if how == "exit":
                    process.stdin.write("exit\n")
                    await asyncio.wait_for(process.wait(check=False), CLIENT_TIMEOUT)
                conn.close()
                await asyncio.wait_for(conn.wait_closed(), CLIENT_TIMEOUT)
            finally:
                conn.close()
            # Past both timeouts, so a timer that was left running would have fired.
            await asyncio.sleep(lifetime + idle + SLACK)
            close = session_close(drain(recorder))
            assert close.end_reason == EndReason.DISCONNECT
    finally:
        loop.set_exception_handler(previous_handler)
    assert loop_errors == []
    assert [r.getMessage() for r in caplog.records if "SESSION TIMEOUT" in r.getMessage()] == []
