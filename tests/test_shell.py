"""Tests for run_exec, run_interactive and handle_process in honeypot/shell.py.

Satisfies R1.9 (exec), R8.6 (interactive session handling) and R4.9 (output sanitization),
plus the oversize-command logging rule (no command text in logs).

Each test starts a real server through create_honeypot_server on port 0 with a temporary
host key, as in test_ssh_server.py. Credentials and keys are generated per test or obviously
fake; no real .env, host key or config/credentials.toml is read.
"""

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from functools import partial
from pathlib import Path

import asyncssh
import pytest

from honeypot import shell
from honeypot.auth import AuthPolicy
from honeypot.commands.engine import CommandResult, Context
from honeypot.limits import AdmissionController
from honeypot.shell import MAX_COMMAND_BYTES, handle_process
from honeypot.ssh_server import create_honeypot_server
from honeypot.vfs import load_template

# Obviously fake test-only values.
FAKE_SECRET_HEX = "deadbeef" * 8
DEMO_USER = "demo-user"
DEMO_PASS = "demo-pass-not-real"
LISTED_USER = "root"
LISTED_PASS = "123456"
CREDENTIALS_TOML = f'[[credentials]]\nusername = "{LISTED_USER}"\npassword = "{LISTED_PASS}"\n'
LOOPBACK = "127.0.0.1"
CLIENT_TIMEOUT = 10.0
QUIET_WINDOW = 0.5  # seconds of silence that count as "nothing more was sent"

ROOT_PROMPT = "root@web-prod-01:~# "
# The template has no /home/demo-user, so the session falls back to "/" and the prompt shows it.
DEMO_PROMPT = f"{DEMO_USER}@web-prod-01:/$ "
TOO_LONG_MESSAGE = "-bash: command too long\n"

# Marker that must never appear in logs. Padded to the wanted size by the helpers below.
SECRET_MARKER = "SECRET-COMMAND-TEXT"

# The real fake-filesystem template. handle_process deep-copies it per session, so one
# shared instance is safe across tests.
BASE_ROOT = load_template(Path("config/fs_template.toml"))
PROCESS_FACTORY = partial(handle_process, base_root=BASE_ROOT)


def root_prompt(cwd_display: str) -> str:
    return f"root@web-prod-01:{cwd_display}# "


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
async def running_server(tmp_path: Path) -> AsyncIterator[int]:
    acceptor = await create_honeypot_server(
        make_policy(tmp_path),
        AdmissionController(),
        LOOPBACK,
        0,
        write_host_key(tmp_path),
        PROCESS_FACTORY,
    )
    try:
        yield acceptor.get_port()
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


async def read_until(process: asyncssh.SSHClientProcess, text: str) -> str:
    """Read from the client's stdout up to and including ``text``."""
    return await asyncio.wait_for(process.stdout.readuntil(text), CLIENT_TIMEOUT)


async def finish(process: asyncssh.SSHClientProcess) -> asyncssh.SSHCompletedProcess:
    return await asyncio.wait_for(process.wait(check=False), CLIENT_TIMEOUT)


def padded_command(total_bytes: int) -> str:
    """ASCII command of exactly ``total_bytes`` bytes that contains SECRET_MARKER."""
    prefix = f"echo {SECRET_MARKER} "
    return prefix + "a" * (total_bytes - len(prefix))


class ExecuteSpy:
    """Replaces shell.execute to record which lines reach the command engine."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def __call__(self, ctx: Context, line: str) -> CommandResult:
        self.calls.append(line)
        return CommandResult(stdout=f"ran:{line}\n")


@pytest.fixture
def execute_spy(monkeypatch: pytest.MonkeyPatch) -> ExecuteSpy:
    spy = ExecuteSpy()
    monkeypatch.setattr(shell, "execute", spy)
    return spy


def shell_log_messages(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.name == "honeypot.shell"]


# ---------------------------------------------------------------------------
# Exec (R1.9)
# ---------------------------------------------------------------------------


async def test_r1_9_exec_echo_returns_output_with_exit_status_0(tmp_path):
    async with running_server(tmp_path) as port:
        async with await connect(port) as conn:
            result = await asyncio.wait_for(conn.run("echo hello", check=False), CLIENT_TIMEOUT)
            assert result.stdout == "hello\n"
            assert result.stderr == ""
            assert result.exit_status == 0


async def test_r1_9_exec_command_of_exactly_4096_bytes_is_accepted(tmp_path):
    command = padded_command(MAX_COMMAND_BYTES)
    assert len(command.encode("utf-8")) == 4096
    async with running_server(tmp_path) as port:
        async with await connect(port) as conn:
            result = await asyncio.wait_for(conn.run(command, check=False), CLIENT_TIMEOUT)
            assert result.stdout == f"{command.removeprefix('echo ')}\n"
            assert result.stderr == ""
            assert result.exit_status == 0


async def test_r1_9_exec_command_of_4097_bytes_is_rejected(tmp_path):
    command = padded_command(MAX_COMMAND_BYTES + 1)
    assert len(command.encode("utf-8")) == 4097
    async with running_server(tmp_path) as port:
        async with await connect(port) as conn:
            result = await asyncio.wait_for(conn.run(command, check=False), CLIENT_TIMEOUT)
            assert result.stderr == TOO_LONG_MESSAGE
            assert result.stdout == ""
            assert result.exit_status == 1


async def test_r1_9_exec_multibyte_command_over_4096_bytes_is_rejected(tmp_path):
    # 1366 euro signs are 3 bytes each: 4098 bytes, but only 1366 characters.
    command = "\u20ac" * 1366
    assert len(command) < MAX_COMMAND_BYTES
    assert len(command.encode("utf-8")) == 4098
    async with running_server(tmp_path) as port:
        async with await connect(port) as conn:
            result = await asyncio.wait_for(conn.run(command, check=False), CLIENT_TIMEOUT)
            assert result.stderr == TOO_LONG_MESSAGE
            assert result.stdout == ""
            assert result.exit_status == 1


async def test_r1_9_exec_multibyte_command_of_exactly_4096_bytes_is_accepted(tmp_path):
    # 1365 euro signs (4095 bytes) plus one ASCII byte: exactly 4096 bytes.
    command = "\u20ac" * 1365 + "x"
    assert len(command.encode("utf-8")) == 4096
    async with running_server(tmp_path) as port:
        async with await connect(port) as conn:
            result = await asyncio.wait_for(conn.run(command, check=False), CLIENT_TIMEOUT)
            # Accepted, not rejected: the engine ran it and found no such command (127), not
            # the oversize error (exit 1). The exact name is not asserted because the parser
            # splits "\u20ac" into one token per character.
            assert result.stdout == ""
            assert result.stderr.startswith("-bash: ")
            assert result.stderr.endswith(": command not found\n")
            assert result.stderr != TOO_LONG_MESSAGE
            assert result.exit_status == 127


async def test_r4_9_exec_output_has_no_escape_character(tmp_path, execute_spy):
    # The spy echoes the line back, so the ESC and BEL bytes reach the sanitizer without
    # depending on how the parser tokenizes them.
    async with running_server(tmp_path) as port:
        async with await connect(port) as conn:
            result = await asyncio.wait_for(
                conn.run("echo \x1b[31mred\x1b]0;title\x07", check=False), CLIENT_TIMEOUT
            )
            assert "\x1b" not in result.stdout
            assert "\x07" not in result.stdout
            assert result.stdout == "ran:echo [31mred]0;title\n"
            assert result.exit_status == 0


# ---------------------------------------------------------------------------
# Interactive session (R8.6)
# ---------------------------------------------------------------------------


async def test_r8_6_root_prompt_is_root_at_web_prod_01(tmp_path):
    async with running_server(tmp_path) as port:
        async with await connect(port) as conn:
            process = await conn.create_process()
            try:
                assert await read_until(process, " ") == ROOT_PROMPT
                process.stdin.write("exit\n")
                result = await finish(process)
                assert result.stdout == "logout\n"
                assert result.exit_status == 0
            finally:
                process.close()


async def test_r8_6_non_root_prompt_ends_in_dollar(tmp_path):
    async with running_server(tmp_path) as port:
        async with await connect(port, DEMO_USER, DEMO_PASS) as conn:
            process = await conn.create_process()
            try:
                prompt = await read_until(process, " ")
                assert prompt == DEMO_PROMPT
                assert prompt.endswith("$ ")
                process.stdin.write("exit\n")
                result = await finish(process)
                assert result.exit_status == 0
            finally:
                process.close()


async def test_r8_6_empty_line_executes_nothing(tmp_path, execute_spy):
    async with running_server(tmp_path) as port:
        async with await connect(port) as conn:
            process = await conn.create_process()
            try:
                assert await read_until(process, " ") == ROOT_PROMPT
                # Empty and whitespace-only lines produce only a fresh prompt.
                process.stdin.write("\n")
                assert await read_until(process, " ") == ROOT_PROMPT
                process.stdin.write("   \t \n")
                assert await read_until(process, " ") == ROOT_PROMPT
                assert execute_spy.calls == []

                # A real command does reach execute, so the spy is wired up.
                process.stdin.write("whoami\n")
                assert await read_until(process, " ") == f"ran:whoami\n{ROOT_PROMPT}"
                assert execute_spy.calls == ["whoami"]

                process.stdin.write("exit\n")
                result = await finish(process)
                assert result.exit_status == 0
            finally:
                process.close()


async def test_r8_6_exit_prints_logout_and_closes_with_status_0(tmp_path, execute_spy):
    async with running_server(tmp_path) as port:
        async with await connect(port) as conn:
            process = await conn.create_process()
            try:
                assert await read_until(process, " ") == ROOT_PROMPT
                process.stdin.write("exit\n")
                result = await finish(process)
                assert result.stdout == "logout\n"
                assert result.exit_status == 0
                assert execute_spy.calls == []
            finally:
                process.close()


async def test_r8_6_eof_prints_logout_and_closes_with_status_0(tmp_path, execute_spy):
    async with running_server(tmp_path) as port:
        async with await connect(port) as conn:
            process = await conn.create_process()
            try:
                assert await read_until(process, " ") == ROOT_PROMPT
                process.stdin.write_eof()
                result = await finish(process)
                assert result.stdout == "logout\n"
                assert result.exit_status == 0
                assert execute_spy.calls == []
            finally:
                process.close()


async def read_quiet(process: asyncssh.SSHClientProcess, window: float = QUIET_WINDOW) -> str:
    """Return whatever the server sends within ``window`` seconds ("" if it stays silent)."""
    chunks: list[str] = []
    loop = asyncio.get_running_loop()
    deadline = loop.time() + window
    while (remaining := deadline - loop.time()) > 0:
        try:
            chunks.append(await asyncio.wait_for(process.stdout.read(1024), remaining))
        except TimeoutError:
            break
    return "".join(chunks)


@pytest.mark.parametrize("resizes", [1, 3])
async def test_r8_6_terminal_resize_sends_no_extra_prompt(tmp_path, execute_spy, resizes):
    async with running_server(tmp_path) as port:
        async with await connect(port) as conn:
            # A pty is needed for the client to send window-change requests. The pty line
            # editor echoes input and uses CRLF line endings, so read the echo too.
            process = await conn.create_process(term_type="xterm", term_size=(80, 24))
            try:
                # The one prompt the session is allowed to have sent so far.
                assert await read_until(process, " ") == ROOT_PROMPT

                for i in range(resizes):
                    process.change_terminal_size(100 + i, 30 + i)
                # No input was sent, so nothing more may arrive.
                assert await read_quiet(process) == ""

                # The session is alive: one command gives its echo, its output, and exactly
                # one new prompt, and then the server is silent again.
                process.stdin.write("whoami\r")
                assert await read_until(process, ROOT_PROMPT) == (
                    f"whoami\r\nran:whoami\r\n{ROOT_PROMPT}"
                )
                assert await read_quiet(process) == ""
                assert execute_spy.calls == ["whoami"]

                process.stdin.write("exit\r")
                result = await finish(process)
                assert result.exit_status == 0
                assert result.stdout == "exit\r\nlogout\r\n"
            finally:
                process.close()


async def test_r8_6_ctrl_c_prints_caret_c_and_keeps_session_open(tmp_path, execute_spy):
    async with running_server(tmp_path) as port:
        async with await connect(port) as conn:
            process = await conn.create_process()
            try:
                assert await read_until(process, " ") == ROOT_PROMPT

                process.send_break(100)
                assert await read_until(process, " ") == f"^C\n{ROOT_PROMPT}"

                # Still alive: a command still executes and the prompt comes back.
                process.stdin.write("whoami\n")
                assert await read_until(process, " ") == f"ran:whoami\n{ROOT_PROMPT}"
                assert execute_spy.calls == ["whoami"]

                process.stdin.write("exit\n")
                result = await finish(process)
                assert result.exit_status == 0
            finally:
                process.close()


async def test_r8_6_interactive_line_over_4096_bytes_is_rejected_and_session_continues(
    tmp_path, execute_spy
):
    command = padded_command(MAX_COMMAND_BYTES + 1)
    async with running_server(tmp_path) as port:
        async with await connect(port) as conn:
            process = await conn.create_process()
            try:
                assert await read_until(process, " ") == ROOT_PROMPT

                process.stdin.write(command + "\n")
                assert await read_until(process, ROOT_PROMPT) == f"{TOO_LONG_MESSAGE}{ROOT_PROMPT}"
                assert execute_spy.calls == []

                # Session continues: a normal command works afterwards.
                process.stdin.write("whoami\n")
                assert await read_until(process, " ") == f"ran:whoami\n{ROOT_PROMPT}"
                assert execute_spy.calls == ["whoami"]

                process.stdin.write("exit\n")
                result = await finish(process)
                assert result.exit_status == 0
            finally:
                process.close()


async def test_r8_6_interactive_line_of_exactly_4096_bytes_is_accepted(tmp_path, execute_spy):
    command = padded_command(MAX_COMMAND_BYTES)
    async with running_server(tmp_path) as port:
        async with await connect(port) as conn:
            process = await conn.create_process()
            try:
                assert await read_until(process, " ") == ROOT_PROMPT
                process.stdin.write(command + "\n")
                assert await read_until(process, ROOT_PROMPT) == f"ran:{command}\n{ROOT_PROMPT}"
                assert execute_spy.calls == [command]
                process.stdin.write("exit\n")
                result = await finish(process)
                assert result.exit_status == 0
            finally:
                process.close()


# ---------------------------------------------------------------------------
# Logging of oversize commands
# ---------------------------------------------------------------------------


async def test_r1_9_exec_oversize_log_has_byte_count_and_never_the_command(tmp_path, caplog):
    command = padded_command(MAX_COMMAND_BYTES + 1)
    caplog.set_level(logging.DEBUG, logger="honeypot.shell")
    async with running_server(tmp_path) as port:
        async with await connect(port) as conn:
            result = await asyncio.wait_for(conn.run(command, check=False), CLIENT_TIMEOUT)
            assert result.exit_status == 1

    assert shell_log_messages(caplog) == [
        f"BYTE LENGTH TOO LONG client_ip={LOOPBACK} byte_count=4097"
    ]
    assert [r.levelno for r in caplog.records if r.name == "honeypot.shell"] == [logging.WARNING]
    assert_command_not_logged(caplog)


async def test_r1_9_exec_multibyte_oversize_log_counts_bytes_not_characters(tmp_path, caplog):
    command = "\u20ac" * 1366
    caplog.set_level(logging.DEBUG, logger="honeypot.shell")
    async with running_server(tmp_path) as port:
        async with await connect(port) as conn:
            await asyncio.wait_for(conn.run(command, check=False), CLIENT_TIMEOUT)

    assert shell_log_messages(caplog) == [
        f"BYTE LENGTH TOO LONG client_ip={LOOPBACK} byte_count=4098"
    ]
    assert "\u20ac" not in caplog.text


async def test_r8_6_interactive_oversize_log_has_byte_count_and_never_the_command(tmp_path, caplog):
    command = padded_command(MAX_COMMAND_BYTES + 1)
    caplog.set_level(logging.DEBUG, logger="honeypot.shell")
    async with running_server(tmp_path) as port:
        async with await connect(port) as conn:
            process = await conn.create_process()
            try:
                assert await read_until(process, " ") == ROOT_PROMPT
                process.stdin.write(command + "\n")
                assert await read_until(process, ROOT_PROMPT) == f"{TOO_LONG_MESSAGE}{ROOT_PROMPT}"
                process.stdin.write("exit\n")
                await finish(process)
            finally:
                process.close()

    assert shell_log_messages(caplog) == [
        f"BYTE LENGTH TOO LONG client_ip={LOOPBACK} byte_count=4097"
    ]
    assert_command_not_logged(caplog)


def assert_command_not_logged(caplog: pytest.LogCaptureFixture) -> None:
    # Check the rendered text, each formatted message, and the raw args and msg templates.
    assert SECRET_MARKER not in caplog.text
    for record in caplog.records:
        assert SECRET_MARKER not in record.getMessage()
        assert SECRET_MARKER not in repr(record.args)
        assert SECRET_MARKER not in repr(record.msg)


# ---------------------------------------------------------------------------
# Stdout/stderr routing, prompt, and per-session cwd (real command engine)
# ---------------------------------------------------------------------------

NOT_FOUND = "-bash: nosuchcmd: command not found\n"


async def test_r8_6_exec_keeps_stderr_separate_from_stdout(tmp_path):
    async with running_server(tmp_path) as port:
        async with await connect(port) as conn:
            result = await asyncio.wait_for(conn.run("nosuchcmd", check=False), CLIENT_TIMEOUT)
            assert result.stdout == ""
            assert result.stderr == NOT_FOUND
            assert result.exit_status == 127


@pytest.mark.parametrize(
    ("pty_options", "eol", "echoed_input"),
    [
        pytest.param({}, "\n", "", id="no-pty"),
        pytest.param(
            {"term_type": "xterm", "term_size": (80, 24)}, "\r\n", "nosuchcmd\r\n", id="pty"
        ),
    ],
)
async def test_r8_6_interactive_writes_command_stderr_to_stdout(
    tmp_path, pty_options, eol, echoed_input
):
    async with running_server(tmp_path) as port:
        async with await connect(port) as conn:
            process = await conn.create_process(**pty_options)
            try:
                assert await read_until(process, " ") == ROOT_PROMPT
                process.stdin.write("nosuchcmd" + ("\r" if pty_options else "\n"))
                expected_error = NOT_FOUND.replace("\n", eol)
                assert await read_until(process, ROOT_PROMPT) == (
                    f"{echoed_input}{expected_error}{ROOT_PROMPT}"
                )
                process.stdin.write("exit" + ("\r" if pty_options else "\n"))
                result = await finish(process)
                # Nothing was sent on the separate stderr stream.
                assert result.stderr == ""
                assert result.exit_status == 0
            finally:
                process.close()


async def run_lines(process: asyncssh.SSHClientProcess, line: str, prompt: str) -> str:
    """Send one line, return everything up to and including the next ``prompt``."""
    process.stdin.write(line + "\n")
    return await read_until(process, prompt)


async def test_r8_6_prompt_shows_tilde_at_home_and_full_path_elsewhere(tmp_path):
    async with running_server(tmp_path) as port:
        async with await connect(port) as conn:
            process = await conn.create_process()
            try:
                assert await read_until(process, " ") == root_prompt("~")

                assert await run_lines(process, "cd /etc", root_prompt("/etc")) == (
                    root_prompt("/etc")
                )
                assert await run_lines(process, "cd /var/log", root_prompt("/var/log")) == (
                    root_prompt("/var/log")
                )
                # A bare cd returns home.
                assert await run_lines(process, "cd", root_prompt("~")) == root_prompt("~")
                # Below home the prompt abbreviates only the home prefix.
                assert await run_lines(process, "cd .ssh", root_prompt("~/.ssh")) == (
                    root_prompt("~/.ssh")
                )
                assert await run_lines(process, "cd /root", root_prompt("~")) == root_prompt("~")

                process.stdin.write("exit\n")
                result = await finish(process)
                assert result.exit_status == 0
            finally:
                process.close()


async def test_r8_6_failed_cd_keeps_prompt_and_cwd(tmp_path):
    async with running_server(tmp_path) as port:
        async with await connect(port) as conn:
            process = await conn.create_process()
            try:
                assert await read_until(process, " ") == root_prompt("~")
                assert await run_lines(process, "cd /etc", root_prompt("/etc")) == (
                    root_prompt("/etc")
                )
                assert await run_lines(process, "cd /no/such/dir", root_prompt("/etc")) == (
                    f"-bash: cd: /no/such/dir: No such file or directory\n{root_prompt('/etc')}"
                )
                assert await run_lines(process, "pwd", root_prompt("/etc")) == (
                    f"/etc\n{root_prompt('/etc')}"
                )
                process.stdin.write("exit\n")
                await finish(process)
            finally:
                process.close()


async def test_r2_10_cd_carries_over_between_commands_in_one_session(tmp_path):
    async with running_server(tmp_path) as port:
        async with await connect(port) as conn:
            process = await conn.create_process()
            try:
                assert await read_until(process, " ") == root_prompt("~")
                assert await run_lines(process, "pwd", root_prompt("~")) == (
                    f"/root\n{root_prompt('~')}"
                )
                assert await run_lines(process, "cd /etc", root_prompt("/etc")) == (
                    root_prompt("/etc")
                )
                assert await run_lines(process, "pwd", root_prompt("/etc")) == (
                    f"/etc\n{root_prompt('/etc')}"
                )
                # Relative cd builds on the carried-over cwd.
                assert await run_lines(process, "cd ssh", root_prompt("/etc/ssh")) == (
                    root_prompt("/etc/ssh")
                )
                assert await run_lines(process, "pwd", root_prompt("/etc/ssh")) == (
                    f"/etc/ssh\n{root_prompt('/etc/ssh')}"
                )
                process.stdin.write("exit\n")
                await finish(process)
            finally:
                process.close()


async def test_r2_10_concurrent_sessions_do_not_share_cwd(tmp_path):
    async with running_server(tmp_path) as port:
        async with await connect(port) as conn_a, await connect(port) as conn_b:
            proc_a = await conn_a.create_process()
            proc_b = await conn_b.create_process()
            try:
                assert await read_until(proc_a, " ") == root_prompt("~")
                assert await read_until(proc_b, " ") == root_prompt("~")

                # Session A moves; session B must stay at home.
                assert await run_lines(proc_a, "cd /var/log", root_prompt("/var/log")) == (
                    root_prompt("/var/log")
                )
                assert await run_lines(proc_b, "pwd", root_prompt("~")) == (
                    f"/root\n{root_prompt('~')}"
                )

                # Session B moves elsewhere; session A must stay where it was.
                assert await run_lines(proc_b, "cd /etc", root_prompt("/etc")) == (
                    root_prompt("/etc")
                )
                assert await run_lines(proc_a, "pwd", root_prompt("/var/log")) == (
                    f"/var/log\n{root_prompt('/var/log')}"
                )
                assert await run_lines(proc_b, "pwd", root_prompt("/etc")) == (
                    f"/etc\n{root_prompt('/etc')}"
                )

                for proc in (proc_a, proc_b):
                    proc.stdin.write("exit\n")
                    await finish(proc)
            finally:
                proc_a.close()
                proc_b.close()
