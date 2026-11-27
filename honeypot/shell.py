import copy
import logging
import unicodedata
from typing import Any
from uuid import UUID

import asyncssh

from honeypot.commands.engine import CommandResult, Context, execute, home_dir
from honeypot.recorder import Recorder
from honeypot.vfs import Node, VirtualFS
from shared.events import EventType

log = logging.getLogger(__name__)
MAX_COMMAND_BYTES = 4096
HOSTNAME = "web-prod-01"


def sanitize_for_terminal(text: str) -> str:
    kept = []

    for ch in text:
        category = unicodedata.category(ch)

        if ch == "\n" or ch == "\t":
            kept.append(ch)
        elif category == "Cc":
            continue
        else:
            kept.append(ch)

    return "".join(kept)


def _is_too_long(command: str) -> bool:
    byte_count = len(command.encode("utf-8", "surrogatepass"))
    return byte_count > MAX_COMMAND_BYTES


def _make_context(process: asyncssh.SSHServerProcess, base_root: Node) -> Context:
    username = process.get_extra_info("username") or "user"
    # Each session gets its own copy of the filesystem (R2.10).
    vfs = VirtualFS(copy.deepcopy(base_root))
    home = home_dir(username)
    node = vfs.resolve("/", home)
    cwd = home if node is not None and node.kind == "dir" else "/"
    return Context(vfs=vfs, cwd=cwd, username=username, hostname=HOSTNAME)


def _display_cwd(cwd: str, home: str) -> str:
    if cwd == home:
        return "~"
    if cwd.startswith(home + "/"):
        return "~" + cwd[len(home) :]
    return cwd


class _SessionRecording:
    """Records one session's shell events; ends the session if recording fails."""

    def __init__(
        self,
        process: asyncssh.SSHServerProcess,
        recorder: Recorder,
        session_id: UUID | None,
    ) -> None:
        self._process = process
        self._recorder = recorder
        self._session_id = session_id

    def record(self, event_type: EventType, payload: dict[str, Any]) -> bool:
        # Fail closed (R5.11): if the event can't be recorded, end the session.
        if self._session_id is not None and self._recorder.record(
            self._session_id, event_type, payload
        ):
            return True
        self._process.exit(1)
        conn = self._process.get_extra_info("connection")
        if conn is not None:
            conn.close()
        return False

    def output(self, result: CommandResult) -> bool:
        # The raw output is the evidence; safe_text makes it safe to store.
        return self.record(
            EventType.OUTPUT,
            {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_status": result.exit_status,
            },
        )


async def run_exec(
    process: asyncssh.SSHServerProcess, ctx: Context, rec: _SessionRecording
) -> None:
    command = process.command
    client_ip = process.get_extra_info("peername")[0]

    if _is_too_long(command):
        byte_count = len(command.encode("utf-8", "surrogatepass"))
        # Record the size only, never the oversized command itself.
        if not rec.record(EventType.LIMIT_REJECTED, {"bytes": byte_count}):
            return
        process.stderr.write("-bash: command too long\n")
        log.warning("BYTE LENGTH TOO LONG client_ip=%s byte_count=%d", client_ip, byte_count)
        process.exit(1)
        return

    if not rec.record(EventType.COMMAND, {"line": command}):
        return
    result = execute(ctx, command)
    if not rec.output(result):
        return
    process.stdout.write(sanitize_for_terminal(result.stdout))
    process.stderr.write(sanitize_for_terminal(result.stderr))
    process.exit(result.exit_status)


async def run_interactive(
    process: asyncssh.SSHServerProcess, ctx: Context, rec: _SessionRecording
) -> None:
    prompt_char = "#" if ctx.username == "root" else "$"
    home = home_dir(ctx.username)
    client_ip = process.get_extra_info("peername")[0]

    show_prompt = True

    while True:
        if show_prompt:
            # Rebuilt every time, because cd changes ctx.cwd.
            cwd_display = _display_cwd(ctx.cwd, home)
            prompt = f"{ctx.username}@{ctx.hostname}:{cwd_display}{prompt_char} "
            process.stdout.write(prompt)

        try:
            line = await process.stdin.readline()
            show_prompt = True

            # End the session at EOF
            if not line:
                process.stdout.write("logout\n")
                break

            cmd = line.strip()

            if not cmd:
                continue

            if _is_too_long(cmd):
                byte_count = len(cmd.encode("utf-8", "surrogatepass"))
                if not rec.record(EventType.LIMIT_REJECTED, {"bytes": byte_count}):
                    return
                process.stdout.write("-bash: command too long\n")
                log.warning(
                    "BYTE LENGTH TOO LONG client_ip=%s byte_count=%d",
                    client_ip,
                    byte_count,
                )
                continue

            if not rec.record(EventType.COMMAND, {"line": cmd}):
                return

            if cmd == "exit":
                process.stdout.write("logout\n")
                break

            result = execute(ctx, cmd)
            if not rec.output(result):
                return
            process.stdout.write(sanitize_for_terminal(result.stdout))
            # With a terminal, stdout and stderr both go to the same screen.
            process.stdout.write(sanitize_for_terminal(result.stderr))

        except asyncssh.TerminalSizeChanged:
            show_prompt = False
            continue

        except asyncssh.BreakReceived:
            show_prompt = True
            process.stdout.write("^C\n")
            continue

    process.exit(0)


async def handle_process(
    process: asyncssh.SSHServerProcess, base_root: Node, recorder: Recorder
) -> None:
    # One context per connection: cd carries over between commands, but two
    # attackers never share a filesystem.
    ctx = _make_context(process, base_root)
    rec = _SessionRecording(process, recorder, process.get_extra_info("session_id"))
    if process.command is None:
        await run_interactive(process, ctx, rec)
    else:
        await run_exec(process, ctx, rec)
