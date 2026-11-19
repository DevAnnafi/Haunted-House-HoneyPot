import logging
import unicodedata

import asyncssh

log = logging.getLogger(__name__)
MAX_COMMAND_BYTES = 4096


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


def dispatch(command: str) -> tuple[str, int]:
    return (f"{command}\n", 0)


def _is_too_long(command: str) -> bool:
    byte_count = len(command.encode("utf-8", "surrogatepass"))
    return byte_count > MAX_COMMAND_BYTES


async def run_exec(process: asyncssh.SSHServerProcess) -> None:
    command = process.command
    client_ip = process.get_extra_info("peername")[0]
    byte_count = len(command.encode("utf-8", "surrogatepass"))

    if _is_too_long(command):
        process.stderr.write("-bash: command too long\n")
        log.warning("BYTE LENGTH TOO LONG client_ip=%s byte_count=%d", client_ip, byte_count)
        process.exit(1)

    else:
        output, status = dispatch(command)
        safe_output = sanitize_for_terminal(output)
        process.stdout.write(safe_output)
        process.exit(status)


async def run_interactive(process: asyncssh.SSHServerProcess) -> None:
    # Show a prompt - For root users use # and for regular users use $
    username = process.get_extra_info("username") or "user"
    prompt_char = "#" if username == "root" else "$"
    prompt = f"{username}@web-prod-01:~{prompt_char} "
    client_ip = process.get_extra_info("peername")[0]

    while True:
        process.stdout.write(prompt)

        try:
            # Read one line
            line = await process.stdin.readline()

            # End the session at EOF
            if not line:
                process.stdout.write("logout\n")
                break

            cmd = line.strip()

            if not cmd:
                continue

            if cmd == "exit":
                process.stdout.write("logout\n")
                break

            # If the bytes of line is too long, write out the line is too long
            if _is_too_long(cmd):
                process.stdout.write("-bash: command too long\n")
                byte_count = len(cmd.encode("utf-8", "surrogatepass"))
                log.warning(
                    "BYTE LENGTH TOO LONG client_ip=%s byte_count=%d", client_ip, byte_count
                )
            else:
                output, _status = dispatch(cmd)
                safe_output = sanitize_for_terminal(output)
                process.stdout.write(safe_output)

        except asyncssh.TerminalSizeChanged:
            continue

        except asyncssh.BreakReceived:
            process.stdout.write("^C\n")
            continue

    process.exit(0)


async def handle_process(process: asyncssh.SSHServerProcess) -> None:
    if process.command is None:
        await run_interactive(process)
    else:
        await run_exec(process)
