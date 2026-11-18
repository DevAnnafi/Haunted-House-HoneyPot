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


async def run_exec(process: asyncssh.SSHServerProcess) -> None:
    command = process.command
    client_ip = process.get_extra_info("peername")[0]
    byte_count = len(command.encode("utf-8", "surrogatepass"))

    if byte_count > MAX_COMMAND_BYTES:
        process.stderr.write("-bash: command too long\n")
        log.warning("BYTE LENGTH TOO LONG client_ip=%s byte_count=%d", client_ip, byte_count)
        process.exit(1)

    else:
        output, status = dispatch(command)
        safe_output = sanitize_for_terminal(output)
        process.stdout.write(safe_output)
        process.exit(status)
