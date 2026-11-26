import asyncio
import contextlib
import logging
import sys
from functools import partial

from dotenv import load_dotenv
from psycopg_pool import PoolTimeout

from honeypot.auth import AuthPolicy, ConfigurationError, load_auth_policy_from_env
from honeypot.config import Config, load_config_from_env
from honeypot.limits import AdmissionController
from honeypot.recorder import Recorder
from honeypot.shell import handle_process
from honeypot.ssh_server import create_honeypot_server
from honeypot.vfs import Node, load_template
from honeypot.writer import open_pool, run_writer

log = logging.getLogger("honeypot.main")


def configure_logging() -> None:
    logging.basicConfig(level=logging.INFO)
    # asyncssh's INFO logs include raw attacker commands and usernames (CWE-117).
    logging.getLogger("asyncssh").setLevel(logging.WARNING)


async def serve(config: Config, auth: AuthPolicy, base_root: Node) -> None:
    # Refuse to start without a working database: no unrecorded sessions.
    pool = await open_pool(config.database_url)
    try:
        recorder = Recorder()
        writer = asyncio.create_task(run_writer(recorder, pool))
        admission = AdmissionController()
        server = await create_honeypot_server(
            auth=auth,
            admission=admission,
            host=config.ssh_host,
            port=config.ssh_port,
            host_key_path=config.host_key_path,
            # partial fills in base_root; asyncssh still calls it with just the process.
            process_factory=partial(handle_process, base_root=base_root),
            login_timeout=config.login_timeout,
        )
        log.info("HONEYPOT LISTENING host=%s port=%d", config.ssh_host, config.ssh_port)
        try:
            # On Windows, the selector loop only notices Ctrl+C when it wakes up,
            # so wake it once a second instead of waiting indefinitely.
            while True:
                await asyncio.sleep(1)
        finally:
            server.close()
            await server.wait_closed()
            writer.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await writer
    finally:
        await pool.close()


def main() -> int:
    load_dotenv()
    configure_logging()

    try:
        config = load_config_from_env()
        auth = load_auth_policy_from_env(config.credentials_path)
        # Load once at startup: a broken template stops the honeypot here,
        # not on the first attacker's login.
        base_root = load_template(config.fs_template_path)
    except ConfigurationError as exc:
        log.error("CONFIG ERROR %s", exc)
        return 1

    loop_factory = asyncio.SelectorEventLoop if sys.platform == "win32" else None
    try:
        asyncio.run(serve(config, auth, base_root), loop_factory=loop_factory)
    except PoolTimeout:
        # Never log the URL: it contains the password.
        log.error("DATABASE UNAVAILABLE could not connect to PostgreSQL")
        return 1
    except KeyboardInterrupt:
        log.info("HONEYPOT STOPPED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
