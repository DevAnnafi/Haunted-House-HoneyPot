import asyncio
import logging
import sys

from dotenv import load_dotenv

from honeypot.auth import AuthPolicy, ConfigurationError, load_auth_policy_from_env
from honeypot.config import Config, load_config_from_env
from honeypot.limits import AdmissionController
from honeypot.shell import handle_process
from honeypot.ssh_server import create_honeypot_server

log = logging.getLogger("honeypot.main")


def configure_logging() -> None:
    logging.basicConfig(level=logging.INFO)
    # asyncssh's INFO logs include raw attacker commands and usernames (CWE-117).
    logging.getLogger("asyncssh").setLevel(logging.WARNING)


async def serve(config: Config, auth: AuthPolicy) -> None:
    admission = AdmissionController()
    server = await create_honeypot_server(
        auth=auth,
        admission=admission,
        host=config.ssh_host,
        port=config.ssh_port,
        host_key_path=config.host_key_path,
        process_factory=handle_process,
        login_timeout=config.login_timeout,
    )
    log.info("HONEYPOT LISTENING host=%s port=%d", config.ssh_host, config.ssh_port)
    await server.wait_closed()


def main() -> int:
    load_dotenv()
    configure_logging()

    try:
        config = load_config_from_env()
        auth = load_auth_policy_from_env(config.credentials_path)
    except ConfigurationError as exc:
        log.error("CONFIG ERROR %s", exc)
        return 1

    loop_factory = asyncio.SelectorEventLoop if sys.platform == "win32" else None
    try:
        asyncio.run(serve(config, auth), loop_factory=loop_factory)
    except KeyboardInterrupt:
        log.info("HONEYPOT STOPPED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
