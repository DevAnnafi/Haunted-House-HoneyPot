import asyncio, asyncssh, sys
from pathlib import Path

TEST_USERNAME = "ghost"
TEST_PASSWORD = "boo123"


def format_auth_log(ip, username, success: bool):
    result = "SUCCESS" if success else "FAILED"
    return f"AUTH {result} ip={ip} username={username!r}"


class HoneyPotServer(asyncssh.SSHServer):
    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self.client_ip = conn.get_extra_info("peername")[0]
        print(f"SSH connection received from {self.client_ip}")

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username, password) -> bool:
        success = username == TEST_USERNAME and password == TEST_PASSWORD
        result = "SUCCESS" if success else "FAILED"
        print(format_auth_log(self.client_ip, username, success))
        return success

    def connection_requested(
        self, dest_host: str, dest_port: int, orig_host: str, orig_port: int
    ) -> bool:
        print(f"FORWARD DENIED type=local ip={self.client_ip} dest={dest_host!r}:{dest_port}")
        return False

    def server_requested(self, listen_host: str, listen_port: int) -> bool:
        print(
            f"FORWARD DENIED type=remote ip={self.client_ip} listen={listen_host!r}:{listen_port}"
        )
        return False

    def unix_connection_requested(self, dest_path: str) -> bool:
        print(f"FORWARD DENIED type=unix-local ip={self.client_ip} dest={dest_path!r}")
        return False

    def unix_server_requested(self, listen_path: str) -> bool:
        print(f"FORWARD DENIED type=unix-remote ip={self.client_ip} listen={listen_path!r}")
        return False


async def handle_session(process: asyncssh.SSHServerProcess) -> None:
    if process.command is not None:
        process.stdout.write(f"you ran: {process.command}\n")
        process.exit(0)
    else:
        process.stdout.write("ghost@haunted:~$ ")
        while True:
            try:
                async for line in process.stdin:
                    cleaned_line = line.strip()

                    if cleaned_line == "exit":
                        process.stdout.write("logout\n")
                        break

                    process.stdout.write(f"{cleaned_line}\n")
                    process.stdout.write("ghost@haunted:~$ ")
                break

            except asyncssh.TerminalSizeChanged:
                continue

            except asyncssh.BreakReceived:
                break

        process.exit(0)


async def create_honeypot_server(port: int) -> asyncssh.SSHAcceptor:
    host_key = Path(__file__).parent / "host_key"

    return await asyncssh.create_server(
        HoneyPotServer,
        "127.0.0.1",
        port,
        server_host_keys=[str(host_key)],
        process_factory=handle_session,
        agent_forwarding=False,
        x11_forwarding=False,
        sftp_factory=None,
        allow_scp=False,
        login_timeout=15,
        rdns_lookup=False,
        max_line_length=4096,
        server_version="OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
    )


async def start_server() -> None:
    await create_honeypot_server(2222)

    print("SSH honeypot listening on 127.0.0.1:2222")

    await asyncio.Future()


if __name__ == "__main__":
    try:
        asyncio.run(start_server())
    except KeyboardInterrupt:
        print("\nSSH honeypot stopped.")
