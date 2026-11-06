import asyncio, asyncssh, sys
from pathlib import Path

TEST_USERNAME = "ghost"
TEST_PASSWORD = "boo123"

class HoneyPotServer(asyncssh.SSHServer):
    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self.client_ip = conn.get_extra_info('peername')[0]
        print(f'SSH connection received from {self.client_ip}')
        
    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username, password) -> bool:
        success = (username == TEST_USERNAME and password == TEST_PASSWORD)
        result = "SUCCESS" if success else "FAILED"
        print(f"AUTH {result} ip={self.client_ip} username={username!r}")
        return success

async def handle_session(process: asyncssh.SSHServerProcess) -> None:
    process.stdout.write("hello\n")
    process.exit(0)

async def start_server() -> None:
    host_key = Path(__file__).parent / "host_key"

    await asyncssh.create_server(
        HoneyPotServer,
        "127.0.0.1",
        2222,
        server_host_keys=[str(host_key)],
        process_factory=handle_session,
    )

    print("SSH honeypot listening on 127.0.0.1:2222")

    await asyncio.Future()


if __name__ == "__main__":
    try:
        asyncio.run(start_server())
    except KeyboardInterrupt:
        print("\nSSH honeypot stopped.") 

    

