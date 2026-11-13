from spike_server import format_auth_log, create_honeypot_server, TEST_USERNAME, TEST_PASSWORD
from hypothesis import given, strategies as st
import pytest
import asyncssh


@given(username=st.text(), success=st.booleans())
def test_auth_log_is_single_safe_line(username, success):
    line = format_auth_log("127.0.0.1", username, success)
    assert "\n" not in line
    assert "\r" not in line
    assert "\x1b" not in line
    expected_status = "SUCCESS" if success else "FAILED"
    assert line.startswith(f"AUTH {expected_status} "), (
        f"Expected log to start with 'AUTH {expected_status} '"
    )


@pytest.mark.asyncio
async def test_exec_request_end_to_end():
    server = await create_honeypot_server(0)
    try:
        port = server.get_port()
        async with asyncssh.connect(
            "127.0.0.1",
            port,
            username=TEST_USERNAME,
            password=TEST_PASSWORD,
            known_hosts=None,
        ) as conn:
            result = await conn.run("uname -a")
            assert result.stdout == "you ran: uname -a\n"
            assert result.exit_status == 0
    finally:
        server.close()
        await server.wait_closed()
