from spike_server import format_auth_log
from hypothesis import given, strategies as st

@given(username=st.text(), success=st.booleans())
def test_auth_log_is_single_safe_line(username, success):
    line = format_auth_log("127.0.0.1", username, success)
    assert "\n" not in line
    assert "\r" not in line
    assert "\x1b" not in line
    expected_status = "SUCCESS" if success else "FAILED"
    assert line.startswith(
        f"AUTH {expected_status} "
    ), f"Expected log to start with 'AUTH {expected_status} '"