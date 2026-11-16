"""Tests for honeypot.limits.AdmissionController (T1.9; R8.1, R8.2, R8.3, R8.10)."""

from hypothesis import given
from hypothesis import strategies as st

from honeypot.limits import AdmissionController

GLOBAL_LIMIT = 100
PER_IP_LIMIT = 5
RATE_LIMIT = 10
RATE_WINDOW = 60.0


class FakeClock:
    """A clock whose current time is controlled by the test."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def make_controller(clock: FakeClock, **kwargs: float) -> AdmissionController:
    return AdmissionController(clock=clock, **kwargs)


def test_r8_1_101st_connection_rejected() -> None:
    controller = make_controller(FakeClock())
    for i in range(GLOBAL_LIMIT):
        assert controller.try_acquire(f"10.0.{i // 250}.{i % 250}") is True
    assert controller.try_acquire("192.168.1.1") is False


def test_r8_2_sixth_connection_from_one_ip_rejected() -> None:
    controller = make_controller(FakeClock())
    for _ in range(PER_IP_LIMIT):
        assert controller.try_acquire("203.0.113.7") is True
    assert controller.try_acquire("203.0.113.7") is False
    # Other IPs are unaffected by this IP's limit.
    assert controller.try_acquire("203.0.113.8") is True


def test_r8_3_eleventh_attempt_within_window_rejected() -> None:
    clock = FakeClock()
    controller = make_controller(clock)
    ip = "203.0.113.7"
    for _ in range(RATE_LIMIT):
        assert controller.try_acquire(ip) is True
        controller.release(ip)  # keep the per-IP limit out of play
        clock.advance(1.0)  # 10 attempts span 9 s, well inside 60 s
    assert controller.try_acquire(ip) is False


def test_r8_3_rejected_attempts_count_toward_rate_limit() -> None:
    clock = FakeClock()
    controller = make_controller(clock)
    ip = "203.0.113.7"
    for _ in range(RATE_LIMIT):
        assert controller.try_acquire(ip) is True
        controller.release(ip)
    # Keep attempting well past one window; every attempt stays rejected.
    for _ in range(40):
        clock.advance(5.0)  # 200 s total, more than three windows
        assert controller.try_acquire(ip) is False
    # Stopping for the full window unblocks the IP.
    clock.advance(RATE_WINDOW)
    assert controller.try_acquire(ip) is True


def test_r8_3_allowed_again_after_window_passes() -> None:
    clock = FakeClock()
    controller = make_controller(clock)
    ip = "203.0.113.7"
    for _ in range(RATE_LIMIT):
        assert controller.try_acquire(ip) is True
        controller.release(ip)
    assert controller.try_acquire(ip) is False
    clock.advance(RATE_WINDOW + 1.0)
    assert controller.try_acquire(ip) is True


def test_r8_2_release_allows_new_acquisition() -> None:
    controller = make_controller(FakeClock())
    ip = "203.0.113.7"
    for _ in range(PER_IP_LIMIT):
        assert controller.try_acquire(ip) is True
    assert controller.try_acquire(ip) is False
    controller.release(ip)
    assert controller._open_per_ip[ip] == PER_IP_LIMIT - 1
    assert controller._open_total == PER_IP_LIMIT - 1
    assert controller.try_acquire(ip) is True
    assert controller._open_per_ip[ip] == PER_IP_LIMIT
    assert controller._open_total == PER_IP_LIMIT


def test_r8_1_release_frees_global_slot() -> None:
    controller = make_controller(FakeClock())
    for i in range(GLOBAL_LIMIT):
        assert controller.try_acquire(f"10.0.{i // 250}.{i % 250}") is True
    assert controller.try_acquire("192.168.1.1") is False
    controller.release("10.0.0.0")
    assert controller.try_acquire("192.168.1.2") is True


def test_r8_10_release_unknown_ip_is_noop() -> None:
    controller = make_controller(FakeClock())
    controller.release("198.51.100.1")
    assert controller._open_total == 0
    assert controller._open_per_ip == {}

    assert controller.try_acquire("203.0.113.7") is True
    controller.release("198.51.100.1")
    assert controller._open_total == 1
    assert controller._open_per_ip == {"203.0.113.7": 1}

    # Releasing more times than acquired never goes negative.
    controller.release("203.0.113.7")
    controller.release("203.0.113.7")
    assert controller._open_total == 0
    assert controller._open_per_ip == {}


def test_r8_10_entry_removed_when_all_connections_released() -> None:
    controller = make_controller(FakeClock())
    ip = "203.0.113.7"
    for _ in range(3):
        assert controller.try_acquire(ip) is True
    for _ in range(3):
        assert ip in controller._open_per_ip
        controller.release(ip)
    assert ip not in controller._open_per_ip
    assert controller._open_total == 0


_IPS = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
_ops = st.one_of(
    st.tuples(st.just("acquire"), st.sampled_from(_IPS)),
    st.tuples(st.just("release"), st.sampled_from(_IPS)),
    st.tuples(st.just("tick"), st.sampled_from(["short", "long"])),
)


@given(
    ops=st.lists(_ops, max_size=300),
    global_limit=st.integers(min_value=1, max_value=12),
    per_ip_limit=st.integers(min_value=1, max_value=6),
)
def test_r8_10_counts_never_exceed_limits_or_go_negative(
    ops: list[tuple[str, str]], global_limit: int, per_ip_limit: int
) -> None:
    clock = FakeClock()
    controller = make_controller(clock, global_limit=global_limit, per_ip_limit=per_ip_limit)
    for op, arg in ops:
        if op == "acquire":
            controller.try_acquire(arg)
        elif op == "release":
            controller.release(arg)
        else:
            clock.advance(1.0 if arg == "short" else 61.0)

        assert 0 <= controller._open_total <= global_limit
        for count in controller._open_per_ip.values():
            assert 1 <= count <= per_ip_limit
        assert controller._open_total == sum(controller._open_per_ip.values())
