from collections import deque
import time


class AdmissionController:
    def __init__(
        self,
        global_limit=100,
        per_ip_limit=5,
        rate_limit=10,
        rate_window=60.0,
        clock=time.monotonic,
    ):
        self._open_total = 0
        self._open_per_ip = {}
        self._attempts = {}  # TODO: prune stale entries (IPs with no attempts in the last rate window)
        self._global_limit = global_limit
        self._per_ip_limit = per_ip_limit
        self._rate_limit = rate_limit
        self._rate_window = rate_window
        self._clock = clock

    def try_acquire(self, ip: str) -> bool:
        now = self._clock()
        # record this attempt in the IP's deque (create the deque if needed)
        if ip not in self._attempts:
            self._attempts[ip] = deque(maxlen=self._rate_limit)

        attempts = self._attempts[ip]

        # if the rate limit is exceeded → return False
        rate_exceeded = len(attempts) == self._rate_limit and now - attempts[0] < self._rate_window

        attempts.append(now)

        if rate_exceeded:
            return False

        # if the global limit is reached → return False
        if self._open_total >= self._global_limit:
            return False

        # if the per-IP limit is reached → return False
        if self._open_per_ip.get(ip, 0) >= self._per_ip_limit:
            return False

        # increment the total and the IP's count
        self._open_total += 1
        self._open_per_ip[ip] = self._open_per_ip.get(ip, 0) + 1

        return True

    def release(self, ip: str) -> None:
        if ip not in self._open_per_ip:
            return

        self._open_total -= 1
        self._open_per_ip[ip] -= 1

        if self._open_per_ip[ip] == 0:
            del self._open_per_ip[ip]
