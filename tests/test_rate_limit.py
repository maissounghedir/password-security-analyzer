from app.api.rate_limit import RateLimiter


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_blocks_after_limit():
    limiter = RateLimiter(3, 60, clock=FakeClock())
    assert [limiter.allow("a") for _ in range(4)] == [True, True, True, False]


def test_window_expires():
    clock = FakeClock()
    limiter = RateLimiter(1, 60, clock=clock)
    assert limiter.allow("a") is True
    assert limiter.allow("a") is False
    clock.now = 60
    assert limiter.allow("a") is True


def test_clients_are_independent():
    limiter = RateLimiter(1, 60, clock=FakeClock())
    assert limiter.allow("a") is True
    assert limiter.allow("b") is True
    assert limiter.allow("a") is False


def test_blocked_requests_do_not_extend_the_block():
    clock = FakeClock()
    limiter = RateLimiter(1, 60, clock=clock)
    limiter.allow("a")
    clock.now = 30
    assert limiter.allow("a") is False   # blocked, not recorded
    clock.now = 60
    assert limiter.allow("a") is True    # first hit expired on schedule


def test_stale_clients_are_purged():
    clock = FakeClock()
    limiter = RateLimiter(1, 60, clock=clock, max_keys=2)
    limiter.allow("a")
    limiter.allow("b")
    clock.now = 100
    limiter.allow("c")                   # triggers the purge
    assert limiter.tracked_clients == 1