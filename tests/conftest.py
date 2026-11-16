import pytest

import app.main as main
from app.api.rate_limit import RateLimiter


@pytest.fixture(autouse=True)
def isolated_rate_limiter(monkeypatch):
    """Give every test a fresh limiter so tests never block each other."""
    monkeypatch.setattr(main, "rate_limiter", RateLimiter(10_000, 60.0))