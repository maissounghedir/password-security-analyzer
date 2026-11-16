import logging

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.api.rate_limit import RateLimiter
from app.api.schemas import AnalyzeRequest
from app.main import MAX_BODY_BYTES, app

client = TestClient(app)

SECRET = "MySecretDragon2024!"


# ---------- /analyze ----------

def test_analyze_returns_full_report():
    response = client.post("/analyze", json={"password": "Qwerty1990!"})
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {
        "score", "rating", "effective_entropy_bits", "entropy",
        "is_common_password", "common_match_type", "patterns",
        "recommendations", "disclaimer",
    }
    assert 0 <= body["score"] <= 100
    assert "estimates" in body["disclaimer"]
    assert body["recommendations"]


def test_common_password_is_reported():
    body = client.post("/analyze", json={"password": "password"}).json()
    assert body["is_common_password"] is True
    assert body["common_match_type"] == "exact"
    assert body["rating"] in ("Very weak", "Weak")


def test_patterns_never_expose_positions_or_text():
    body = client.post("/analyze", json={"password": "mydragon1990"}).json()
    assert body["patterns"]
    for pattern in body["patterns"]:
        assert set(pattern) == {"type", "length", "description"}


def test_response_does_not_echo_the_password():
    response = client.post("/analyze", json={"password": SECRET})
    assert response.status_code == 200
    assert SECRET not in response.text
    assert "mysecretdragon" not in response.text.lower()


# ---------- validation ----------

@pytest.mark.parametrize(
    "payload",
    [
        {},                                # missing field
        {"password": ""},                  # too short
        {"password": "x" * 129},           # too long
        {"password": 12345},               # wrong type
        {"password": "abc", "extra": 1},   # unknown field
    ],
)
def test_invalid_analyze_requests_are_rejected(payload):
    assert client.post("/analyze", json=payload).status_code == 422


def test_validation_errors_do_not_echo_the_password():
    too_long = "Zq9#" * 40  # 160 characters
    response = client.post("/analyze", json={"password": too_long})
    assert response.status_code == 422
    assert too_long not in response.text
    assert "input" not in response.json()["detail"][0]

    response = client.post("/analyze", json={"password": SECRET, "extra": 1})
    assert response.status_code == 422
    assert SECRET not in response.text


def test_password_in_url_is_not_supported():
    response = client.get("/analyze", params={"password": SECRET})
    assert response.status_code == 405
    assert SECRET not in response.text


# ---------- /generate ----------

def test_generate_defaults():
    response = client.post("/generate", json={})
    assert response.status_code == 200
    body = response.json()
    assert len(body["password"]) == 16
    assert body["length"] == 16
    assert "estimates" in body["disclaimer"]


def test_generate_options_are_respected():
    body = client.post(
        "/generate",
        json={"length": 24, "use_symbols": False, "use_digits": False},
    ).json()
    assert len(body["password"]) == 24
    assert body["password"].isalpha()
    assert body["score"] >= 70


def test_generated_passwords_differ():
    first = client.post("/generate", json={}).json()["password"]
    second = client.post("/generate", json={}).json()["password"]
    assert first != second


@pytest.mark.parametrize(
    "payload",
    [
        {"length": 7},
        {"length": 129},
        {"length": "abc"},
        {
            "use_lowercase": False, "use_uppercase": False,
            "use_digits": False, "use_symbols": False,
        },
        {"unknown": True},
    ],
)
def test_invalid_generate_requests_are_rejected(payload):
    assert client.post("/generate", json=payload).status_code == 422


# ---------- security headers ----------

@pytest.mark.parametrize(
    "method, path, kwargs",
    [
        ("get", "/health", {}),
        ("post", "/analyze", {"json": {"password": "abc"}}),
        ("post", "/analyze", {"json": {}}),       # 422 responses too
        ("post", "/generate", {"json": {}}),
    ],
)
def test_security_headers_on_every_response(method, path, kwargs):
    response = getattr(client, method)(path, **kwargs)
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"


# ---------- hardening ----------

def test_oversized_body_is_rejected():
    response = client.post(
        "/analyze",
        content="x" * (MAX_BODY_BYTES + 1),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert response.headers["cache-control"] == "no-store"


def test_rate_limit_returns_429(monkeypatch):
    monkeypatch.setattr(main, "rate_limiter", RateLimiter(2, 60.0))
    assert client.post("/analyze", json={"password": "abc"}).status_code == 200
    assert client.post("/generate", json={}).status_code == 200

    blocked = client.post("/analyze", json={"password": "abc"})
    assert blocked.status_code == 429
    assert blocked.headers["retry-after"] == "60"
    assert blocked.headers["cache-control"] == "no-store"

    assert client.get("/health").status_code == 200  # health is never limited


def test_no_cors_headers_by_default():
    response = client.post(
        "/analyze",
        json={"password": "abc"},
        headers={"Origin": "http://evil.example"},
    )
    assert "access-control-allow-origin" not in response.headers


# ---------- no leaks ----------

def test_password_never_appears_in_logs(caplog):
    caplog.set_level(logging.DEBUG)
    client.post("/analyze", json={"password": SECRET})        # success path
    client.post("/analyze", json={"password": SECRET * 10})   # 422 path
    assert SECRET not in caplog.text


def test_request_model_hides_password_in_repr():
    assert SECRET not in repr(AnalyzeRequest(password=SECRET))