import pytest

from app.analyzer.common_passwords import check_common_password


def test_exact_match():
    result = check_common_password("password")
    assert result.is_common is True
    assert result.match_type == "exact"


def test_case_insensitive_match():
    assert check_common_password("PASSWORD").match_type == "exact"


@pytest.mark.parametrize("password", ["p@ssw0rd", "P@ssw0rd!", "password123!", "Qwerty!!"])
def test_variations_are_detected(password):
    result = check_common_password(password)
    assert result.is_common is True
    assert result.match_type == "variation"


def test_random_password_is_not_common():
    result = check_common_password("xK9#vLq2$mWz")
    assert result.is_common is False
    assert result.match_type is None


def test_empty_password_is_not_common():
    assert check_common_password("").is_common is False


def test_result_never_exposes_matched_word():
    result = check_common_password("p@ssw0rd")
    assert not hasattr(result, "matched_word")
    assert not hasattr(result, "password")