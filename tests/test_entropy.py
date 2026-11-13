import math
from app.analyzer.entropy import UNICODE_POOL
import pytest

from app.analyzer.entropy import (
    calculate_entropy,
    calculate_pool_size,
    classify_entropy,
)


def test_empty_password_has_zero_entropy():
    result = calculate_entropy("")
    assert result.bits == 0.0
    assert result.rating == "Very weak"


def test_pool_size_lowercase_only():
    assert calculate_pool_size("abcdef") == 26


def test_pool_size_digits_only():
    assert calculate_pool_size("123456") == 10


def test_pool_size_all_classes():
    assert calculate_pool_size("aA1!") == 26 + 26 + 10 + 32


def test_entropy_formula_lowercase():
    result = calculate_entropy("abcdefgh")
    assert result.bits == pytest.approx(8 * math.log2(26), abs=0.01)


def test_entropy_increases_with_length():
    assert calculate_entropy("abcdefgh").bits > calculate_entropy("abcd").bits


def test_entropy_increases_with_diversity():
    assert calculate_entropy("aA1!aA1!").bits > calculate_entropy("abcdefgh").bits




def test_unicode_characters_expand_pool():
    assert calculate_pool_size("é") == UNICODE_POOL

@pytest.mark.parametrize(
    "bits, expected",
    [
        (10, "Very weak"),
        (30, "Weak"),
        (50, "Reasonable"),
        (80, "Strong"),
        (130, "Very strong"),
    ],
)
def test_classification(bits, expected):
    assert classify_entropy(bits) == expected