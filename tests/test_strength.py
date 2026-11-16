import math

import pytest

from app.analyzer.common_passwords import load_common_passwords
from app.analyzer.strength import (
    PATTERN_COST_BITS,
    analyze_strength,
    rate_score,
    score_from_bits,
)


def test_empty_password():
    result = analyze_strength("")
    assert result.score == 0
    assert result.rating == "Very weak"


def test_common_password_is_very_weak():
    result = analyze_strength("Password1")
    assert result.common.is_common is True
    assert result.effective_entropy_bits < result.entropy.bits
    assert result.rating in ("Very weak", "Weak")


def test_common_password_entropy_is_capped_by_wordlist_size():
    result = analyze_strength("password")
    cap = math.log2(len(load_common_passwords()))
    assert result.effective_entropy_bits <= cap + 0.01


def test_random_password_keeps_full_entropy():
    result = analyze_strength("xK9#vLq2$mWz")
    assert result.patterns == ()
    assert result.common.is_common is False
    assert result.effective_entropy_bits == pytest.approx(result.entropy.bits, abs=0.01)
    assert result.rating == "Very strong"


def test_adjacent_patterns_are_penalized_separately():
    # Two adjacent sequences: 'mnop' (ascending) and '7654' (descending).
    result = analyze_strength("mnop7654")
    assert result.common.is_common is False  # precondition: not in the wordlist
    assert result.effective_entropy_bits == pytest.approx(2 * PATTERN_COST_BITS)
    assert result.rating == "Weak"


def test_overlapping_detections_are_penalized_once():
    # 'qwerty' is both a keyboard walk and a dictionary word: one region.
    result = analyze_strength("qwertyXk9#vLq2$")
    expected = 9 * math.log2(94) + PATTERN_COST_BITS
    assert result.effective_entropy_bits == pytest.approx(expected, abs=0.05)


def test_score_mapping():
    assert score_from_bits(0) == 0
    assert score_from_bits(80) == 100
    assert score_from_bits(500) == 100
    assert score_from_bits(-5) == 0


@pytest.mark.parametrize(
    "score, expected",
    [(10, "Very weak"), (30, "Weak"), (60, "Fair"), (80, "Strong"), (95, "Very strong")],
)
def test_rating_thresholds(score, expected):
    assert rate_score(score) == expected


def test_result_never_contains_the_password():
    password = "xK9#vLq2$mWz"
    assert password not in repr(analyze_strength(password))