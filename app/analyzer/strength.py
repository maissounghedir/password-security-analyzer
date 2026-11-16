import math
from dataclasses import dataclass

from app.analyzer.common_passwords import (
    CommonPasswordResult,
    check_common_password,
    load_common_passwords,
)
from app.analyzer.entropy import EntropyResult, calculate_entropy
from app.analyzer.patterns import PatternFinding, detect_patterns

# Tunable model constants. These are approximations, not measured values.
PATTERN_COST_BITS = 10.0    # cost to guess one pattern region
MANGLING_RULE_BITS = 5.0    # extra work for leetspeak/suffix rules
TARGET_BITS = 80.0          # effective entropy that maps to a score of 100

ESTIMATE_DISCLAIMER = (
    "Scores and entropy values are estimates based on a simplified model. "
    "They are not guarantees of security."
)


@dataclass(frozen=True)
class StrengthResult:
    """Combined strength assessment. Never contains the password itself."""
    score: int
    rating: str
    effective_entropy_bits: float
    entropy: EntropyResult
    common: CommonPasswordResult
    patterns: tuple[PatternFinding, ...]


def _merge_overlapping(findings) -> list[tuple[int, int]]:
    """Merge overlapping findings into regions. Adjacent ones stay separate."""
    intervals = sorted((f.start, f.start + f.length) for f in findings)
    merged: list[tuple[int, int]] = []
    for start, end in intervals:
        if merged and start < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def estimate_effective_entropy(
    entropy: EntropyResult,
    common: CommonPasswordResult,
    findings,
) -> float:
    """Estimate the entropy an attacker faces after accounting for weaknesses."""
    if entropy.length == 0 or entropy.pool_size == 0:
        return 0.0

    bits_per_char = math.log2(entropy.pool_size)
    regions = _merge_overlapping(findings)

    covered = sum(end - start for start, end in regions)
    uncovered = max(entropy.length - covered, 0)

    bits = uncovered * bits_per_char
    for start, end in regions:
        # A pattern never costs more than random characters would.
        bits += min(PATTERN_COST_BITS, (end - start) * bits_per_char)

    if common.is_common:
        # Found within N guesses, where N is the wordlist size.
        list_bits = math.log2(max(len(load_common_passwords()), 2))
        if common.match_type == "variation":
            list_bits += MANGLING_RULE_BITS
        bits = min(bits, list_bits)

    return round(bits, 2)


def score_from_bits(bits: float) -> int:
    """Map effective entropy to a 0-100 score (linear, capped at TARGET_BITS)."""
    return round(min(max(bits, 0.0), TARGET_BITS) / TARGET_BITS * 100)


def rate_score(score: int) -> str:
    """Map a 0-100 score to a rating."""
    if score < 25:
        return "Very weak"
    if score < 50:
        return "Weak"
    if score < 70:
        return "Fair"
    if score < 90:
        return "Strong"
    return "Very strong"


def analyze_strength(password: str) -> StrengthResult:
    """Run all analyzers and combine them into one strength assessment."""
    entropy = calculate_entropy(password)
    common = check_common_password(password)
    findings = tuple(detect_patterns(password))

    effective = estimate_effective_entropy(entropy, common, findings)
    score = score_from_bits(effective)

    return StrengthResult(
        score=score,
        rating=rate_score(score),
        effective_entropy_bits=effective,
        entropy=entropy,
        common=common,
        patterns=findings,
    )