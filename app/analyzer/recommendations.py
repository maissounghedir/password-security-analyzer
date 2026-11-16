import string
from dataclasses import dataclass
from enum import Enum

from app.analyzer.patterns import PatternType
from app.analyzer.strength import StrengthResult

MIN_LENGTH_CRITICAL = 8
RECOMMENDED_LENGTH = 12
PASSPHRASE_LENGTH = 16   # beyond this, composition rules matter little
STRONG_SCORE = 90


class Severity(str, Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


@dataclass(frozen=True)
class Recommendation:
    """Advice for the user. Messages are generic and never echo the password."""
    code: str
    severity: Severity
    message: str


_PATTERN_ADVICE = {
    PatternType.REPEATED_CHARACTERS:
        "Avoid repeating the same character several times in a row.",
    PatternType.REPEATED_BLOCK:
        "Avoid repeating a short block of characters over and over.",
    PatternType.SEQUENCE:
        "Avoid sequences of consecutive letters or digits such as 'abc' or '123'.",
    PatternType.KEYBOARD_WALK:
        "Avoid keyboard patterns such as 'qwerty' or 'azerty'.",
    PatternType.YEAR:
        "Avoid years and dates: they are among the first things attackers try.",
    PatternType.DICTIONARY_WORD:
        "Avoid common words. Combine several unrelated words, or use random characters.",
}


def _missing_classes(password: str) -> list[str]:
    """Return the names of the character types absent from the password."""
    checks = [
        ("lowercase letters", string.ascii_lowercase),
        ("uppercase letters", string.ascii_uppercase),
        ("digits", string.digits),
        ("symbols", string.punctuation),
    ]
    return [name for name, chars in checks if not any(c in chars for c in password)]


def generate_recommendations(password: str, result: StrengthResult) -> list[Recommendation]:
    """Turn an analysis into prioritized, actionable advice."""
    length = result.entropy.length

    if length == 0:
        return [Recommendation("empty_password", Severity.CRITICAL, "No password was provided.")]

    recs: list[Recommendation] = []

    # 1. Known-bad passwords
    if result.common.is_common:
        if result.common.match_type == "exact":
            recs.append(Recommendation(
                "common_password", Severity.CRITICAL,
                "This password appears in lists of commonly used passwords, which "
                "attackers try first. Choose a completely different one.",
            ))
        else:
            recs.append(Recommendation(
                "common_password_variation", Severity.CRITICAL,
                "This is a small variation of a very common password (swapped symbols "
                "or added digits). Attackers apply these tricks automatically.",
            ))

    # 2. Length
    if length < MIN_LENGTH_CRITICAL:
        recs.append(Recommendation(
            "too_short", Severity.CRITICAL,
            f"Your password is only {length} characters long. Use at least "
            f"{RECOMMENDED_LENGTH}: length is the biggest factor against brute force.",
        ))
    elif length < RECOMMENDED_LENGTH:
        recs.append(Recommendation(
            "short", Severity.WARNING,
            f"Your password is {length} characters long. Aim for at least "
            f"{RECOMMENDED_LENGTH}, ideally {PASSPHRASE_LENGTH} or more.",
        ))

    # 3. Character variety (only matters for shorter passwords)
    if length < PASSPHRASE_LENGTH:
        missing = _missing_classes(password)
        if missing:
            recs.append(Recommendation(
                "missing_character_types", Severity.INFO,
                f"Mix in more character types: add {', '.join(missing)}. "
                "A long passphrase of unrelated words also works well.",
            ))

    # 4. Patterns (one advice per pattern type)
    seen: set[PatternType] = set()
    for finding in result.patterns:
        if finding.pattern_type in seen:
            continue
        seen.add(finding.pattern_type)
        recs.append(Recommendation(
            f"pattern_{finding.pattern_type.value}", Severity.WARNING,
            _PATTERN_ADVICE[finding.pattern_type],
        ))

    # 5. General guidance
    if not recs:
        recs.append(Recommendation(
            "no_weakness_detected", Severity.INFO,
            "No major weakness detected. Keep it unique: never reuse it on another account.",
        ))
    if result.score < STRONG_SCORE:
        recs.append(Recommendation(
            "use_password_manager", Severity.INFO,
            "A password manager can generate and store a unique random password "
            "for every account, so you don't have to memorize them.",
        ))

    order = list(Severity)
    recs.sort(key=lambda r: order.index(r.severity))  # stable sort keeps rule order
    return recs