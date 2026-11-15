import re
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache

from app.analyzer.common_passwords import load_common_passwords

MIN_SEQUENCE = 3
MIN_KEYBOARD_WALK = 4
MIN_WORD_LENGTH = 4

# QWERTY and AZERTY rows (the numeric row is covered by the sequence detector).
KEYBOARD_ROWS = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",   # QWERTY
    "azertyuiop", "qsdfghjklm", "wxcvbn",   # AZERTY
]
_ALL_ROWS = KEYBOARD_ROWS + [row[::-1] for row in KEYBOARD_ROWS]


class PatternType(str, Enum):
    REPEATED_CHARACTERS = "repeated_characters"
    REPEATED_BLOCK = "repeated_block"
    SEQUENCE = "sequence"
    KEYBOARD_WALK = "keyboard_walk"
    YEAR = "year"
    DICTIONARY_WORD = "dictionary_word"


@dataclass(frozen=True)
class PatternFinding:
    """A detected weakness. Deliberately never stores the matched text."""
    pattern_type: PatternType
    length: int
    description: str


def detect_repeated_characters(password: str) -> list[PatternFinding]:
    """Find runs of the same character, e.g. 'aaaa'."""
    findings = []
    # (.) captures one char; \1{2,} means "the same char, 2+ more times".
    for match in re.finditer(r"(.)\1{2,}", password.lower(), re.DOTALL):
        n = match.end() - match.start()
        findings.append(PatternFinding(
            PatternType.REPEATED_CHARACTERS, n,
            f"Same character repeated {n} times in a row",
        ))
    return findings


def detect_repeated_block(password: str) -> list[PatternFinding]:
    """Detect a password made of one block repeated, e.g. 'abcabc'."""
    match = re.fullmatch(r"(.{2,}?)\1+", password.lower(), re.DOTALL)
    if not match or len(set(match.group(1))) == 1:
        return []  # no repetition, or single-char case (handled above)
    block = match.group(1)
    times = len(password) // len(block)
    return [PatternFinding(
        PatternType.REPEATED_BLOCK, len(password),
        f"Password is a {len(block)}-character block repeated {times} times",
    )]


def _char_class(char: str):
    """Return 'alpha' or 'digit' for ASCII letters/digits, else None."""
    if char.isascii() and char.isalpha():
        return "alpha"
    if char.isascii() and char.isdigit():
        return "digit"
    return None


def _is_step(a: str, b: str, step: int) -> bool:
    """True if b follows a by `step` in the same class (letters or digits)."""
    cls = _char_class(a)
    return cls is not None and cls == _char_class(b) and ord(b) - ord(a) == step


def detect_sequences(password: str) -> list[PatternFinding]:
    """Find ascending or descending runs like 'abcd', '1234', '4321'."""
    text = password.lower()
    findings = []
    i = 0
    while i < len(text) - 1:
        step = ord(text[i + 1]) - ord(text[i])
        if step in (1, -1) and _is_step(text[i], text[i + 1], step):
            j = i + 1
            while j + 1 < len(text) and _is_step(text[j], text[j + 1], step):
                j += 1
            run = j - i + 1
            if run >= MIN_SEQUENCE:
                direction = "ascending" if step == 1 else "descending"
                findings.append(PatternFinding(
                    PatternType.SEQUENCE, run,
                    f"Sequence of {run} consecutive characters ({direction})",
                ))
            i = j
        else:
            i += 1
    return findings


def detect_keyboard_walks(password: str) -> list[PatternFinding]:
    """Find runs of adjacent keys on QWERTY/AZERTY rows, forward or reversed."""
    text = password.lower()
    findings = []
    i = 0
    while i < len(text):
        longest = 0
        for row in _ALL_ROWS:
            k = MIN_KEYBOARD_WALK
            while i + k <= len(text) and text[i:i + k] in row:
                longest = max(longest, k)
                k += 1
        if longest:
            findings.append(PatternFinding(
                PatternType.KEYBOARD_WALK, longest,
                f"Keyboard pattern of {longest} adjacent keys",
            ))
            i += longest
        else:
            i += 1
    return findings


def detect_years(password: str) -> list[PatternFinding]:
    """Find year-like numbers (1900-2039) not part of a longer digit run."""
    return [
        PatternFinding(PatternType.YEAR, 4, "Contains a year-like number")
        for _ in re.finditer(r"(?<!\d)(?:19\d{2}|20[0-3]\d)(?!\d)", password)
    ]


@lru_cache(maxsize=1)
def _dictionary_words() -> tuple[str, ...]:
    """Alphabetic entries of the wordlist, longest first."""
    words = [w for w in load_common_passwords()
             if len(w) >= MIN_WORD_LENGTH and w.isalpha()]
    return tuple(sorted(words, key=len, reverse=True))


def detect_dictionary_words(password: str) -> list[PatternFinding]:
    """Find common words inside the password (longest first, no overlaps)."""
    text = password.lower()
    consumed = [False] * len(text)
    findings = []
    for word in _dictionary_words():
        start = text.find(word)
        if start == -1:
            continue
        end = start + len(word)
        if any(consumed[start:end]):
            continue
        consumed[start:end] = [True] * len(word)
        findings.append(PatternFinding(
            PatternType.DICTIONARY_WORD, len(word),
            f"Contains a common word ({len(word)} letters)",
        ))
    return findings


def detect_patterns(password: str) -> list[PatternFinding]:
    """Run every detector and return all findings."""
    if not password:
        return []
    findings: list[PatternFinding] = []
    for detector in (
        detect_repeated_characters,
        detect_repeated_block,
        detect_sequences,
        detect_keyboard_walks,
        detect_years,
        detect_dictionary_words,
    ):
        findings.extend(detector(password))
    return findings