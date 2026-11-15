import string
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Literal, Optional

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "common_passwords.txt"

# "1" and "!" are ambiguous: they can stand for "i" or "l".
_LEET_BASE = {
    "@": "a", "4": "a", "8": "b", "3": "e",
    "0": "o", "$": "s", "5": "s", "7": "t",
}
_LEET_AS_I = str.maketrans({**_LEET_BASE, "1": "i", "!": "i"})
_LEET_AS_L = str.maketrans({**_LEET_BASE, "1": "l", "!": "l"})

_TRAILING_CHARS = string.digits + string.punctuation + " "

MatchType = Literal["exact", "variation"]


@dataclass(frozen=True)
class CommonPasswordResult:
    """Outcome of a common-password check. Never contains the matched word."""
    is_common: bool
    match_type: Optional[MatchType] = None


@lru_cache(maxsize=1)
def load_common_passwords() -> frozenset[str]:
    """Load the wordlist once and cache it in memory."""
    words = set()
    with DATA_FILE.open(encoding="utf-8", errors="ignore") as file:
        for line in file:
            word = line.strip().lower()
            if word and not word.startswith("#"):
                words.add(word)
    return frozenset(words)


def _build_variants(password: str) -> set[str]:
    """Generate the likely mangled forms of a password."""
    lowered = password.lower()
    stripped = lowered.rstrip(_TRAILING_CHARS)

    variants = {lowered, stripped}
    for base in (lowered, stripped):
        variants.add(base.translate(_LEET_AS_I))
        variants.add(base.translate(_LEET_AS_L))
    variants.discard("")
    return variants


def check_common_password(password: str) -> CommonPasswordResult:
    """Check a password against the local wordlist, including simple variations."""
    if not password:
        return CommonPasswordResult(is_common=False)

    wordlist = load_common_passwords()

    if password.lower() in wordlist:
        return CommonPasswordResult(is_common=True, match_type="exact")

    if _build_variants(password) & wordlist:
        return CommonPasswordResult(is_common=True, match_type="variation")

    return CommonPasswordResult(is_common=False)