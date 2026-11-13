import math
import string
from dataclasses import dataclass

# Approximate pool size contributed by non-ASCII characters (accents, emoji, other scripts).
# This is a deliberate simplification: the real alphabet is far larger.
UNICODE_POOL = 100


@dataclass(frozen=True)
class EntropyResult:
    """Result of an entropy estimation. All values are estimates."""
    bits: float
    pool_size: int
    length: int
    rating: str


def calculate_pool_size(password: str) -> int:
    """Return the size of the character pool implied by the classes present."""
    pool = 0
    if any(c in string.ascii_lowercase for c in password):
        pool += 26
    if any(c in string.ascii_uppercase for c in password):
        pool += 26
    if any(c in string.digits for c in password):
        pool += 10
    if any(c in string.punctuation for c in password):
        pool += 32
    if " " in password:
        pool += 1
    if any(not c.isascii() for c in password):
        pool += UNICODE_POOL
    return pool


def classify_entropy(bits: float) -> str:
    """Map an entropy value in bits to a human-readable rating."""
    if bits < 28:
        return "Very weak"
    if bits < 36:
        return "Weak"
    if bits < 60:
        return "Reasonable"
    if bits < 128:
        return "Strong"
    return "Very strong"


def calculate_entropy(password: str) -> EntropyResult:
    """Estimate password entropy in bits using E = L * log2(R)."""
    length = len(password)
    pool_size = calculate_pool_size(password)

    if length == 0 or pool_size == 0:
        bits = 0.0
    else:
        bits = round(length * math.log2(pool_size), 2)

    return EntropyResult(
        bits=bits,
        pool_size=pool_size,
        length=length,
        rating=classify_entropy(bits),
    )