import secrets
import string
from dataclasses import dataclass

MIN_LENGTH = 8
MAX_LENGTH = 128
DEFAULT_LENGTH = 16

# Characters easily confused when read or typed: I, l, 1, O, 0, o
AMBIGUOUS_CHARS = frozenset("Il1O0o")


@dataclass(frozen=True)
class GeneratorOptions:
    """Validated settings for password generation."""
    length: int = DEFAULT_LENGTH
    use_lowercase: bool = True
    use_uppercase: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    exclude_ambiguous: bool = False

    def __post_init__(self) -> None:
        if not MIN_LENGTH <= self.length <= MAX_LENGTH:
            raise ValueError(f"length must be between {MIN_LENGTH} and {MAX_LENGTH}")
        if not any((self.use_lowercase, self.use_uppercase,
                    self.use_digits, self.use_symbols)):
            raise ValueError("at least one character type must be enabled")


def _selected_pools(options: GeneratorOptions) -> list[str]:
    """Return one character pool per enabled character type."""
    candidates = [
        (options.use_lowercase, string.ascii_lowercase),
        (options.use_uppercase, string.ascii_uppercase),
        (options.use_digits, string.digits),
        (options.use_symbols, string.punctuation),
    ]
    pools = []
    for enabled, chars in candidates:
        if not enabled:
            continue
        if options.exclude_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS_CHARS)
        pools.append(chars)
    return pools


def _secure_shuffle(items: list[str]) -> None:
    """In-place Fisher-Yates shuffle using a cryptographically secure RNG."""
    for i in range(len(items) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        items[i], items[j] = items[j], items[i]


def generate_password(options: GeneratorOptions | None = None) -> str:
    """Generate a random password using the OS's cryptographically secure RNG."""
    options = options or GeneratorOptions()
    pools = _selected_pools(options)
    all_chars = "".join(pools)

    # One guaranteed character per enabled type, then fill the remainder.
    chars = [secrets.choice(pool) for pool in pools]
    chars += [secrets.choice(all_chars) for _ in range(options.length - len(chars))]

    _secure_shuffle(chars)
    return "".join(chars)