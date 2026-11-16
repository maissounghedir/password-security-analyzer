from collections import Counter

import pytest

import app.generator.password_generator as generator
from app.analyzer.strength import analyze_strength
from app.generator.password_generator import (
    AMBIGUOUS_CHARS,
    GeneratorOptions,
    generate_password,
)


def test_default_length():
    assert len(generate_password()) == 16


@pytest.mark.parametrize("length", [8, 24, 128])
def test_custom_length(length):
    assert len(generate_password(GeneratorOptions(length=length))) == length


@pytest.mark.parametrize("length", [7, 129, 0, -5])
def test_invalid_length_is_rejected(length):
    with pytest.raises(ValueError):
        GeneratorOptions(length=length)


def test_at_least_one_character_type_required():
    with pytest.raises(ValueError):
        GeneratorOptions(
            use_lowercase=False, use_uppercase=False,
            use_digits=False, use_symbols=False,
        )


def test_every_enabled_type_is_present():
    for _ in range(300):
        password = generate_password(GeneratorOptions(length=8))
        assert any(c.islower() for c in password)
        assert any(c.isupper() for c in password)
        assert any(c.isdigit() for c in password)
        assert any(not c.isalnum() for c in password)


def test_only_enabled_types_are_used():
    options = GeneratorOptions(
        length=40, use_lowercase=False, use_uppercase=False, use_symbols=False,
    )
    assert generate_password(options).isdigit()


def test_ambiguous_characters_are_excluded():
    options = GeneratorOptions(length=64, exclude_ambiguous=True)
    for _ in range(300):
        assert not set(generate_password(options)) & AMBIGUOUS_CHARS


def test_passwords_are_unique():
    passwords = {generate_password() for _ in range(1000)}
    assert len(passwords) == 1000


def test_digit_distribution_is_roughly_uniform():
    # 200 x 128 = 25,600 digits: expected ~2,560 each (std dev ~48).
    options = GeneratorOptions(
        length=128, use_lowercase=False, use_uppercase=False, use_symbols=False,
    )
    counts = Counter("".join(generate_password(options) for _ in range(200)))
    for digit in "0123456789":
        assert 2260 < counts[digit] < 2860  # about +/- 6 standard deviations


def test_module_does_not_use_insecure_random():
    assert not hasattr(generator, "random")


def test_generated_passwords_score_as_strong():
    for _ in range(50):
        assert analyze_strength(generate_password()).score >= 70