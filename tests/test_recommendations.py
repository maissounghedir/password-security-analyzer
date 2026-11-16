from app.analyzer.recommendations import Severity, generate_recommendations
from app.analyzer.strength import analyze_strength


def recs_for(password: str):
    return generate_recommendations(password, analyze_strength(password))


def codes_for(password: str) -> list[str]:
    return [r.code for r in recs_for(password)]


def test_empty_password():
    recs = recs_for("")
    assert [r.code for r in recs] == ["empty_password"]
    assert recs[0].severity == Severity.CRITICAL


def test_common_password_is_critical_and_listed_first():
    recs = recs_for("password")
    assert recs[0].code == "common_password"
    assert recs[0].severity == Severity.CRITICAL


def test_very_short_password():
    recs = recs_for("aB3$")
    assert "too_short" in [r.code for r in recs]
    assert next(r for r in recs if r.code == "too_short").severity == Severity.CRITICAL


def test_medium_length_is_a_warning_not_critical():
    codes = codes_for("xK9#vLq2")  # 8 characters
    assert "short" in codes
    assert "too_short" not in codes


def test_missing_character_types_are_named():
    recs = recs_for("jqzxkvmwhfdb")  # 12 lowercase letters
    message = next(r for r in recs if r.code == "missing_character_types").message
    assert "uppercase letters" in message
    assert "digits" in message
    assert "symbols" in message


def test_long_passphrase_skips_composition_advice():
    assert "missing_character_types" not in codes_for("correct horse battery staple")


def test_pattern_advice_is_generated():
    codes = codes_for("Qwerty1990!")
    assert "pattern_keyboard_walk" in codes
    assert "pattern_year" in codes
    assert "pattern_dictionary_word" in codes


def test_pattern_advice_is_not_duplicated():
    assert codes_for("aaabbbccc").count("pattern_repeated_characters") == 1


def test_strong_password_gets_no_warnings():
    assert codes_for("xK9#vLq2$mWz") == ["no_weakness_detected"]


def test_recommendations_are_sorted_by_severity():
    order = list(Severity)
    indexes = [order.index(r.severity) for r in recs_for("Password1")]
    assert indexes == sorted(indexes)


def test_messages_never_expose_password_content():
    for rec in recs_for("mydragon1990"):
        text = rec.message.lower()
        assert "dragon" not in text
        assert "1990" not in text
        assert "mydragon" not in text