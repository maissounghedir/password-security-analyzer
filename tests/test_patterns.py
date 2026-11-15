from app.analyzer.patterns import (
    PatternType,
    detect_dictionary_words,
    detect_keyboard_walks,
    detect_patterns,
    detect_repeated_block,
    detect_repeated_characters,
    detect_sequences,
    detect_years,
)


def test_repeated_characters():
    findings = detect_repeated_characters("aaab")
    assert len(findings) == 1
    assert findings[0].pattern_type == PatternType.REPEATED_CHARACTERS
    assert findings[0].length == 3
    assert detect_repeated_characters("abab") == []


def test_repeated_block():
    assert len(detect_repeated_block("abcabc")) == 1
    assert detect_repeated_block("abcabd") == []
    assert detect_repeated_block("aaaa") == []  # single char: other detector


def test_ascending_and_descending_sequences():
    assert detect_sequences("abcd")[0].length == 4
    assert "descending" in detect_sequences("4321")[0].description
    assert detect_sequences("abd") == []
    assert detect_sequences("a1b2") == []


def test_two_sequences_in_one_password():
    assert len(detect_sequences("abc123")) == 2


def test_keyboard_walks():
    assert detect_keyboard_walks("qwerty")[0].length == 6
    assert detect_keyboard_walks("azerty")[0].length == 6
    assert detect_keyboard_walks("ytrewq")[0].length == 6
    assert detect_keyboard_walks("myqwertyx")[0].length == 6
    assert detect_keyboard_walks("qwe") == []


def test_years():
    assert len(detect_years("john1990")) == 1
    assert detect_years("19900") == []
    assert detect_years("1850") == []


def test_dictionary_words_case_insensitive():
    findings = detect_dictionary_words("MyDragon99")
    assert len(findings) == 1
    assert findings[0].pattern_type == PatternType.DICTIONARY_WORD


def test_strong_random_password_has_no_patterns():
    assert detect_patterns("xK9#vLq2$mWz") == []


def test_empty_password():
    assert detect_patterns("") == []


def test_combined_patterns():
    types = {f.pattern_type for f in detect_patterns("Qwerty1990!")}
    assert {
        PatternType.KEYBOARD_WALK,
        PatternType.YEAR,
        PatternType.DICTIONARY_WORD,
    } <= types


def test_findings_never_expose_password_content():
    for finding in detect_patterns("mydragon1990"):
        assert "dragon" not in finding.description.lower()
        assert "1990" not in finding.description
        assert not hasattr(finding, "text")