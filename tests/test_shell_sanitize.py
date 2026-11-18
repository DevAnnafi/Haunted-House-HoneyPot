"""Tests for ``sanitize_for_terminal`` (R4.9 [PBT]).

Current behaviour under test: every character of Unicode category ``Cc`` except
``\\n`` and ``\\t`` is removed. ESC is a ``Cc`` character, so escape sequences lose
their ESC byte and the remaining parameter bytes are left behind as inert text.
"""

import unicodedata

from hypothesis import given, settings
from hypothesis import strategies as st

from honeypot.shell import sanitize_for_terminal

C0 = [chr(i) for i in range(0x00, 0x20)]
C1 = [chr(i) for i in range(0x80, 0xA0)]
DEL = "\x7f"

# Draws from all categories plus dedicated C0/DEL/C1 and lone-surrogate strategies, so those
# characters are generated often (verified by the coverage test below).
hostile_text = st.lists(
    st.one_of(
        st.characters(codec=None, categories=None, exclude_categories=()),
        st.characters(max_codepoint=0x9F),  # C0, DEL, C1 and printable ASCII
        st.just(DEL),
        st.characters(categories=["Cs"]),  # lone surrogates
    ),
    max_size=200,
).map("".join)


def _is_subsequence(small: str, big: str) -> bool:
    it = iter(big)
    return all(ch in it for ch in small)


# ---------------------------------------------------------------------------
# Strategy coverage
# ---------------------------------------------------------------------------


def test_r4_9_strategy_generates_c0_del_c1_and_surrogates() -> None:
    seen: dict[str, bool] = {"c0": False, "del": False, "c1": False, "surrogate": False}

    @settings(max_examples=300, deadline=None)
    @given(hostile_text)
    def collect(text: str) -> None:
        for ch in text:
            if ch in C0:
                seen["c0"] = True
            elif ch == DEL:
                seen["del"] = True
            elif ch in C1:
                seen["c1"] = True
            elif 0xD800 <= ord(ch) <= 0xDFFF:
                seen["surrogate"] = True

    collect()
    assert seen == {"c0": True, "del": True, "c1": True, "surrogate": True}


# ---------------------------------------------------------------------------
# Property tests
# ---------------------------------------------------------------------------


@settings(max_examples=500, deadline=None)
@given(hostile_text)
def test_r4_9_output_has_no_control_chars_except_newline_and_tab(text: str) -> None:
    out = sanitize_for_terminal(text)
    for ch in out:
        if ch in ("\n", "\t"):
            continue
        assert unicodedata.category(ch) != "Cc", repr(ch)


@settings(max_examples=500, deadline=None)
@given(hostile_text)
def test_r4_9_sanitize_is_idempotent(text: str) -> None:
    once = sanitize_for_terminal(text)
    assert sanitize_for_terminal(once) == once


@settings(max_examples=500, deadline=None)
@given(hostile_text)
def test_r4_9_sanitize_never_raises(text: str) -> None:
    result = sanitize_for_terminal(text)
    assert isinstance(result, str)


@settings(max_examples=500, deadline=None)
@given(hostile_text)
def test_r4_9_output_is_subsequence_of_input(text: str) -> None:
    out = sanitize_for_terminal(text)
    assert len(out) <= len(text)
    assert _is_subsequence(out, text)


# ---------------------------------------------------------------------------
# Example tests
# ---------------------------------------------------------------------------


def test_r4_9_empty_string() -> None:
    assert sanitize_for_terminal("") == ""


def test_r4_9_printable_ascii_unchanged() -> None:
    text = "root@haunted:~# ls -la /etc"
    assert sanitize_for_terminal(text) == text


def test_r4_9_non_ascii_and_emoji_unchanged() -> None:
    text = "\u3053\u3093\u306b\u3061\u306f \U0001f47b caf\u00e9 \u03a9"
    assert sanitize_for_terminal(text) == text


def test_r4_9_newline_and_tab_preserved() -> None:
    assert sanitize_for_terminal("a\tb\nc") == "a\tb\nc"


def test_r4_9_csi_clear_screen_loses_esc() -> None:
    out = sanitize_for_terminal("before\x1b[2J\x1b[Hafter")
    assert out == "before[2J[Hafter"
    assert "\x1b" not in out


def test_r4_9_osc52_clipboard_terminated_by_bel() -> None:
    out = sanitize_for_terminal("x\x1b]52;c;aGVsbG8=\x07y")
    assert out == "x]52;c;aGVsbG8=y"
    assert "\x1b" not in out
    assert "\x07" not in out


def test_r4_9_osc52_clipboard_terminated_by_esc_backslash() -> None:
    out = sanitize_for_terminal("x\x1b]52;c;aGVsbG8=\x1b\\y")
    assert out == "x]52;c;aGVsbG8=\\y"
    assert "\x1b" not in out


def test_r4_9_osc8_hyperlink_loses_esc_and_bel() -> None:
    out = sanitize_for_terminal("\x1b]8;;http://evil.example/\x07click\x1b]8;;\x07")
    assert out == "]8;;http://evil.example/click]8;;"
    assert "\x1b" not in out
    assert "\x07" not in out


def test_r4_9_c1_csi_9b_removed() -> None:
    assert sanitize_for_terminal("a\x9b2Jb") == "a2Jb"


def test_r4_9_all_c1_controls_removed() -> None:
    assert sanitize_for_terminal("".join(C1)) == ""


def test_r4_9_carriage_return_overwrite_removed() -> None:
    assert sanitize_for_terminal("password: ok\rFAKE") == "password: okFAKE"


def test_r4_9_del_removed() -> None:
    assert sanitize_for_terminal("ab\x7fcd") == "abcd"


def test_r4_9_backspace_removed() -> None:
    assert sanitize_for_terminal("abc\x08\x08X") == "abcX"


def test_r4_9_lone_surrogate_does_not_raise() -> None:
    assert isinstance(sanitize_for_terminal("a\ud800b"), str)
