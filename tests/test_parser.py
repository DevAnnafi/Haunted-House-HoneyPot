"""Tests for honeypot/commands/parser.py (R2.5 pipelines/redirection, R2.7 unsupported syntax)."""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from honeypot.commands.parser import (
    MAX_STAGES,
    UNSUPPORTED,
    CommandCall,
    ParseError,
    Pipeline,
    Redirect,
    parse,
)

# --- strategies -------------------------------------------------------------

# Biased towards the characters the parser treats specially.
_SPECIAL = [
    *"\"'|>;&<$(){}`\\ \t\n#*?~",
    "$(",
    "&&",
    "||",
    ">>",
    "\u00e9",
    "\u2603",
    "\U0001f47b",
    "\x00",
]
_special_text = st.lists(
    st.one_of(st.sampled_from(_SPECIAL), st.text(max_size=5)),
    max_size=30,
).map("".join)
any_line = st.one_of(st.text(max_size=200), _special_text)


def _err(message: str) -> ParseError:
    return ParseError(message)


def _syntax(token: str) -> ParseError:
    return ParseError(f"-bash: syntax error near unexpected token `{token}'")


def _ok(result: Pipeline | ParseError) -> Pipeline:
    assert isinstance(result, Pipeline), result
    return result


# --- property tests ---------------------------------------------------------


@settings(max_examples=500, deadline=None)
@given(any_line)
def test_r2_5_parse_never_raises_and_returns_known_type(line: str) -> None:
    result = parse(line)
    assert isinstance(result, (Pipeline, ParseError))


@settings(max_examples=500, deadline=None)
@given(any_line)
def test_r2_5_pipeline_shape_invariants(line: str) -> None:
    result = parse(line)
    if not isinstance(result, Pipeline):
        return
    assert 1 <= len(result.stages) <= MAX_STAGES
    for stage in result.stages:
        # An empty name is valid: bash treats "" as a command and reports
        # "-bash: : command not found", so the parser must not reject it.
        assert isinstance(stage.name, str)
        for word in [stage.name, *stage.args]:
            assert "`" not in word
            assert "$(" not in word
            assert word not in UNSUPPORTED
    if result.redirect is not None:
        assert result.redirect.op in {">", ">>"}
        assert result.redirect.target != ""


@settings(max_examples=500, deadline=None)
@given(any_line)
def test_r2_7_parse_errors_start_with_bash_prefix(line: str) -> None:
    result = parse(line)
    if isinstance(result, ParseError):
        assert result.message.startswith("-bash: ")


# --- R2.5 examples: commands, pipelines, redirects --------------------------


def test_r2_5_single_command_no_args() -> None:
    assert parse("ls") == Pipeline([CommandCall("ls", [])], None)


def test_r2_5_single_command_with_args() -> None:
    assert parse("ls -la /etc") == Pipeline([CommandCall("ls", ["-la", "/etc"])], None)


def test_r2_5_extra_whitespace_is_ignored() -> None:
    assert parse("  ls \t -l   ") == Pipeline([CommandCall("ls", ["-l"])], None)


def test_r2_5_double_quoted_argument_is_one_word() -> None:
    assert parse('echo "hello world"') == Pipeline([CommandCall("echo", ["hello world"])], None)


def test_r2_5_single_quoted_argument_is_one_word() -> None:
    assert parse("echo 'a  b'") == Pipeline([CommandCall("echo", ["a  b"])], None)


def test_r2_5_quoted_pipe_char_inside_word_is_not_a_split() -> None:
    assert parse('echo "a|b"') == Pipeline([CommandCall("echo", ["a|b"])], None)


def test_r2_5_two_stage_pipeline() -> None:
    assert parse("cat /etc/passwd | grep root") == Pipeline(
        [CommandCall("cat", ["/etc/passwd"]), CommandCall("grep", ["root"])], None
    )


def test_r2_5_three_stage_pipeline() -> None:
    assert parse("ps aux | grep ssh | wc -l") == Pipeline(
        [
            CommandCall("ps", ["aux"]),
            CommandCall("grep", ["ssh"]),
            CommandCall("wc", ["-l"]),
        ],
        None,
    )


def test_r2_5_pipe_without_spaces() -> None:
    assert parse("ls|wc") == Pipeline([CommandCall("ls", []), CommandCall("wc", [])], None)


def test_r2_5_redirect_truncate() -> None:
    assert parse("echo hi > out") == Pipeline([CommandCall("echo", ["hi"])], Redirect(">", "out"))


def test_r2_5_redirect_append() -> None:
    assert parse("echo hi >> out") == Pipeline([CommandCall("echo", ["hi"])], Redirect(">>", "out"))


def test_r2_5_redirect_without_spaces_truncate() -> None:
    assert parse("echo hi>out") == Pipeline([CommandCall("echo", ["hi"])], Redirect(">", "out"))


def test_r2_5_redirect_without_spaces_append() -> None:
    assert parse("echo hi>>out") == Pipeline([CommandCall("echo", ["hi"])], Redirect(">>", "out"))


def test_r2_5_pipeline_with_redirect() -> None:
    assert parse("cat a | sort > b") == Pipeline(
        [CommandCall("cat", ["a"]), CommandCall("sort", [])], Redirect(">", "b")
    )


def test_r2_5_quoted_redirect_target() -> None:
    assert parse('echo hi > "my file"') == Pipeline(
        [CommandCall("echo", ["hi"])], Redirect(">", "my file")
    )


# --- R2.5 error cases: pipelines and redirects ------------------------------


def test_r2_5_four_stages_rejected() -> None:
    assert parse("a | b | c | d") == _syntax("|")


def test_r2_5_leading_pipe_rejected() -> None:
    assert parse("| ls") == _syntax("|")


def test_r2_5_trailing_pipe_rejected() -> None:
    assert parse("ls |") == _syntax("|")


def test_r2_5_double_pipe_with_space_rejected() -> None:
    assert parse("ls | | wc") == _syntax("|")


def test_r2_5_redirect_without_target_rejected() -> None:
    assert parse("echo hi >") == _syntax("newline")


def test_r2_5_append_without_target_rejected() -> None:
    assert parse("echo hi >>") == _syntax("newline")


def test_r2_5_redirect_followed_by_redirect_rejected() -> None:
    assert parse("echo hi > > out") == _syntax(">")


def test_r2_5_redirect_followed_by_pipe_rejected() -> None:
    assert parse("echo hi > | wc") == _syntax("|")


def test_r2_5_two_redirects_rejected() -> None:
    assert parse("echo hi > a > b") == _syntax(">")


def test_r2_5_two_redirects_mixed_ops_rejected() -> None:
    assert parse("echo hi > a >> b") == _syntax(">>")


def test_r2_5_extra_words_after_target_rejected() -> None:
    assert parse("echo hi > out extra") == _syntax("extra")


def test_r2_5_pipe_after_redirect_target_rejected() -> None:
    assert parse("echo hi > out | wc") == _syntax("|")


def test_r2_5_redirect_with_no_command_rejected() -> None:
    assert parse("> out") == _syntax("newline")


def test_r2_5_quoted_empty_command_name_is_a_stage() -> None:
    assert parse('""') == Pipeline([CommandCall("", [])], None)


def test_r2_5_quoted_empty_command_name_in_pipeline() -> None:
    assert parse('echo hi | ""') == Pipeline(
        [CommandCall("echo", ["hi"]), CommandCall("", [])], None
    )


def test_r2_5_empty_line_rejected() -> None:
    result = parse("")
    assert isinstance(result, ParseError)
    assert result.message.startswith("-bash: ")


# --- R2.7 unsupported syntax ------------------------------------------------


def test_r2_7_unclosed_double_quote() -> None:
    assert parse('echo "hi') == _err("-bash: unexpected EOF while looking for matching `\"'")


def test_r2_7_unclosed_single_quote() -> None:
    assert parse("echo 'hi") == _err("-bash: unexpected EOF while looking for matching `''")


def test_r2_7_semicolon() -> None:
    assert parse("ls; whoami") == _syntax(";")


def test_r2_7_semicolon_with_spaces() -> None:
    assert parse("ls ; whoami") == _syntax(";")


def test_r2_7_and_and() -> None:
    assert parse("ls && whoami") == _syntax("&&")


def test_r2_7_or_or() -> None:
    assert parse("ls || whoami") == _syntax("||")


def test_r2_7_background_ampersand() -> None:
    assert parse("sleep 100 &") == _syntax("&")


def test_r2_7_input_redirect() -> None:
    assert parse("cat < /etc/passwd") == _syntax("<")


def test_r2_7_command_substitution_dollar_paren() -> None:
    assert parse("echo $(whoami)") == _syntax("(")


def test_r2_7_subshell_parens() -> None:
    assert parse("(ls)") == _syntax("(")


def test_r2_7_backticks() -> None:
    assert parse("echo `id`") == _syntax("`")


def test_r2_7_backticks_inside_double_quotes() -> None:
    assert parse('echo "`id`"') == _syntax("`id`")


@pytest.mark.parametrize("line", ["ls;", "ls&&", "ls||", "ls&", "ls<x", "ls$(x)", "ls`x`"])
def test_r2_7_unsupported_syntax_without_spaces_is_error(line: str) -> None:
    result = parse(line)
    assert isinstance(result, ParseError)
    assert result.message.startswith("-bash: ")
