import shlex
from dataclasses import dataclass

MAX_STAGES = 3
UNSUPPORTED = {";", "&&", "||", "&", "<", "(", ")"}
REDIRECT_OPS = {">", ">>"}
OPERATORS = {"|", ">", ">>"}


@dataclass
class CommandCall:
    name: str
    args: list[str]


@dataclass
class Redirect:
    op: str
    target: str


@dataclass
class Pipeline:
    stages: list[CommandCall]
    redirect: Redirect | None = None


@dataclass
class ParseError:
    message: str


def _syntax_error(token: str) -> ParseError:
    return ParseError(f"-bash: syntax error near unexpected token `{token}'")


def parse(line: str) -> Pipeline | ParseError:
    # 1. Tokenize. shlex only splits text; it never runs anything.
    try:
        tokens = list(shlex.shlex(line, posix=True, punctuation_chars=True))
    except ValueError:
        quote = '"' if line.count('"') % 2 else "'"
        return ParseError(f"-bash: unexpected EOF while looking for matching `{quote}'")

    # 2. Reject syntax we never interpret (R2.7). shlex drops quotes, so a
    # quoted ";" is rejected too: a harmless false positive.
    for token in tokens:
        if token in UNSUPPORTED or "`" in token or "$(" in token:
            return _syntax_error(token)

    # 3. Pull off a single trailing redirection.
    redirect = None
    for i, token in enumerate(tokens):
        if token in REDIRECT_OPS:
            after = tokens[i + 1 :]
            if not after:
                return _syntax_error("newline")
            if after[0] in OPERATORS:
                return _syntax_error(after[0])
            if len(after) > 1:
                return _syntax_error(after[1])
            redirect = Redirect(token, after[0])
            tokens = tokens[:i]
            break

    # 4. Split on "|" into groups of tokens, one group per stage.
    groups: list[list[str]] = [[]]
    for token in tokens:
        if token == "|":
            groups.append([])
        else:
            groups[-1].append(token)

    # 5. Check the shape.
    if any(not group for group in groups):
        return _syntax_error("|" if len(groups) > 1 else "newline")
    if len(groups) > MAX_STAGES:
        return _syntax_error("|")

    stages = [CommandCall(group[0], group[1:]) for group in groups]
    return Pipeline(stages, redirect)
