"""ownership_guard.py -- PreToolUse hook script.

Blocks agent file-write, file-edit, and shell-command tool calls that would
modify developer-owned paths under honeypot/ (except honeypot/__init__.py).

Developer-owned paths (from conventions.md):
  honeypot/  -- SSH layer, command engine, VFS, haunt engine, LLM fallback,
               session recorder, ATT&CK detection rules.
  Excluded: honeypot/__init__.py (Kiro-generated stub, always allowed).

Two classes of tool call are intercepted:

1. File tools (fs_write, fs_append, str_replace, delete_file):
   The target path is read directly from tool_input["path"].  If it resolves
   to a developer-owned honeypot path the call is blocked.

2. Shell tools (execute_pwsh, execute_bash):
   The command string is read from tool_input["command"].  If the string
   contains both a reference to a developer-owned honeypot path and a write
   operation keyword the call is blocked.

   NOTE -- shell detection is best-effort.  A determined agent (or a human
   copy-pasting) can craft a command that bypasses this heuristic (e.g. via
   shell variables, heredocs, or base64-encoded payloads).  This hook is a
   convenience reminder, not a security boundary.  Final enforcement is a
   mandatory review of every diff before it is committed.

Exit codes (per Kiro hook docs):
  0        -- allow the tool call (stdout added to agent context)
  non-zero -- block the tool call (stderr returned as the reason)
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import PurePosixPath

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

# Paths under honeypot/ that Kiro is explicitly allowed to touch.
ALLOWED_HONEYPOT_FILES: frozenset[str] = frozenset(
    [
        "honeypot/__init__.py",
    ]
)

# Shell tool IDs on each platform.
_SHELL_TOOLS: frozenset[str] = frozenset(["execute_pwsh", "execute_bash"])

# ---------------------------------------------------------------------------
# Write-operation keywords for shell-command heuristic.
#
# Covers:
#   POSIX redirections  >  >>
#   PowerShell cmdlets  Set-Content  Add-Content  Out-File  New-Item
#                       Copy-Item  Move-Item  Remove-Item
#   Common Unix tools   cp  mv  rm  tee
#   Python file writes  open(..., "w")  open(..., "a")  .write(
#   PowerShell          [IO.File]::WriteAllText  [IO.File]::AppendAllText
# ---------------------------------------------------------------------------
_WRITE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r">>?"),  # POSIX > and >>
    re.compile(r"\bSet-Content\b", re.IGNORECASE),
    re.compile(r"\bAdd-Content\b", re.IGNORECASE),
    re.compile(r"\bOut-File\b", re.IGNORECASE),
    re.compile(r"\bNew-Item\b", re.IGNORECASE),
    re.compile(r"\bCopy-Item\b", re.IGNORECASE),
    re.compile(r"\bMove-Item\b", re.IGNORECASE),
    re.compile(r"\bRemove-Item\b", re.IGNORECASE),
    re.compile(r"\bcp\b"),
    re.compile(r"\bmv\b"),
    re.compile(r"\brm\b"),
    re.compile(r"\btee\b"),
    re.compile(r'\bopen\s*\([^)]*["\']w[a-z]*["\']'),  # open(..., "w")
    re.compile(r'\bopen\s*\([^)]*["\']a[a-z]*["\']'),  # open(..., "a")
    re.compile(r"\.write\("),
    re.compile(r"\[IO\.File\]::WriteAllText\b", re.IGNORECASE),
    re.compile(r"\[IO\.File\]::AppendAllText\b", re.IGNORECASE),
    re.compile(r"\bfs_write\b"),  # agent tool name appearing in a command
]


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def _normalise(raw: str) -> str:
    """Normalise a path to forward-slash form relative to the project root.

    Kiro may pass absolute paths or paths with backslashes on Windows.
    We strip the workspace prefix and normalise separators so comparisons
    work consistently across platforms.
    """
    # Replace backslashes, then collapse any run of slashes (e.g. // from \\)
    # so that prefix matching works regardless of escaping in the JSON payload.
    normalised = raw.replace("\\", "/")
    while "//" in normalised:
        normalised = normalised.replace("//", "/")
    for prefix in (
        "c:/users/annaf/haunted-house-honeypot/",
        "/workspace/",
        "./",
    ):
        lower = normalised.lower()
        if lower.startswith(prefix.lower()):
            normalised = normalised[len(prefix) :]
            break
    return normalised


def _is_developer_owned(repo_path: str) -> bool:
    """Return True if repo_path is in a developer-owned area."""
    p = PurePosixPath(repo_path)
    parts = p.parts
    if not parts:
        return False
    if parts[0] != "honeypot":
        return False
    if repo_path in ALLOWED_HONEYPOT_FILES:
        return False
    return True


# ---------------------------------------------------------------------------
# Per-tool-type checks
# ---------------------------------------------------------------------------


def _check_file_tool(tool_input: dict) -> str | None:
    """Return a block reason if a file tool targets a developer-owned path, else None.

    If the target path cannot be determined from the payload the call is blocked:
    we cannot verify the path is safe, so we fail closed.
    """
    raw_path = tool_input.get("path")
    if raw_path is None:
        return (
            "Ownership guard: file-write tool called but the target path could not be\n"
            "determined from the hook payload (no 'path' key in tool_input).\n"
            "\n"
            "Blocking the call because the path cannot be verified against the\n"
            "developer-owned areas defined in conventions.md.\n"
            "\n"
            "To proceed, confirm the target path is not under honeypot/ and retry,\n"
            "or ask the developer to explicitly authorise this tool call."
        )
    repo_path = _normalise(str(raw_path))
    if _is_developer_owned(repo_path):
        return (
            f"Ownership guard: '{repo_path}' is in a developer-owned area.\n"
            "\n"
            "Per conventions.md, the developer writes the SSH layer, command engine,\n"
            "virtual filesystem, haunt engine, LLM fallback, session recorder, and\n"
            "ATT&CK detection rules under honeypot/. Kiro must NOT write or modify\n"
            "these files unless explicitly asked.\n"
            "\n"
            "To proceed, the developer must explicitly instruct Kiro to edit this file."
        )
    return None


def _normalise_command(raw: str) -> str:
    """Normalise a shell command string for path matching.

    Replaces backslashes with forward slashes, collapses repeated slashes,
    and lowercases the result so that path comparisons are
    case-insensitive and slash-style-independent.
    """
    normalised = raw.replace("\\", "/")
    while "//" in normalised:
        normalised = normalised.replace("//", "/")
    return normalised.lower()


def _check_shell_tool(tool_input: dict) -> str | None:
    """Return a block reason if a shell command looks like it writes a developer-owned path.

    This is best-effort heuristic detection.  See the module docstring for the
    enforcement note.

    Matching strategy:
    - The command is normalised to lower-case forward-slash form before any
      pattern is applied, so backslash paths (Windows) and mixed-case names
      are caught.
    - The path pattern matches 'honeypot/' preceded only by a word boundary,
      a quote character, or a slash, so it fires for relative paths
      (honeypot/foo.py), absolute paths (.../haunted-house-honeypot/honeypot/),
      and quoted variants ("honeypot/foo.py").
    """
    command = tool_input.get("command")
    if not command:
        return None

    # Normalise the whole command text before matching.
    normalised_cmd = _normalise_command(command)

    # Match 'honeypot/' unless it is immediately preceded by a word character
    # or hyphen (which would make it part of a longer name like 'not-a-honeypot/').
    # This fires for relative paths (honeypot/foo.py), absolute paths
    # (.../honeypot/foo.py), quoted paths ("honeypot/foo.py"), unquoted paths
    # after a space (Remove-Item honeypot\foo.py), after -Path: flags, and
    # inside parentheses.
    # Capture everything up to the next whitespace or quote as the path tail.
    path_re = re.compile(r'(?<![\w\-])honeypot/([\w./\-]*)')
    matches = path_re.findall(normalised_cmd)

    # Reconstruct the full relative path and check developer ownership.
    developer_owned_refs: list[str] = []
    for tail in matches:
        repo_path = f"honeypot/{tail}" if tail else "honeypot/"
        if _is_developer_owned(repo_path):
            developer_owned_refs.append(repo_path)

    if not developer_owned_refs:
        return None

    # Check whether the command also contains a write operation.
    has_write = any(pat.search(command) for pat in _WRITE_PATTERNS)
    if not has_write:
        return None

    refs_str = ", ".join(f"'{r}'" for r in developer_owned_refs)
    return (
        f"Ownership guard: shell command references developer-owned path(s) "
        f"{refs_str} with a write operation.\n"
        "\n"
        "Per conventions.md, the developer writes the code under honeypot/. Kiro\n"
        "must NOT write to these paths unless explicitly asked.\n"
        "\n"
        "NOTE: shell-command detection is best-effort. Final enforcement is a\n"
        "mandatory review of every diff before it is committed.\n"
        "\n"
        "To proceed, the developer must explicitly instruct Kiro to run this command."
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    try:
        raw = sys.stdin.read()
        payload = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        print(
            f"Ownership guard: could not parse hook payload from stdin: {exc}\n"
            "\n"
            "The tool call cannot be verified against developer-owned paths.\n"
            "Blocking to fail closed. Check that the hook runtime is piping\n"
            "a valid JSON payload to this script.",
            file=sys.stderr,
        )
        return 2
    except Exception as exc:
        print(
            f"Ownership guard: unexpected error reading stdin: {exc}\n"
            "\n"
            "Blocking to fail closed.",
            file=sys.stderr,
        )
        return 2

    tool_name: str = payload.get("tool_name", "")
    tool_input: dict = payload.get("tool_input", {})

    if tool_name in _SHELL_TOOLS:
        reason = _check_shell_tool(tool_input)
    else:
        reason = _check_file_tool(tool_input)

    if reason:
        print(reason, file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
