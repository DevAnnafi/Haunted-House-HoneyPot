r"""check_attack_ids.py — PostFileSave hook script for honeypot/attack.py.

Receives the saved file path from Kiro on stdin as JSON (always attack.py for
this hook, but the script validates it defensively).

Scans every string literal in the file for MITRE ATT&CK technique IDs and
reports any that do not match the canonical format:

    T\d{4}(\.\d{3})?

Examples of valid IDs:  T1059, T1059.001, T1136.003
Examples of invalid IDs: t1059, T999, T10590, T1059.01, TA0002

Exits non-zero if any invalid ID is found so Kiro reports it.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# Pattern that *looks like* an ATT&CK technique ID (candidate finder).
# Matches any T followed by digits, with an optional sub-technique suffix.
_CANDIDATE_RE = re.compile(r"\bT\d{3,}(?:\.\d+)?\b")

# Pattern that an ID *must* fully match to be valid.
_VALID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def _get_file_path() -> str | None:
    """Read the saved file path from Kiro's stdin JSON payload."""
    if not sys.stdin.isatty():
        try:
            payload = json.load(sys.stdin)
            for key in ("file_path", "path", "filePath"):
                if key in payload:
                    return str(payload[key])
        except (json.JSONDecodeError, ValueError):
            pass
    return None


def _check(file_path: Path) -> list[tuple[int, str]]:
    """Return a list of (line_number, invalid_id) pairs."""
    invalid: list[tuple[int, str]] = []
    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        print(f"check_attack_ids: cannot read {file_path}: {exc}", file=sys.stderr)
        return invalid

    for lineno, line in enumerate(lines, start=1):
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        for candidate in _CANDIDATE_RE.findall(line):
            if not _VALID_RE.match(candidate):
                invalid.append((lineno, candidate))

    return invalid


def main() -> int:
    raw_path = _get_file_path()
    if raw_path is None:
        print("check_attack_ids: no file path received on stdin; nothing to check.")
        return 0

    file_path = Path(raw_path)
    if not file_path.exists():
        return 0

    # Only meaningful for attack.py, but run on whatever path is given.
    invalids = _check(file_path)

    if not invalids:
        print(f"✅ check_attack_ids: all technique IDs valid in {file_path}")
        return 0

    print(
        f"❌ check_attack_ids: invalid MITRE ATT&CK technique ID(s) in {file_path}:",
        file=sys.stderr,
    )
    for lineno, bad_id in invalids:
        print(
            rf"  {file_path}:{lineno}: '{bad_id}' — must match T\d{{4}}(\.\d{{3}})?",
            file=sys.stderr,
        )
    print(
        "\nValid examples: T1059, T1059.001, T1136.003",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
