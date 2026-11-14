"""security_scan.py — PostFileSave hook script.

Receives the saved file path from Kiro on stdin as JSON.
Scans the file for forbidden calls and reports findings with file and line
number.  Exits non-zero if any forbidden pattern is found so Kiro reports it.

Forbidden patterns (from conventions.md security rules):
  subprocess          — any reference to the subprocess module
  os.system(          — direct shell execution
  os.popen(           — direct shell execution via pipe
  eval(               — arbitrary code evaluation
  exec(               — arbitrary code execution

These patterns must never appear in code that handles attacker input.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Each entry is (display_name, literal_substring_to_search).
# The search is case-sensitive and matches anywhere on a line.
FORBIDDEN: list[tuple[str, str]] = [
    ("subprocess", "subprocess"),
    ("os.system(", "os.system("),
    ("os.popen(", "os.popen("),
    ("eval(", "eval("),
    ("exec(", "exec("),
]


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


def _scan(file_path: Path) -> list[tuple[int, str, str]]:
    """Return a list of (line_number, pattern_name, line_text) findings."""
    findings: list[tuple[int, str, str]] = []
    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        print(f"security_scan: cannot read {file_path}: {exc}", file=sys.stderr)
        return findings

    for lineno, line in enumerate(lines, start=1):
        # Skip comment-only lines (they may legitimately name the patterns).
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        for name, pattern in FORBIDDEN:
            if pattern in line:
                findings.append((lineno, name, line.rstrip()))

    return findings


def _scan_all_honeypot() -> list[tuple[Path, int, str, str]]:
    """Scan every .py file under honeypot/ and return (path, lineno, name, text) tuples."""
    all_findings: list[tuple[Path, int, str, str]] = []
    honeypot_dir = Path("honeypot")
    if honeypot_dir.is_dir():
        for py_file in sorted(honeypot_dir.rglob("*.py")):
            for lineno, name, text in _scan(py_file):
                all_findings.append((py_file, lineno, name, text))
    return all_findings


def main() -> int:
    raw_path = _get_file_path()

    if raw_path is None:
        # Fail closed: if the payload didn't include a file path, scan every
        # .py file under honeypot/ rather than silently skipping.
        print(
            "security_scan: no file path in payload — scanning all of honeypot/ …",
            flush=True,
        )
        all_findings = _scan_all_honeypot()
        if not all_findings:
            print("✅ security_scan: no forbidden patterns found in honeypot/")
            return 0
        print("🚨 security_scan: forbidden pattern(s) found:", file=sys.stderr)
        for fp, lineno, name, text in all_findings:
            print(f"  {fp}:{lineno}: [{name}]  {text}", file=sys.stderr)
        print(
            "\nThese patterns must never appear in code that handles attacker input "
            "(conventions.md security rules).",
            file=sys.stderr,
        )
        return 1

    file_path = Path(raw_path)
    if not file_path.exists():
        # File may have been deleted; nothing to scan.
        return 0

    findings = _scan(file_path)

    if not findings:
        print(f"✅ security_scan: no forbidden patterns found in {file_path}")
        return 0

    print(
        f"🚨 security_scan: forbidden pattern(s) found in {file_path}:",
        file=sys.stderr,
    )
    for lineno, name, text in findings:
        print(f"  {file_path}:{lineno}: [{name}]  {text}", file=sys.stderr)

    print(
        "\nThese patterns must never appear in code that handles attacker input "
        "(conventions.md security rules).",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
