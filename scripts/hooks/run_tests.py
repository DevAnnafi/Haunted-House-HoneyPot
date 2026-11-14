"""run_tests.py — PostFileSave hook script.

Receives the saved file path from Kiro on stdin as JSON.
Derives the corresponding test module (if any) and runs pytest quietly.
Prints a summary and exits non-zero on failure so Kiro reports it.

Mapping rules:
  honeypot/foo.py          → tests/test_foo.py
  honeypot/commands/foo.py → tests/test_commands.py  (command sub-package)
  api/foo.py               → tests/test_api.py
  shared/foo.py            → tests/test_shared.py (if it exists)
  tests/test_foo.py        → tests/test_foo.py    (saved test file runs itself)

If no corresponding test module exists, the full suite runs instead.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _get_file_path() -> str | None:
    """Read the saved file path from Kiro's stdin JSON payload."""
    if not sys.stdin.isatty():
        try:
            payload = json.load(sys.stdin)
            # Kiro delivers the path under 'file_path'; fall back to other likely keys.
            for key in ("file_path", "path", "filePath"):
                if key in payload:
                    return str(payload[key])
        except (json.JSONDecodeError, ValueError):
            pass
    return None


def _normalise(raw: str) -> str:
    """Strip workspace prefix and normalise to forward slashes."""
    p = raw.replace("\\", "/")
    for prefix in (
        "c:/users/annaf/haunted-house-honeypot/",
        "/workspace/",
        "./",
    ):
        if p.lower().startswith(prefix.lower()):
            p = p[len(prefix) :]
            break
    return p


def _derive_test_path(saved: str) -> Path | None:
    """Return a test module Path for *saved*, or None to run the full suite."""
    p = Path(_normalise(saved))
    parts = p.parts

    if not parts:
        return None

    # A saved test file runs itself.
    if parts[0] == "tests" and p.name.startswith("test_"):
        return p if p.exists() else None

    name = p.stem  # filename without extension

    if parts[0] == "honeypot":
        # Sub-packages under honeypot/commands/ map to tests/test_commands.py.
        if len(parts) >= 2 and parts[1] == "commands":
            candidate = Path("tests") / "test_commands.py"
        else:
            candidate = Path("tests") / f"test_{name}.py"
    elif parts[0] in ("api", "shared"):
        candidate = Path("tests") / f"test_{parts[0]}.py"
    else:
        return None

    return candidate if candidate.exists() else None


def main() -> int:
    saved = _get_file_path()

    if saved:
        test_target = _derive_test_path(saved)
        if test_target:
            target_str = str(test_target)
            label = f"tests for {saved}"
        else:
            target_str = "tests/"
            label = "full test suite (no matching test module found)"
    else:
        target_str = "tests/"
        label = "full test suite"

    print(f"Running {label} …", flush=True)

    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pytest", "-q", "--tb=short", target_str],
        capture_output=True,
        text=True,
        cwd=os.getcwd(),
    )

    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)

    if result.returncode != 0:
        print(f"\n❌ pytest failed (exit {result.returncode})", file=sys.stderr)
    else:
        last_line = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
        print(f"✅ {last_line or 'All tests passed'}")

    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
