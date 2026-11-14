"""Smoke test: verify the three top-level packages are importable.

This is the minimum test required so that pytest collects at least one item
in CI.  Pytest exits with code 5 when it collects zero tests, which would
fail the pipeline even before any real logic is tested.
"""

import api
import honeypot
import shared


def test_packages_are_importable() -> None:
    """honeypot, api, and shared must all import without error."""
    assert honeypot.__doc__ is not None
    assert api.__doc__ is not None
    assert shared.__doc__ is not None
