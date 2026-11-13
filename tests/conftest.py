"""Shared pytest fixtures for the haunted-house-honeypot test suite.

Fixtures that need a real database are marked with the ``db`` fixture (not yet
implemented; added in T5.4).  All other tests run without a database using
the ``InMemoryRecorder`` defined in T2.9.
"""

# ---------------------------------------------------------------------------
# Event-loop policy: psycopg's async driver does not work with the Windows
# Proactor event loop.  Switch to the Selector loop on Windows so integration
# tests that touch PostgreSQL work in development.
# ---------------------------------------------------------------------------
import asyncio
import sys

if sys.platform == "win32":
    # WindowsSelectorEventLoopPolicy was deprecated in Python 3.14 and is
    # slated for removal in 3.16.  On Python 3.14+ the selector loop is
    # already the default on Windows, so the explicit set is a no-op but
    # avoids the DeprecationWarning.
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
