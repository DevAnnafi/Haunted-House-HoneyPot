"""Unit tests for honeypot/auth.py (T1.8). Satisfies R1.3, R1.5, R1.6, R1.15."""

import re
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from honeypot.auth import AuthPolicy, ConfigurationError, load_auth_policy_from_env

# Obviously fake test-only values. Never real secrets.
FAKE_SECRET_HEX = "deadbeef" * 8
OTHER_FAKE_SECRET_HEX = "cafebabe" * 8
DEMO_USER = "demo-user"
DEMO_PASS = "demo-pass-not-real"

HEX64 = re.compile(r"[0-9a-f]{64}")

CREDENTIALS_TOML = """\
[[credentials]]
username = "root"
password = "toor"

[[credentials]]
username = "admin"
password = "admin123"
"""


@pytest.fixture
def credentials_file(tmp_path: Path) -> Path:
    path = tmp_path / "credentials.toml"
    path.write_text(CREDENTIALS_TOML, encoding="utf-8")
    return path


@pytest.fixture
def policy(credentials_file: Path) -> AuthPolicy:
    return AuthPolicy(credentials_file, FAKE_SECRET_HEX, DEMO_USER, DEMO_PASS)


# --- check() ---


def test_r1_3_check_accepts_listed_pair(policy: AuthPolicy) -> None:
    assert policy.check("root", "toor") is True
    assert policy.check("admin", "admin123") is True


def test_r1_3_check_rejects_listed_username_unlisted_password(policy: AuthPolicy) -> None:
    assert policy.check("root", "wrong-password") is False


def test_r1_3_check_rejects_listed_password_with_other_listed_username(
    policy: AuthPolicy,
) -> None:
    # Both values are on the list, but not as a pair.
    assert policy.check("root", "admin123") is False
    assert policy.check("admin", "toor") is False


def test_r1_5_check_accepts_demo_credentials(policy: AuthPolicy) -> None:
    assert policy.check(DEMO_USER, DEMO_PASS) is True


def test_r1_5_check_rejects_demo_username_with_wrong_password(policy: AuthPolicy) -> None:
    assert policy.check(DEMO_USER, "wrong-password") is False


def test_r1_3_check_rejects_empty_username_and_password(policy: AuthPolicy) -> None:
    assert policy.check("", "") is False


# --- fingerprint() ---


def test_r1_6_fingerprint_is_64_lowercase_hex(policy: AuthPolicy) -> None:
    assert HEX64.fullmatch(policy.fingerprint("hunter2")) is not None


def test_r1_6_fingerprint_same_password_same_secret_is_identical(
    credentials_file: Path,
) -> None:
    a = AuthPolicy(credentials_file, FAKE_SECRET_HEX, DEMO_USER, DEMO_PASS)
    b = AuthPolicy(credentials_file, FAKE_SECRET_HEX, DEMO_USER, DEMO_PASS)
    assert a.fingerprint("hunter2") == a.fingerprint("hunter2")
    assert a.fingerprint("hunter2") == b.fingerprint("hunter2")


def test_r1_6_fingerprint_differs_for_different_passwords(policy: AuthPolicy) -> None:
    assert policy.fingerprint("hunter2") != policy.fingerprint("hunter3")


def test_r1_6_fingerprint_differs_under_different_secret(credentials_file: Path) -> None:
    a = AuthPolicy(credentials_file, FAKE_SECRET_HEX, DEMO_USER, DEMO_PASS)
    b = AuthPolicy(credentials_file, OTHER_FAKE_SECRET_HEX, DEMO_USER, DEMO_PASS)
    assert a.fingerprint("hunter2") != b.fingerprint("hunter2")


@given(password=st.text())
def test_r1_6_fingerprint_is_hex_and_never_contains_password(password: str) -> None:
    # Hypothesis forbids function-scoped fixtures here, so build the policy inline.
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "credentials.toml"
        path.write_text(CREDENTIALS_TOML, encoding="utf-8")
        fp = AuthPolicy(path, FAKE_SECRET_HEX, DEMO_USER, DEMO_PASS).fingerprint(password)
    assert HEX64.fullmatch(fp) is not None
    if len(password) >= 4:
        assert password not in fp


# --- configuration errors ---


def test_r1_15_invalid_hex_secret_raises(credentials_file: Path) -> None:
    with pytest.raises(ConfigurationError):
        AuthPolicy(credentials_file, "not-hex-zzzz", DEMO_USER, DEMO_PASS)


@pytest.fixture
def full_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    monkeypatch.setenv("HONEYPOT_HMAC_SECRET", FAKE_SECRET_HEX)
    monkeypatch.setenv("HONEYPOT_DEMO_USERNAME", DEMO_USER)
    monkeypatch.setenv("HONEYPOT_DEMO_PASSWORD", DEMO_PASS)
    return monkeypatch


def test_r1_15_missing_secret_raises(full_env: pytest.MonkeyPatch, credentials_file: Path) -> None:
    full_env.delenv("HONEYPOT_HMAC_SECRET")
    with pytest.raises(ConfigurationError):
        load_auth_policy_from_env(credentials_file)


def test_r1_15_missing_demo_username_raises(
    full_env: pytest.MonkeyPatch, credentials_file: Path
) -> None:
    full_env.delenv("HONEYPOT_DEMO_USERNAME")
    with pytest.raises(ConfigurationError):
        load_auth_policy_from_env(credentials_file)


def test_r1_15_missing_demo_password_raises(
    full_env: pytest.MonkeyPatch, credentials_file: Path
) -> None:
    full_env.delenv("HONEYPOT_DEMO_PASSWORD")
    with pytest.raises(ConfigurationError):
        load_auth_policy_from_env(credentials_file)


def test_r1_15_load_from_env_returns_working_policy(
    full_env: pytest.MonkeyPatch, credentials_file: Path
) -> None:
    loaded = load_auth_policy_from_env(credentials_file)
    assert loaded.check("root", "toor") is True
    assert loaded.check(DEMO_USER, DEMO_PASS) is True
    assert loaded.check("root", "wrong") is False
    expected = AuthPolicy(credentials_file, FAKE_SECRET_HEX, DEMO_USER, DEMO_PASS)
    assert loaded.fingerprint("x") == expected.fingerprint("x")


# --- lone surrogates ---
# st.characters() excludes category "Cs" by default, so surrogates are added explicitly.
SURROGATE_TEXT = st.text(
    alphabet=st.one_of(
        st.characters(),
        st.characters(categories=["Cs"]),
        st.sampled_from(["\ud800", "\udbff", "\udc00", "\udfff"]),
    ),
    max_size=64,
)


@given(username=SURROGATE_TEXT, password=SURROGATE_TEXT)
def test_r1_surrogates_never_raise(username: str, password: str) -> None:
    # Hypothesis fixtures are function-scoped, so build the policy inline.
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "credentials.toml"
        path.write_text(CREDENTIALS_TOML, encoding="utf-8")
        policy = AuthPolicy(path, FAKE_SECRET_HEX, DEMO_USER, DEMO_PASS)
        assert isinstance(policy.check(username, password), bool)
        assert HEX64.fullmatch(policy.fingerprint(password)) is not None


def test_r1_surrogates_explicit(policy: AuthPolicy) -> None:
    assert policy.check("\ud800", "\ud800") is False
    assert policy.check(DEMO_USER, "\udfff") is False
    assert HEX64.fullmatch(policy.fingerprint("\ud800")) is not None
