"""Tests for honeypot/config.py and the config-error path of ``python -m honeypot`` (T1.10).

Satisfies R1.2, R1.8 (configuration). Environment variables are set with monkeypatch and
files live in tmp_path. No real .env, host key, or config/credentials.toml is read.
"""

import math
import os
import subprocess
import sys
from pathlib import Path

import pytest

from honeypot.auth import ConfigurationError
from honeypot.config import (
    DEFAULT_CREDENTIALS_PATH,
    DEFAULT_FS_TEMPLATE_PATH,
    DEFAULT_LOGIN_TIMEOUT,
    DEFAULT_SSH_HOST,
    DEFAULT_SSH_PORT,
    load_config_from_env,
)

REPO_ROOT = Path(__file__).resolve().parent.parent

CONFIG_VARS = (
    "HONEYPOT_SSH_HOST",
    "HONEYPOT_SSH_PORT",
    "HONEYPOT_HOST_KEY_PATH",
    "HONEYPOT_SETUP_TIMEOUT",
    "HONEYPOT_CREDENTIALS_PATH",
    "HONEYPOT_FS_TEMPLATE_PATH",
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start every test with none of the config variables set."""
    for name in CONFIG_VARS:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def host_key(tmp_path: Path) -> Path:
    path = tmp_path / "host_key"
    path.write_text("not a real key; config loading only checks that the file exists\n")
    return path


@pytest.fixture
def credentials(tmp_path: Path) -> Path:
    path = tmp_path / "credentials.toml"
    path.write_text('[[credentials]]\nusername = "root"\npassword = "123456"\n')
    return path


FS_TEMPLATE_TEXT = (
    '[[node]]\npath = "/"\ntype = "dir"\nmode = "0755"\nowner = "root"\ngroup = "root"\n'
    'mtime = "2026-03-12T09:41:07Z"\n'
)


@pytest.fixture
def fs_template(tmp_path: Path) -> Path:
    # Config loading only checks that the file exists; it never parses it.
    path = tmp_path / "fs_template.toml"
    path.write_text(FS_TEMPLATE_TEXT)
    return path


@pytest.fixture
def valid_env(
    monkeypatch: pytest.MonkeyPatch, host_key: Path, credentials: Path, fs_template: Path
) -> pytest.MonkeyPatch:
    """Environment with the three required file paths set to real files."""
    monkeypatch.setenv("HONEYPOT_HOST_KEY_PATH", str(host_key))
    monkeypatch.setenv("HONEYPOT_CREDENTIALS_PATH", str(credentials))
    monkeypatch.setenv("HONEYPOT_FS_TEMPLATE_PATH", str(fs_template))
    return monkeypatch


# ---------------------------------------------------------------------------
# Host key path
# ---------------------------------------------------------------------------


def test_r1_host_key_path_missing_is_rejected(valid_env):
    valid_env.delenv("HONEYPOT_HOST_KEY_PATH")
    with pytest.raises(ConfigurationError) as exc:
        load_config_from_env()
    assert str(exc.value) == "HONEYPOT_HOST_KEY_PATH must be set"


def test_r1_host_key_path_empty_is_rejected(valid_env):
    valid_env.setenv("HONEYPOT_HOST_KEY_PATH", "")
    with pytest.raises(ConfigurationError) as exc:
        load_config_from_env()
    assert str(exc.value) == "HONEYPOT_HOST_KEY_PATH must be set"


def test_r1_host_key_path_to_nonexistent_file_is_rejected(valid_env, tmp_path):
    missing = tmp_path / "no_such_key"
    valid_env.setenv("HONEYPOT_HOST_KEY_PATH", str(missing))
    with pytest.raises(ConfigurationError) as exc:
        load_config_from_env()
    assert str(exc.value) == f"HONEYPOT_HOST_KEY_PATH does not point to a file: {missing}"


def test_r1_host_key_path_to_directory_is_rejected(valid_env, tmp_path):
    valid_env.setenv("HONEYPOT_HOST_KEY_PATH", str(tmp_path))
    with pytest.raises(ConfigurationError) as exc:
        load_config_from_env()
    assert str(exc.value) == f"HONEYPOT_HOST_KEY_PATH does not point to a file: {tmp_path}"


# ---------------------------------------------------------------------------
# Port
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("raw", ["abc", "22.5", "2222abc", " ", "0x10"])
def test_r1_non_integer_port_is_rejected(valid_env, raw):
    valid_env.setenv("HONEYPOT_SSH_PORT", raw)
    with pytest.raises(ConfigurationError) as exc:
        load_config_from_env()
    assert str(exc.value) == f"HONEYPOT_SSH_PORT must be an integer, got {raw!r}"


@pytest.mark.parametrize("raw", ["0", "65536", "-1"])
def test_r1_port_out_of_range_is_rejected(valid_env, raw):
    valid_env.setenv("HONEYPOT_SSH_PORT", raw)
    with pytest.raises(ConfigurationError) as exc:
        load_config_from_env()
    assert str(exc.value) == f"HONEYPOT_SSH_PORT out of range: {int(raw)}"


@pytest.mark.parametrize("raw", [1, 2222, 65535])
def test_r1_port_in_range_is_accepted(valid_env, raw):
    valid_env.setenv("HONEYPOT_SSH_PORT", str(raw))
    assert load_config_from_env().ssh_port == raw


# ---------------------------------------------------------------------------
# Setup (login) timeout
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("raw", ["0", "0.0", "-1", "-0.5", "nan", "NaN", "inf", "-inf"])
def test_r8_8_invalid_timeout_is_rejected(valid_env, raw):
    valid_env.setenv("HONEYPOT_SETUP_TIMEOUT", raw)
    with pytest.raises(ConfigurationError) as exc:
        load_config_from_env()
    # Compare against the parsed value's own repr so nan/inf formatting matches the loader.
    assert str(exc.value) == (f"HONEYPOT_SETUP_TIMEOUT must be a positive number, got {float(raw)}")


@pytest.mark.parametrize("raw", ["abc", "1,5", "5s"])
def test_r8_8_non_numeric_timeout_is_rejected(valid_env, raw):
    valid_env.setenv("HONEYPOT_SETUP_TIMEOUT", raw)
    with pytest.raises(ConfigurationError) as exc:
        load_config_from_env()
    assert str(exc.value) == f"HONEYPOT_SETUP_TIMEOUT must be a number, got {raw!r}"


def test_r8_8_positive_timeout_is_accepted(valid_env):
    valid_env.setenv("HONEYPOT_SETUP_TIMEOUT", "0.5")
    config = load_config_from_env()
    assert config.login_timeout == 0.5
    assert math.isfinite(config.login_timeout)


# ---------------------------------------------------------------------------
# Credentials file
# ---------------------------------------------------------------------------


def test_r1_credentials_file_that_does_not_exist_is_rejected(valid_env, tmp_path):
    missing = tmp_path / "no_such_credentials.toml"
    valid_env.setenv("HONEYPOT_CREDENTIALS_PATH", str(missing))
    with pytest.raises(ConfigurationError) as exc:
        load_config_from_env()
    assert str(exc.value) == f"credentials file not found: {missing}"


# ---------------------------------------------------------------------------
# Filesystem template
# ---------------------------------------------------------------------------


def test_r1_fs_template_that_does_not_exist_is_rejected(valid_env, tmp_path):
    missing = tmp_path / "no_such_template.toml"
    valid_env.setenv("HONEYPOT_FS_TEMPLATE_PATH", str(missing))
    with pytest.raises(ConfigurationError) as exc:
        load_config_from_env()
    assert str(exc.value) == f"filesystem template not found: {missing}"


def test_r1_fs_template_path_to_directory_is_rejected(valid_env, tmp_path):
    valid_env.setenv("HONEYPOT_FS_TEMPLATE_PATH", str(tmp_path))
    with pytest.raises(ConfigurationError) as exc:
        load_config_from_env()
    assert str(exc.value) == f"filesystem template not found: {tmp_path}"


def test_r1_missing_default_fs_template_is_rejected(valid_env, monkeypatch, tmp_path):
    # No override, and the relative default does not exist under the working directory.
    valid_env.delenv("HONEYPOT_FS_TEMPLATE_PATH")
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ConfigurationError) as exc:
        load_config_from_env()
    assert str(exc.value) == f"filesystem template not found: {Path(DEFAULT_FS_TEMPLATE_PATH)}"


def test_r1_empty_fs_template_path_falls_back_to_the_default(valid_env, monkeypatch, tmp_path):
    valid_env.setenv("HONEYPOT_FS_TEMPLATE_PATH", "")
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ConfigurationError) as exc:
        load_config_from_env()
    assert str(exc.value) == f"filesystem template not found: {Path(DEFAULT_FS_TEMPLATE_PATH)}"


def test_r1_fs_template_path_override_is_used(valid_env, fs_template):
    assert load_config_from_env().fs_template_path == fs_template


# ---------------------------------------------------------------------------
# Defaults and empty values
# ---------------------------------------------------------------------------


def test_r1_defaults_are_loopback_2222_and_15_seconds():
    # Pin the documented defaults themselves, independent of the loader.
    assert DEFAULT_SSH_HOST == "127.0.0.1"
    assert DEFAULT_SSH_PORT == 2222
    assert DEFAULT_LOGIN_TIMEOUT == 15.0
    assert DEFAULT_CREDENTIALS_PATH == "config/credentials.toml"
    assert DEFAULT_FS_TEMPLATE_PATH == "config/fs_template.toml"


def _chdir_with_default_files(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Make the relative default credentials and template paths resolve inside tmp_path."""
    credentials = tmp_path / DEFAULT_CREDENTIALS_PATH
    credentials.parent.mkdir(parents=True)
    credentials.write_text('[[credentials]]\nusername = "root"\npassword = "123456"\n')
    template = tmp_path / DEFAULT_FS_TEMPLATE_PATH
    template.parent.mkdir(parents=True, exist_ok=True)
    template.write_text(FS_TEMPLATE_TEXT)
    monkeypatch.chdir(tmp_path)


def test_r1_unset_optional_values_use_defaults(monkeypatch, tmp_path, host_key):
    _chdir_with_default_files(monkeypatch, tmp_path)
    monkeypatch.setenv("HONEYPOT_HOST_KEY_PATH", str(host_key))

    config = load_config_from_env()

    assert config.ssh_host == "127.0.0.1"
    assert config.ssh_port == 2222
    assert config.login_timeout == 15.0
    assert config.credentials_path == Path(DEFAULT_CREDENTIALS_PATH)
    assert config.fs_template_path == Path(DEFAULT_FS_TEMPLATE_PATH)
    assert config.host_key_path == host_key


def test_r1_empty_optional_values_fall_back_to_defaults(monkeypatch, tmp_path, host_key):
    _chdir_with_default_files(monkeypatch, tmp_path)
    monkeypatch.setenv("HONEYPOT_HOST_KEY_PATH", str(host_key))
    for name in (
        "HONEYPOT_SSH_HOST",
        "HONEYPOT_SSH_PORT",
        "HONEYPOT_SETUP_TIMEOUT",
        "HONEYPOT_CREDENTIALS_PATH",
        "HONEYPOT_FS_TEMPLATE_PATH",
    ):
        monkeypatch.setenv(name, "")

    config = load_config_from_env()

    assert config.ssh_host == "127.0.0.1"
    assert config.ssh_port == 2222
    assert config.login_timeout == 15.0
    assert config.credentials_path == Path(DEFAULT_CREDENTIALS_PATH)
    assert config.fs_template_path == Path(DEFAULT_FS_TEMPLATE_PATH)


def test_r1_explicit_values_override_defaults(valid_env, host_key, credentials):
    valid_env.setenv("HONEYPOT_SSH_HOST", "0.0.0.0")
    valid_env.setenv("HONEYPOT_SSH_PORT", "2200")
    valid_env.setenv("HONEYPOT_SETUP_TIMEOUT", "3.5")

    config = load_config_from_env()

    assert config.ssh_host == "0.0.0.0"
    assert config.ssh_port == 2200
    assert config.login_timeout == 3.5
    assert config.host_key_path == host_key
    assert config.credentials_path == credentials


# ---------------------------------------------------------------------------
# Entry point: python -m honeypot
# ---------------------------------------------------------------------------


def test_r1_entry_point_without_host_key_path_exits_1_with_config_error(tmp_path):
    # An empty value (not an absent one) keeps load_dotenv() from filling the variable in
    # from a developer's real .env, because dotenv never overrides existing variables.
    env = {
        "HONEYPOT_HOST_KEY_PATH": "",
        "HONEYPOT_SSH_HOST": "127.0.0.1",
        "HONEYPOT_SSH_PORT": "0",
    }
    full_env = {**os.environ, **env}

    result = subprocess.run(
        [sys.executable, "-m", "honeypot"],
        cwd=REPO_ROOT,
        env=full_env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 1
    log_lines = result.stderr.splitlines()
    assert log_lines[-1] == "ERROR:honeypot.main:CONFIG ERROR HONEYPOT_HOST_KEY_PATH must be set"
    assert result.stdout == ""
