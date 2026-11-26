import math
import os
from dataclasses import dataclass
from pathlib import Path

from honeypot.auth import ConfigurationError

DEFAULT_SSH_HOST = "127.0.0.1"
DEFAULT_SSH_PORT = 2222
DEFAULT_LOGIN_TIMEOUT = 15.0
DEFAULT_CREDENTIALS_PATH = "config/credentials.toml"
DEFAULT_FS_TEMPLATE_PATH = "config/fs_template.toml"


@dataclass(frozen=True)
class Config:
    ssh_host: str
    ssh_port: int
    host_key_path: Path
    login_timeout: float
    credentials_path: Path
    fs_template_path: Path
    database_url: str


def _require(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ConfigurationError(f"{name} must be set")
    return value


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        raise ConfigurationError(f"{name} must be an integer, got {raw!r}") from None


def _float_env(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        raise ConfigurationError(f"{name} must be a number, got {raw!r}") from None


def load_config_from_env() -> Config:
    host_key_path = Path(_require("HONEYPOT_HOST_KEY_PATH"))
    if not host_key_path.is_file():
        raise ConfigurationError(
            f"HONEYPOT_HOST_KEY_PATH does not point to a file: {host_key_path}"
        )

    ssh_port = _int_env("HONEYPOT_SSH_PORT", DEFAULT_SSH_PORT)
    if not 1 <= ssh_port <= 65535:
        raise ConfigurationError(f"HONEYPOT_SSH_PORT out of range: {ssh_port}")

    login_timeout = _float_env("HONEYPOT_SETUP_TIMEOUT", DEFAULT_LOGIN_TIMEOUT)
    if not math.isfinite(login_timeout) or login_timeout <= 0:
        raise ConfigurationError(
            f"HONEYPOT_SETUP_TIMEOUT must be a positive number, got {login_timeout}"
        )

    credentials_path = Path(os.environ.get("HONEYPOT_CREDENTIALS_PATH") or DEFAULT_CREDENTIALS_PATH)
    if not credentials_path.is_file():
        raise ConfigurationError(f"credentials file not found: {credentials_path}")

    fs_template_path = Path(os.environ.get("HONEYPOT_FS_TEMPLATE_PATH") or DEFAULT_FS_TEMPLATE_PATH)
    if not fs_template_path.is_file():
        raise ConfigurationError(f"filesystem template not found: {fs_template_path}")

    if not fs_template_path.is_file():
        raise ConfigurationError(f"filesystem template not found: {fs_template_path}")

    database_url = _require("HONEYPOT_DATABASE_URL")

    return Config(
        ssh_host=os.environ.get("HONEYPOT_SSH_HOST") or DEFAULT_SSH_HOST,
        ssh_port=ssh_port,
        host_key_path=host_key_path,
        login_timeout=login_timeout,
        credentials_path=credentials_path,
        fs_template_path=fs_template_path,
        database_url=database_url,
    )
