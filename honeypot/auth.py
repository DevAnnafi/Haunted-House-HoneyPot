import hashlib
import hmac
import os
import tomllib
from pathlib import Path


class ConfigurationError(Exception):
    pass


class AuthPolicy:
    def __init__(
        self,
        credentials_path: Path,
        hmac_secret_hex: str,
        demo_username: str,
        demo_password: str,
    ) -> None:
        with open(credentials_path, "rb") as f:
            data = tomllib.load(f)
            self.credentials_pairs = {(c["username"], c["password"]) for c in data["credentials"]}

            try:
                hmac_bytes = bytes.fromhex(hmac_secret_hex)
            except ValueError:
                raise ConfigurationError("HONEYPOT_HMAC_SECRET must be a hex string") from None

            self.fingerprint_key = hmac.new(
                hmac_bytes, b"password-fingerprint", hashlib.sha256
            ).digest()

            self.demo_username = demo_username
            self.demo_password = demo_password

    def check(self, username: str, password: str) -> bool:
        if (username, password) in self.credentials_pairs:
            return True
        return username == self.demo_username and hmac.compare_digest(
            password.encode("utf-8"), self.demo_password.encode("utf-8")
        )

    def fingerprint(self, password: str) -> str:
        return hmac.new(self.fingerprint_key, password.encode("utf-8"), hashlib.sha256).hexdigest()


def load_auth_policy_from_env(credentials_path: Path) -> AuthPolicy:
    hmac_secret = os.environ.get("HONEYPOT_HMAC_SECRET")
    demo_username = os.environ.get("HONEYPOT_DEMO_USERNAME")
    demo_password = os.environ.get("HONEYPOT_DEMO_PASSWORD")

    if not hmac_secret:
        raise ConfigurationError("HONEYPOT_HMAC_SECRET is not set")

    elif not demo_username:
        raise ConfigurationError("HONEYPOT_DEMO_USERNAME is not set")

    elif not demo_password:
        raise ConfigurationError("HONEYPOT_DEMO_PASSWORD is not set")

    return AuthPolicy(
        credentials_path=credentials_path,
        hmac_secret_hex=hmac_secret,
        demo_username=demo_username,
        demo_password=demo_password,
    )
