# Config

Non-secret configuration files committed to the repository.

| File / Directory | Description |
|---|---|
| `credentials.toml` | Weak SSH credential pairs accepted by the auth policy (T1.2) |
| `fs_template/` | Fake Ubuntu filesystem tree pre-populated into each fresh session VFS (T2.3) |

Secrets (database URL, HMAC secret, LLM API key, demo credential, host key path) are
loaded from environment variables or `.env` at runtime — never stored here.
