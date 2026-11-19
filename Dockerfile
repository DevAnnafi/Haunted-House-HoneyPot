# Honeypot service image (T9.1, ADR-0003).
# Pinned to the exact patch version used in development.
FROM python:3.15.2-slim

# No .pyc files (the root filesystem is read-only at runtime), unbuffered logs,
# no pip cache or version-check network call.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Unprivileged user with a fixed UID/GID so the host-key file's ownership can be
# set to match (see .env.example). No login shell, no home directory.
RUN groupadd --system --gid 10001 honeypot \
    && useradd --system --uid 10001 --gid honeypot \
        --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin honeypot

WORKDIR /app

# Dependencies first so this layer is cached until requirements.txt changes.
COPY requirements.txt ./
RUN pip install -r requirements.txt

# Application code and non-secret config only. Secrets and the host key are
# never copied into the image (see .dockerignore).
COPY honeypot/ ./honeypot/
COPY shared/ ./shared/
COPY config/ ./config/

# Code is owned by root and not writable by the honeypot user.
USER honeypot:honeypot

# The listener port inside the container. Publishing is decided in docker-compose.yml.
EXPOSE 2222

CMD ["python", "-m", "honeypot"]
