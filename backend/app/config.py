"""Application settings.

The Settings dataclass is plain values; ``Settings.from_env()`` is the only
place environment variables are read. That read happens ONCE, at module
import, producing the module-level ``settings`` the app entrypoint
(``main.app``) uses — a misconfigured process therefore refuses to boot at
import time rather than halfway through serving. Tests never touch that
global: they build their own Settings and inject it via
``create_app(settings)``.

The environment defaults to ``production`` (fail closed): development mode,
with its committed dev token secret, SQLite and open /docs, exists only when
MINDPATTERN_ENV=development is set *exactly* — any other value (staging,
prod, a typo, or an unset variable) takes the production gates instead of
silently signing tokens with a public constant. Production additionally
rejects SQLite and weak secrets.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from urllib.parse import urlparse

logger = logging.getLogger("mindpattern")

DEFAULT_INSECURE_SECRET = "dev-insecure-secret-change-me"

# Upper bounds for the numeric settings (the lower bound is 1, or 1024 for
# byte counts — see Settings.__post_init__). Past these the value is
# misconfiguration, not tuning: a year-long token TTL turns a token leak
# into a permanent account takeover; a processing session that never
# expires keeps a data key usable in memory; a day-long rate window
# misleads Retry-After and makes the counter's eviction useless.
MAX_TOKEN_TTL_SECONDS = 30 * 86_400  # 30 days
# 5 minutes — the mobile consent copy promises "held in memory for up to 5
# minutes, then destroyed", so the operator-tunable ceiling must match it
# (the 2026-09-16 audit found a 3600s ceiling silently contradicting the
# promise an abandoned session could sit on the key for an hour).
MAX_PROCESSING_SESSION_TTL = 300
MAX_RATE_WINDOW_SECONDS = 3_600  # 1 hour per window
MAX_RATE_LIMIT = 100_000  # hits per window


def _int_env(name: str, default: int) -> int:
    """Parse an int env var; empty means default, garbage is a hard error.

    Silently falling back on a typo'd value (e.g. TTL=8O000) hides
    misconfiguration until it hurts, so invalid input refuses to start.
    """
    raw = os.getenv(name, "")
    if not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"environment variable {name}={raw!r} is not an integer") from exc


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


def _cors_origins() -> list[str]:
    """Comma-separated allowed origins; empty default = NO cross-origin access.

    The mobile app is a native client and never sends Origin headers, so CORS
    is not needed for it; a browser frontend must be explicitly allowlisted.
    """
    raw = os.getenv("MINDPATTERN_CORS_ORIGINS", "").strip()
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


@dataclass
class Settings:
    # Fail closed: production is the DEFAULT. Development (dev secret,
    # SQLite, /docs) requires an explicit MINDPATTERN_ENV=development opt-in.
    environment: str = "production"
    database_url: str = "sqlite+aiosqlite:///./mindpattern.db"

    token_secret: str = DEFAULT_INSECURE_SECRET
    token_ttl_seconds: int = 86_400

    processing_session_ttl: int = 300
    unlock_threshold_days: int = 30

    auth_rate_limit: int = 10
    auth_rate_window: int = 60
    entries_rate_limit: int = 120
    entries_rate_window: int = 60
    processing_rate_limit: int = 10
    processing_rate_window: int = 60
    read_rate_limit: int = 300
    read_rate_window: int = 60
    # Export streams the whole account (up to the 256 MiB blob quota) per
    # request — far heavier than an ordinary read, so it gets its own tight
    # bucket instead of riding the 300/min read bucket.
    export_rate_limit: int = 5
    export_rate_window: int = 60

    # Whole-request body cap, enforced before the JSON is parsed. Field-level
    # caps in schemas.py bound what is *stored*; this bounds what is *read*.
    max_body_bytes: int = 2 * 1024 * 1024  # 2 MiB
    # Per-account storage quota: bounds recompute/export memory and DB growth.
    max_entries_per_user: int = 10_000
    max_user_blob_bytes: int = 256 * 1024 * 1024  # 256 MiB total ciphertext
    # Analysis corpus cap: how many of the most recent entries one recompute
    # decrypts. The 30-day threshold still counts ALL entry dates (from DB
    # metadata, no decryption needed), so the cap cannot un-lock a phase.
    recompute_entry_limit: int = 2_000

    # Connection pool for the (Postgres) production engine. SQLite ignores
    # these — its StaticPool single shared connection is what keeps
    # in-memory databases alive across sessions.
    db_pool_size: int = 5
    db_max_overflow: int = 10
    db_pool_timeout: int = 30

    llm_url: str = ""
    llm_api_key: str = ""
    llm_model: str = "gpt-4o-mini"

    cors_origins: list[str] = field(default_factory=list)
    trust_proxy_headers: bool = False

    def __post_init__(self) -> None:
        # Normalize before any comparison: "Production", "production " and
        # "PRODUCTION" must all hit the production gates — an exact-string
        # check silently disarms every hardening flag on a case typo.
        self.environment = self.environment.strip().lower()
        if not self.token_secret.strip():
            # An explicitly-empty secret is not "unset": without this check
            # HMAC-SHA256(b"") happily signs tokens in staging/prod/anything.
            self.token_secret = DEFAULT_INSECURE_SECRET
        if self.token_secret == DEFAULT_INSECURE_SECRET and self.environment != "development":
            # Fail closed: "staging", "prod", "PRODUCTION" or any typo must not
            # boot with the repo-committed secret — anyone could then mint
            # bearer tokens for arbitrary accounts.
            raise RuntimeError(
                "MINDPATTERN_TOKEN_SECRET is unset/insecure: refuse to start. "
                "Set a strong random value (e.g. openssl rand -hex 32). "
                "(The built-in dev secret is only allowed with "
                "MINDPATTERN_ENV=development exactly.)"
            )
        if self.environment != "development":
            # The 32-char floor applies to EVERY non-development environment,
            # not just production: a 3-char secret in "staging" is equally
            # brute-forceable offline from any captured token.
            if len(self.token_secret.strip()) < 32:
                raise RuntimeError(
                    "MINDPATTERN_TOKEN_SECRET must be at least 32 characters "
                    f"in environment {self.environment!r}"
                )
        # Range-validate everything numeric: "invalid values abort startup"
        # must cover 0/negative too, not just non-integers (a TTL of 0 makes
        # every issued token instantly expired; a window of 0 makes the rate
        # limiter raise inside the dependency — a 500 per request).
        for name in (
            "token_ttl_seconds",
            "processing_session_ttl",
            "unlock_threshold_days",
            "auth_rate_limit",
            "auth_rate_window",
            "entries_rate_limit",
            "entries_rate_window",
            "processing_rate_limit",
            "processing_rate_window",
            "read_rate_limit",
            "read_rate_window",
            "export_rate_limit",
            "export_rate_window",
            "max_entries_per_user",
            "recompute_entry_limit",
            "db_pool_size",
            "db_pool_timeout",
        ):
            if getattr(self, name) < 1:
                raise RuntimeError(f"{name} must be >= 1")
        # max_overflow of 0 is legitimate (a hard pool cap), so it gets its
        # own lower bound.
        if self.db_max_overflow < 0:
            raise RuntimeError("db_max_overflow must be >= 0")
        if self.token_ttl_seconds > MAX_TOKEN_TTL_SECONDS:
            raise RuntimeError(f"token_ttl_seconds must be <= {MAX_TOKEN_TTL_SECONDS}")
        if self.processing_session_ttl > MAX_PROCESSING_SESSION_TTL:
            raise RuntimeError(f"processing_session_ttl must be <= {MAX_PROCESSING_SESSION_TTL}")
        for name in (
            "auth_rate_window",
            "entries_rate_window",
            "processing_rate_window",
            "read_rate_window",
            "export_rate_window",
        ):
            if getattr(self, name) > MAX_RATE_WINDOW_SECONDS:
                raise RuntimeError(f"{name} must be <= {MAX_RATE_WINDOW_SECONDS}")
        for name in (
            "auth_rate_limit",
            "entries_rate_limit",
            "processing_rate_limit",
            "read_rate_limit",
            "export_rate_limit",
        ):
            if getattr(self, name) > MAX_RATE_LIMIT:
                raise RuntimeError(f"{name} must be <= {MAX_RATE_LIMIT}")
        for name in ("max_body_bytes", "max_user_blob_bytes"):
            if getattr(self, name) < 1024:
                raise RuntimeError(f"{name} must be >= 1024")
        if self.environment != "development":
            # SQLite is dev/test only — rejected for ANY non-development
            # value ("prod", "staging", a typo), not just the exact string
            # "production": a typo must not boot against a throwaway local
            # file database.
            if self.database_url.startswith("sqlite"):
                raise RuntimeError(
                    "MINDPATTERN_DB_URL must point at PostgreSQL (or another shared "
                    "database) outside development; SQLite is dev/test only"
                )
        if self.llm_url.strip():
            # Decrypted journal plaintext is POSTed to this endpoint, so the
            # transport must be TLS. Plain http:// is accepted only for a
            # loopback dev server (exact host match — "localhost.evil.com"
            # must not slip through a prefix check) in development mode.
            parsed = urlparse(self.llm_url.strip())
            dev_loopback = (
                self.environment == "development"
                and parsed.scheme == "http"
                and parsed.hostname in ("localhost", "127.0.0.1")
            )
            if parsed.scheme != "https" and not dev_loopback:
                raise RuntimeError(
                    "MINDPATTERN_LLM_URL must use https:// — decrypted journal "
                    "plaintext is POSTed to it. Plain http:// is only accepted "
                    "for http://localhost / http://127.0.0.1 with "
                    "MINDPATTERN_ENV=development exactly."
                )
            if not self.llm_api_key.strip():
                # Warn but boot: loopback dev servers (Ollama etc.) commonly
                # need no key, and llm_available=False deployments never set
                # the URL at all.
                logger.warning(
                    "MINDPATTERN_LLM_URL is set but MINDPATTERN_LLM_API_KEY is "
                    "empty — LLM requests will go out without an API key"
                )

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            environment=os.getenv("MINDPATTERN_ENV", "production"),
            database_url=os.getenv("MINDPATTERN_DB_URL", "sqlite+aiosqlite:///./mindpattern.db"),
            token_secret=os.getenv("MINDPATTERN_TOKEN_SECRET", DEFAULT_INSECURE_SECRET),
            token_ttl_seconds=_int_env("MINDPATTERN_TOKEN_TTL", 86_400),
            processing_session_ttl=_int_env("MINDPATTERN_PROCESSING_TTL", 300),
            unlock_threshold_days=_int_env("MINDPATTERN_UNLOCK_DAYS", 30),
            auth_rate_limit=_int_env("MINDPATTERN_AUTH_RATE_LIMIT", 10),
            auth_rate_window=_int_env("MINDPATTERN_AUTH_RATE_WINDOW", 60),
            entries_rate_limit=_int_env("MINDPATTERN_ENTRIES_RATE_LIMIT", 120),
            entries_rate_window=_int_env("MINDPATTERN_ENTRIES_RATE_WINDOW", 60),
            processing_rate_limit=_int_env("MINDPATTERN_PROCESSING_RATE_LIMIT", 10),
            processing_rate_window=_int_env("MINDPATTERN_PROCESSING_RATE_WINDOW", 60),
            read_rate_limit=_int_env("MINDPATTERN_READ_RATE_LIMIT", 300),
            read_rate_window=_int_env("MINDPATTERN_READ_RATE_WINDOW", 60),
            max_body_bytes=_int_env("MINDPATTERN_MAX_BODY_BYTES", 2 * 1024 * 1024),
            max_entries_per_user=_int_env("MINDPATTERN_MAX_ENTRIES_PER_USER", 10_000),
            max_user_blob_bytes=_int_env("MINDPATTERN_MAX_USER_BLOB_BYTES", 256 * 1024 * 1024),
            recompute_entry_limit=_int_env("MINDPATTERN_RECOMPUTE_ENTRY_LIMIT", 2_000),
            db_pool_size=_int_env("MINDPATTERN_DB_POOL_SIZE", 5),
            db_max_overflow=_int_env("MINDPATTERN_DB_MAX_OVERFLOW", 10),
            db_pool_timeout=_int_env("MINDPATTERN_DB_POOL_TIMEOUT", 30),
            export_rate_limit=_int_env("MINDPATTERN_EXPORT_RATE_LIMIT", 5),
            export_rate_window=_int_env("MINDPATTERN_EXPORT_RATE_WINDOW", 60),
            llm_url=os.getenv("MINDPATTERN_LLM_URL", ""),
            llm_api_key=os.getenv("MINDPATTERN_LLM_API_KEY", ""),
            llm_model=os.getenv("MINDPATTERN_LLM_MODEL", "gpt-4o-mini"),
            cors_origins=_cors_origins(),
            trust_proxy_headers=_bool_env("MINDPATTERN_TRUST_PROXY_HEADERS"),
        )


settings = Settings.from_env()
