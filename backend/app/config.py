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
from ipaddress import ip_network
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
# Whole request bodies are buffered at the ASGI edge to make the size cap
# authoritative even for handlers that never call receive().  Bound the
# complete read too: otherwise a chunked slowloris can keep a request task
# alive forever one byte at a time.
MAX_BODY_READ_TIMEOUT_SECONDS = 120


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


def _optional_bool_env(name: str) -> bool | None:
    """A boolean that distinguishes an absent setting from an explicit off."""
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return None
    return raw in ("1", "true", "yes", "on")


def _cors_origins() -> list[str]:
    """Comma-separated allowed origins; empty default = NO cross-origin access.

    The mobile app is a native client and never sends Origin headers, so CORS
    is not needed for it; a browser frontend must be explicitly allowlisted.
    """
    raw = os.getenv("MINDPATTERN_CORS_ORIGINS", "").strip()
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


def _trusted_proxy_ips() -> list[str]:
    """Read an explicit comma-separated proxy peer allowlist.

    Forwarding headers are client-controlled until the socket peer itself is
    established as one of these addresses/CIDRs.  Keep the setting separate
    from CORS: a browser origin says nothing about who made the TCP
    connection to the API.
    """
    raw = os.getenv("MINDPATTERN_TRUSTED_PROXY_IPS", "").strip()
    return [value.strip() for value in raw.split(",") if value.strip()]


def _is_loopback_hostname(hostname: str | None) -> bool:
    """Whether a parsed URL host is an exact local development endpoint.

    Do not use a suffix/prefix test here: ``localhost.evil.example`` and
    ``127.0.0.2`` are network hosts, not the local process.  ``urlparse``
    removes IPv6 brackets from ``hostname``.
    """

    return hostname in {"localhost", "127.0.0.1", "::1"}


def _validate_cors_origins(origins: list[str], environment: str) -> None:
    """Reject wildcard/malformed CORS configuration at process startup.

    CORS is deliberately an explicit browser-origin allowlist.  Passing
    ``*``, credentials, a path, or a plaintext remote URL to Starlette would
    either defeat that boundary or silently fail to match browser Origin
    headers.  A development-only exact loopback HTTP origin is useful for
    local Vite work; every other origin must be HTTPS.
    """

    for origin in origins:
        try:
            parsed = urlparse(origin)
            # Accessing .port makes malformed authorities such as :abc a
            # deterministic boot failure instead of a surprising runtime
            # CORS mismatch.
            _ = parsed.port
        except ValueError as exc:
            raise RuntimeError(f"cors_origins contains invalid origin {origin!r}") from exc
        is_dev_loopback = (
            environment == "development"
            and parsed.scheme == "http"
            and _is_loopback_hostname(parsed.hostname)
        )
        if (
            not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.params
            or parsed.query
            or parsed.fragment
            or parsed.path
            or (parsed.scheme != "https" and not is_dev_loopback)
        ):
            raise RuntimeError(
                "cors_origins must contain exact https:// origins (or exact "
                "http://localhost/127.0.0.1/[::1] origins in development)"
            )


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
    # Therapist/patient access-audit metadata retention. This is metadata,
    # not journal plaintext, but it remains sensitive and must be explicit.
    access_log_retention_days: int = 730

    # Whole-request body cap, enforced before the JSON is parsed. Field-level
    # caps in schemas.py bound what is *stored*; this bounds what is *read*.
    max_body_bytes: int = 2 * 1024 * 1024  # 2 MiB
    # Total wall-clock budget to receive one request body. This is a total,
    # not an idle, timeout so trickling one byte before every idle deadline
    # cannot pin an ASGI task indefinitely. The edge proxy mirrors 30s.
    body_read_timeout_seconds: int = 30
    # Per-account storage quota: bounds recompute/export memory and DB growth.
    max_entries_per_user: int = 10_000
    max_user_blob_bytes: int = 256 * 1024 * 1024  # 256 MiB total ciphertext
    # Analysis corpus cap: how many of the most recent entries one recompute
    # decrypts. The 30-day threshold still counts ALL entry dates (from DB
    # metadata, no decryption needed), so the cap cannot un-lock a phase.
    recompute_entry_limit: int = 2_000
    # Ciphertext byte budget per recompute, enforced in SQL BEFORE decrypt
    # (2026-09-17): peak recompute memory is bounded by the ANALYSIS budget,
    # not by the account's storage quota — a max-quota account can no longer
    # make the server hold ~quota-sized ciphertext + plaintext + zeroized
    # copies at once. 8 MiB comfortably covers the 2M-char analysis corpus.
    analysis_blob_budget: int = 8 * 1024 * 1024

    # Bearer token for GET /metrics. Empty: the endpoint is open in
    # development and DISABLED (404) in every other environment — privacy
    # fail-closed. Set it to scrape from Prometheus &c.
    metrics_token: str = ""

    # Connection pool for the (Postgres) production engine. SQLite ignores
    # these — its StaticPool single shared connection is what keeps
    # in-memory databases alive across sessions.
    db_pool_size: int = 5
    db_max_overflow: int = 10
    db_pool_timeout: int = 30

    llm_url: str = ""
    llm_api_key: str = ""
    llm_model: str = "gpt-4o-mini"
    # Human-facing processing terms. In production, an LLM endpoint cannot
    # be enabled without these explicit declarations; their values feed the
    # consent-policy fingerprint stored per user.
    llm_provider_name: str = ""
    llm_data_retention: str = ""
    llm_policy_version: str = "v1"

    # Therapist sharing is intentionally development-convenient but
    # production-fail-closed. A production operator must explicitly enable
    # it and supply a controlled enrollment secret; there is no anonymous
    # public route that elevates somebody to a clinician role by default.
    therapist_sharing_enabled: bool | None = None
    therapist_enrollment_token: str = ""

    cors_origins: list[str] = field(default_factory=list)
    trust_proxy_headers: bool = False
    # Source IPs/CIDRs of the *direct* reverse proxy peer. Required whenever
    # proxy headers are trusted; never infer this from a forwarded header.
    trusted_proxy_ips: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Normalize before any comparison: "Production", "production " and
        # "PRODUCTION" must all hit the production gates — an exact-string
        # check silently disarms every hardening flag on a case typo.
        self.environment = self.environment.strip().lower()
        _validate_cors_origins(self.cors_origins, self.environment)
        # Normalize and validate the trust boundary once at boot.  A bare IP
        # becomes its host network (/32 or /128), which keeps the operator
        # setting compact while preserving exact matching semantics.
        normalized_proxy_ips: list[str] = []
        for value in self.trusted_proxy_ips:
            try:
                normalized_proxy_ips.append(str(ip_network(value.strip(), strict=False)))
            except ValueError as exc:
                raise RuntimeError(f"trusted_proxy_ips contains invalid IP/CIDR {value!r}") from exc
        self.trusted_proxy_ips = normalized_proxy_ips
        if self.trust_proxy_headers and not self.trusted_proxy_ips:
            raise RuntimeError(
                "MINDPATTERN_TRUST_PROXY_HEADERS requires a non-empty "
                "MINDPATTERN_TRUSTED_PROXY_IPS allowlist"
            )
        if self.therapist_sharing_enabled is None:
            self.therapist_sharing_enabled = self.environment == "development"
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
            "access_log_retention_days",
            "body_read_timeout_seconds",
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
        # The cross-host advisory guard intentionally reserves one pooled
        # PostgreSQL connection for the process lifetime. A non-development
        # pool with capacity one would therefore boot successfully and then
        # deadlock every ordinary request waiting for the only connection.
        if self.environment != "development" and self.db_pool_size + self.db_max_overflow < 2:
            raise RuntimeError(
                "db_pool_size + db_max_overflow must be >= 2 outside development "
                "(one connection is reserved for the cross-host guard)"
            )
        if self.token_ttl_seconds > MAX_TOKEN_TTL_SECONDS:
            raise RuntimeError(f"token_ttl_seconds must be <= {MAX_TOKEN_TTL_SECONDS}")
        if self.processing_session_ttl > MAX_PROCESSING_SESSION_TTL:
            raise RuntimeError(f"processing_session_ttl must be <= {MAX_PROCESSING_SESSION_TTL}")
        if self.body_read_timeout_seconds > MAX_BODY_READ_TIMEOUT_SECONDS:
            raise RuntimeError(
                f"body_read_timeout_seconds must be <= {MAX_BODY_READ_TIMEOUT_SECONDS}"
            )
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
        for name in ("max_body_bytes", "max_user_blob_bytes", "analysis_blob_budget"):
            if getattr(self, name) < 1024:
                raise RuntimeError(f"{name} must be >= 1024")
        # An analysis budget above the storage quota is misconfiguration
        # (it must BOUND recompute memory below the quota), and 64 MiB of
        # ciphertext is already 8x the 2M-char text analysis budget.
        if self.analysis_blob_budget > 64 * 1024 * 1024:
            raise RuntimeError("analysis_blob_budget must be <= 64 MiB")
        if self.access_log_retention_days > 3_650:
            raise RuntimeError("access_log_retention_days must be <= 3650")
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
            try:
                parsed = urlparse(self.llm_url.strip())
                # As with CORS, .port is where urllib detects malformed
                # authorities such as ``https://provider.example:abc``.
                # Refuse them at boot rather than discovering them only
                # after a consented journal is ready to dispatch.
                _ = parsed.port
            except ValueError as exc:
                raise RuntimeError("MINDPATTERN_LLM_URL contains an invalid authority") from exc
            dev_loopback = (
                self.environment == "development"
                and parsed.scheme == "http"
                and _is_loopback_hostname(parsed.hostname)
            )
            if (
                not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.params
                or parsed.query
                or parsed.fragment
                or (parsed.scheme != "https" and not dev_loopback)
            ):
                raise RuntimeError(
                    "MINDPATTERN_LLM_URL must use https:// — decrypted journal "
                    "plaintext is POSTed to it. Plain http:// is only accepted "
                    "for exact loopback hosts with "
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
            if self.environment != "development":
                missing_policy_terms = [
                    name
                    for name, value in (
                        ("MINDPATTERN_LLM_PROVIDER_NAME", self.llm_provider_name),
                        ("MINDPATTERN_LLM_DATA_RETENTION", self.llm_data_retention),
                        ("MINDPATTERN_LLM_POLICY_VERSION", self.llm_policy_version),
                    )
                    if not value.strip()
                ]
                if missing_policy_terms:
                    raise RuntimeError(
                        "an enabled production LLM requires explicit provider, retention, and policy "
                        "version declarations (set " + ", ".join(missing_policy_terms) + ")"
                    )
        if len(self.llm_policy_version.strip()) > 64:
            raise RuntimeError("llm_policy_version must be at most 64 characters")
        if len(self.llm_provider_name.strip()) > 120:
            raise RuntimeError("llm_provider_name must be at most 120 characters")
        if len(self.llm_data_retention.strip()) > 500:
            raise RuntimeError("llm_data_retention must be at most 500 characters")
        if self.therapist_sharing_enabled and self.environment != "development":
            if len(self.therapist_enrollment_token.strip()) < 32:
                raise RuntimeError(
                    "production therapist sharing requires a controlled "
                    "MINDPATTERN_THERAPIST_ENROLLMENT_TOKEN of at least 32 characters"
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
            body_read_timeout_seconds=_int_env("MINDPATTERN_BODY_READ_TIMEOUT", 30),
            max_body_bytes=_int_env("MINDPATTERN_MAX_BODY_BYTES", 2 * 1024 * 1024),
            max_entries_per_user=_int_env("MINDPATTERN_MAX_ENTRIES_PER_USER", 10_000),
            max_user_blob_bytes=_int_env("MINDPATTERN_MAX_USER_BLOB_BYTES", 256 * 1024 * 1024),
            recompute_entry_limit=_int_env("MINDPATTERN_RECOMPUTE_ENTRY_LIMIT", 2_000),
            analysis_blob_budget=_int_env("MINDPATTERN_ANALYSIS_BLOB_BUDGET", 8 * 1024 * 1024),
            metrics_token=os.getenv("MINDPATTERN_METRICS_TOKEN", "").strip(),
            db_pool_size=_int_env("MINDPATTERN_DB_POOL_SIZE", 5),
            db_max_overflow=_int_env("MINDPATTERN_DB_MAX_OVERFLOW", 10),
            db_pool_timeout=_int_env("MINDPATTERN_DB_POOL_TIMEOUT", 30),
            export_rate_limit=_int_env("MINDPATTERN_EXPORT_RATE_LIMIT", 5),
            export_rate_window=_int_env("MINDPATTERN_EXPORT_RATE_WINDOW", 60),
            access_log_retention_days=_int_env("MINDPATTERN_ACCESS_LOG_RETENTION_DAYS", 730),
            llm_url=os.getenv("MINDPATTERN_LLM_URL", ""),
            llm_api_key=os.getenv("MINDPATTERN_LLM_API_KEY", ""),
            llm_model=os.getenv("MINDPATTERN_LLM_MODEL", "gpt-4o-mini"),
            llm_provider_name=os.getenv("MINDPATTERN_LLM_PROVIDER_NAME", ""),
            llm_data_retention=os.getenv("MINDPATTERN_LLM_DATA_RETENTION", ""),
            llm_policy_version=os.getenv("MINDPATTERN_LLM_POLICY_VERSION", "v1"),
            therapist_sharing_enabled=_optional_bool_env("MINDPATTERN_THERAPIST_SHARING_ENABLED"),
            therapist_enrollment_token=os.getenv("MINDPATTERN_THERAPIST_ENROLLMENT_TOKEN", ""),
            cors_origins=_cors_origins(),
            trust_proxy_headers=_bool_env("MINDPATTERN_TRUST_PROXY_HEADERS"),
            trusted_proxy_ips=_trusted_proxy_ips(),
        )


settings = Settings.from_env()
