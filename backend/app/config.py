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
import warnings
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
# 2026-09-21 audit A-8: upper bounds for the knobs whose misconfiguration
# is visible only as resource exhaustion (a typo or unit mistake must not
# boot). Each ceiling is far above the default (30x+) so real deployments
# keep every headroom they could legitimately want.
MAX_UNLOCK_THRESHOLD_DAYS = 3_650  # 10 years max baseline (default 30)
MAX_ENTRIES_PER_USER = 1_000_000  # 100x the 10k default storage quota
MAX_USER_BLOB_BYTES = 8 * 1024 * 1024 * 1024  # 8 GiB (32x the 256 MiB quota)
MAX_DB_POOL_TIMEOUT = 600  # seconds waiting for a pooled connection
# 2026-09-26 audit (LOW, batch item f): max_body_bytes had only the shared
# >=1024 floor — a typo'd env value of many GiB would boot and buffer
# attacker-sized bodies at the ASGI edge. The ceiling sits above the whole
# request-budget chain (analysis_blob_budget's own 64 MiB A-8 cap and the
# base64-inflated entry bodies it must fit), so real deployments keep
# every headroom they could legitimately want while a unit mistake fails
# fast at boot like the other A-8 bounds.
MAX_BODY_BYTES = 64 * 1024 * 1024
# 2026-09-26 audit item 9: HardeningMiddleware buffers up to one COMPLETE
# request body per in-flight request, so the edge's worst-case buffer memory
# is max_body_bytes × the server's concurrent-request ceiling. That product
# must be budgeted at boot, not discovered as an OOM under a body-size
# flood: refuse the combination when it exceeds this documented budget.
# 512 MiB: comfortable headroom over the default (2 MiB × 100 concurrent
# requests = ~200 MiB, matching the Docker entrypoint's
# --limit-concurrency 100) while sitting below a typical 1 GiB container.
MAX_BODY_BUFFER_BUDGET_BYTES = 512 * 1024 * 1024


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


def _secret_env(name: str, default: str = "") -> str:
    """Resolve a secret from the env, or from a mounted secret FILE.

    2026-09-26 infra audit: container environment variables are readable
    through `docker inspect` by anyone with host docker access, so the
    deployment contract moves secrets to compose `secrets:` file mounts
    (the same posture the metrics bearer token already had via
    bearer_token_file). Resolution order: the env var itself (kept as the
    development/dev-overlay path), else ``<NAME>_FILE`` — the file's
    content, with surrounding whitespace stripped (secret files
    conventionally end in exactly one newline). A named file that cannot
    be read is a hard boot error, never a silent fallback to the default:
    a half-mounted secret must fail closed like every other config typo.
    An empty/whitespace-only file resolves to "" (treated as unset),
    matching the empty-env-var semantics.
    """
    raw = os.getenv(name, "")
    # Independent audit 2026-09-27: the env branch is stripped too, matching
    # the file branch — a secret that resolves differently by source was a
    # configuration trap (the same value pasted into a file worked, into an
    # env var with a trailing newline broke).
    raw = raw.strip()
    if raw:
        return raw
    file_name = os.getenv(f"{name}_FILE", "")
    if not file_name.strip():
        return default
    try:
        with open(file_name, encoding="utf-8") as handle:
            content = handle.read().strip()
    except OSError as exc:
        raise RuntimeError(
            f"environment variable {name}_FILE={file_name!r} could not be read: {exc}"
        ) from exc
    return content if content else default


def _bool_env(name: str, default: bool = False) -> bool:
    """Parse a bool env var; empty means default, garbage is a hard error.

    2026-09-26 audit item 4: an unrecognized value ("ture", "y") used to
    silently map to False — a typo'd MINDPATTERN_TRUST_PROXY_HEADERS=true
    booted with proxy trust OFF, quietly keying all rate limits on the
    proxy's address. Like _int_env, invalid input now refuses to start:
    the fail-closed direction for a typo'd ON flag would otherwise be a
    silent security-relevant behavior change the operator never asked for.
    """
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    raise ValueError(f"environment variable {name}={os.getenv(name)!r} is not a boolean")


def _optional_bool_env(name: str) -> bool | None:
    """A boolean that distinguishes an absent setting from an explicit off.

    Same fail-closed parsing as _bool_env (audit item 4): garbage refuses
    to boot rather than silently meaning "off".
    """
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return None
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    raise ValueError(f"environment variable {name}={os.getenv(name)!r} is not a boolean")


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
    # repr=False on every credential-bearing field (L-13, 2026-09-20): a
    # generated repr(Settings) must never embed the token secret, the DB
    # URL's password component, the metrics bearer, the LLM API key, or the
    # therapist enrollment token. Today nothing logs that repr — this keeps
    # the first casual ``logger.info(settings)`` harmless.
    database_url: str = field(default="sqlite+aiosqlite:///./mindpattern.db", repr=False)

    token_secret: str = field(default=DEFAULT_INSECURE_SECRET, repr=False)
    # 2026-09-26 remediation — purpose-split secrets. Resolution order for
    # each specific secret (see the properties below): the specific env
    # var, else the LEGACY MINDPATTERN_TOKEN_SECRET, else fail exactly as
    # token_secret itself does (the committed dev default is
    # development-only). The "else legacy" arm is the documented
    # deterministic rewrap path: when only the legacy var is set, each
    # specific secret EQUALS the legacy value (identity derivation), the
    # only derivation that keeps existing bearer signatures, wrapped TOTP
    # secrets, and pairing-code digests valid across the upgrade — every
    # purpose already domain-separates internally through its HKDF info
    # label (totp-at-rest/v1, pairing-digest/v1, totp-backup-digest/v1),
    # so key separation TODAY comes from those labels, and setting an
    # explicit var upgrades a purpose to a fully independent secret
    # (one-way: wrapped TOTP secrets and live pairing digests re-mint;
    # bearer tokens invalidate cleanly via the ksv claim in the payload).
    # Resolution is LIVE (properties over fields) on purpose: tests and
    # tooling legitimately mutate ``token_secret`` after construction,
    # and a snapshot taken in __post_init__ would silently split the
    # secrets from the secret they were derived from.
    auth_token_secret_explicit: str = field(default="", repr=False)
    totp_wrap_secret_explicit: str = field(default="", repr=False)
    pairing_secret_explicit: str = field(default="", repr=False)

    @property
    def auth_token_secret(self) -> str:
        """Bearer-token signing secret (deps.require_user, both issuers)."""
        return self.auth_token_secret_explicit.strip() or self.token_secret

    @property
    def totp_wrap_secret(self) -> str:
        """Secret under which therapist TOTP secrets (and their backup-code
        digests) are wrapped at rest."""
        return self.totp_wrap_secret_explicit.strip() or self.token_secret

    @property
    def pairing_secret(self) -> str:
        """Secret keying pairing-code (and backup-code) HMAC digests."""
        return self.pairing_secret_explicit.strip() or self.token_secret

    @property
    def auth_secret_version(self) -> int:
        """ksv stamped into every token: 1 = resolved-from-legacy, 2 =
        explicit dedicated auth secret. Tokens embed the version they were
        minted under and deps refuses a mismatch, so rotating to a split
        secret invalidates EVEN WHEN an operator copies the same bytes."""
        return 2 if self.auth_token_secret_explicit.strip() else 1

    # Independent audit 2026-09-27: keyed seal for the access-log chain.
    # The link hashes are SHA-256 over public fields, so a DB-write attacker
    # could recompute them; the MAC key must live OUTSIDE the database.
    # Explicit MINDPATTERN_AUDIT_MAC_SECRET (env or _FILE) wins; otherwise
    # it is HKDF-derived from the token secret with its own info label, so
    # rotating the token secret rotates the MAC key by construction. LIVE
    # property on the same standing as the purpose-split secrets above.
    audit_mac_secret_explicit: str = field(default="", repr=False)

    @property
    def audit_mac_secret_hex(self) -> str:
        """Hex-encoded HMAC key for AccessLog.entry_mac (32 bytes)."""
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes

        explicit = self.audit_mac_secret_explicit.strip()
        if explicit:
            return explicit
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"mindpattern/audit-chain/v1",
            info=b"mindpattern/audit-chain-mac/v1",
        )
        return hkdf.derive(self.token_secret.encode("utf-8")).hex()

    # Independent audit 2026-09-27: append-only journal anchoring the audit
    # chain's TAIL. A forward hash chain cannot detect deletion of its
    # newest rows; when this path is set (a volume-mounted file), every
    # committed audit append also writes a line here and verification flags
    # a journal that is AHEAD of the database head as tail truncation.
    # Empty (default) keeps the honest link-only boundary; compose wires a
    # named volume by default so production gets the anchor for free.
    audit_journal_path: str = ""

    # 2026-09-26 remediation (LOW c): server-side scrypt work factor.
    # Raised 2^16 -> 2^17 as the config default (~70ms and 128 MiB per
    # hash on current server hardware): the login latency budget stays
    # comfortably inside the auth admission limiter's 503 boundary, while
    # an offline attacker who extracts scrypt_salt+verifier pays 2x the
    # RAM per guess ON TOP of the client-side PBKDF2-600k stretch of the
    # input. OPERATOR MIGRATION NOTE: scrypt output depends on N, and the
    # schema stores no per-account work factor — an account whose stored
    # verifier was hashed under the old 2^16 default fails login after an
    # upgrade until it re-registers, OR the operator pins
    # MINDPATTERN_SCRYPT_N=65536 to hold the old factor for existing
    # fleets. Fresh deployments (and this test suite) create every
    # account under the configured value.
    scrypt_n: int = 2**17
    # 2026-09-21 audit C-6: decoy salts for unknown usernames derive from
    # the token secret by default, so rotating MINDPATTERN_TOKEN_SECRET
    # changes every decoy salt — a longitudinal observer could distinguish
    # "unknown user" responses across the rotation boundary. Set a
    # dedicated secret to decouple the two lifecycles. Empty = derive from
    # token_secret (the pre-existing behavior).
    decoy_secret: str = field(default="", repr=False)
    token_ttl_seconds: int = 86_400

    processing_session_ttl: int = 300
    unlock_threshold_days: int = 30

    auth_rate_limit: int = 10
    auth_rate_window: int = 60
    # Per-USERNAME second-factor failure budget (2026-09-26 pentest D-4).
    # Distinct from auth_rate_limit on purpose: the per-IP bucket cannot
    # see distributed TOTP guessing, and this keyed bucket (reachable only
    # with a valid verifier, so no lockout oracle for unauthenticated
    # spray) must stay independently observable and configurable.
    totp_failure_limit: int = 10
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
    # Ops endpoints (2026-09-20 audit fix L-2): /readyz opens a pooled DB
    # session and runs two queries per hit. Unthrottled, an unauthenticated
    # flood bypasses every API bucket and competes for the same pool as real
    # traffic — one shared, generous bucket for /healthz + /readyz keeps
    # load-balancer probes comfortable while bounding the flood.
    ops_rate_limit: int = 240
    ops_rate_window: int = 60
    # Therapist/patient access-audit metadata retention. This is metadata,
    # not journal plaintext, but it remains sensitive and must be explicit.
    access_log_retention_days: int = 730

    # Whole-request body cap, enforced before the JSON is parsed. Field-level
    # caps in schemas.py bound what is *stored*; this bounds what is *read*.
    max_body_bytes: int = 2 * 1024 * 1024  # 2 MiB
    # 2026-09-26 audit item 9: the concurrent-request count the edge body
    # buffer is budgeted against (see MAX_BODY_BUFFER_BUDGET_BYTES). The
    # default matches the Docker entrypoint's uvicorn --limit-concurrency
    # 100; raise it ONLY together with the server's own concurrency cap (the
    # pair is validated at boot: max_body_bytes × body_buffer_concurrency
    # must stay within the documented memory budget).
    body_buffer_concurrency: int = 100
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
    metrics_token: str = field(default="", repr=False)

    # Connection pool for the (Postgres) production engine. SQLite ignores
    # these — its StaticPool single shared connection is what keeps
    # in-memory databases alive across sessions.
    db_pool_size: int = 5
    db_max_overflow: int = 10
    db_pool_timeout: int = 30
    # Server-side timeouts on every pooled asyncpg connection (2026-09-21
    # audit B-3): statement_timeout bounds any single query; the
    # idle-in-transaction timeout is the important one — a transaction
    # leaked open (bug or crash between statements) used to pin xmin and
    # block vacuum until an operator noticed. Generous defaults: the
    # longest legitimate transaction (rekey) pauses between statements
    # only for per-batch crypto (milliseconds), never minutes.
    db_statement_timeout_ms: int = 30_000
    db_idle_in_transaction_timeout_ms: int = 300_000

    llm_url: str = ""
    llm_api_key: str = field(default="", repr=False)
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
    therapist_enrollment_token: str = field(default="", repr=False)

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
                network = ip_network(value.strip(), strict=False)
            except ValueError as exc:
                raise RuntimeError(f"trusted_proxy_ips contains invalid IP/CIDR {value!r}") from exc
            # 2026-09-19 pen-test round: trust-the-world entries boot cleanly
            # and fail SILENTLY — every XFF chain entry lands inside the
            # trusted set, the rightmost-untrusted walk finds nothing, and
            # rate limiting collapses to ONE global bucket keyed on the
            # proxy's address (ten requests a minute from anyone then 429s
            # auth for the whole deployment, with the misconfig warning
            # suppressed because the header is nominally "trusted").
            if network.prefixlen == 0:
                raise RuntimeError(
                    f"trusted_proxy_ips entry {value!r} matches every address; "
                    "it would collapse all rate limiting into one global "
                    "bucket. List the proxy's actual address(es) or CIDR."
                )
            # Wide-but-not-total ranges are a legitimate private-network
            # shorthand, so they only warn — but the operator should see that
            # every host inside the range can forge rate-limit identities.
            if network.prefixlen < (24 if network.version == 4 else 64):
                warnings.warn(
                    f"trusted_proxy_ips entry {value!r} is wider than /"
                    f"{24 if network.version == 4 else 64}: every host inside "
                    "it can forge X-Forwarded-For identities and spend other "
                    "clients' rate-limit budgets. Prefer the narrowest CIDR "
                    "that actually covers the proxy tier.",
                    stacklevel=2,
                )
            normalized_proxy_ips.append(str(network))
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
        # Purpose-split explicit overrides: an explicitly set specific
        # secret meets the same floor as the legacy secret (each one signs
        # or wraps credential material). Derived (empty) overrides are
        # validated transitively — they equal token_secret, checked above.
        if self.environment != "development":
            for name, explicit in (
                ("MINDPATTERN_AUTH_TOKEN_SECRET", self.auth_token_secret_explicit),
                ("MINDPATTERN_TOTP_WRAP_SECRET", self.totp_wrap_secret_explicit),
                ("MINDPATTERN_PAIRING_SECRET", self.pairing_secret_explicit),
            ):
                if explicit.strip() and len(explicit.strip()) < 32:
                    raise RuntimeError(f"{name} must be at least 32 characters")
            # 2026-09-28 deep audit: the metrics bearer token gates /metrics
            # in production and previously booted with any value (a 1-char
            # token met the same brute-force analysis as a 3-char signing
            # secret). Same floor as every other credential-bearing setting.
            if self.metrics_token.strip() and len(self.metrics_token.strip()) < 32:
                raise RuntimeError(
                    "MINDPATTERN_METRICS_TOKEN must be at least 32 characters "
                    f"in environment {self.environment!r}"
                )
        # scrypt N: a power of two within [2^15, 2^20]. A non-power-of-two N
        # is legal for hashlib but has no analyzed cost profile, and a
        # typo'd order of magnitude must fail at boot, not as a login
        # latency surprise (or an instant OOM at 2^30).
        if not (2**15 <= self.scrypt_n <= 2**20) or self.scrypt_n & (self.scrypt_n - 1) != 0:
            raise RuntimeError(
                f"scrypt_n must be a power of two between 32768 and 1048576 (got {self.scrypt_n})"
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
            "totp_failure_limit",
            "entries_rate_limit",
            "entries_rate_window",
            "processing_rate_limit",
            "processing_rate_window",
            "read_rate_limit",
            "read_rate_window",
            "export_rate_limit",
            "export_rate_window",
            "ops_rate_limit",
            "ops_rate_window",
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
        # C-6 (2026-09-21): a set decoy secret must meet the same bar as
        # the token secret — it feeds a password-derivation decoy path.
        if self.decoy_secret.strip() and len(self.decoy_secret.strip()) < 32:
            raise RuntimeError("MINDPATTERN_DECOY_SECRET must be at least 32 characters")
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
            "ops_rate_window",
        ):
            if getattr(self, name) > MAX_RATE_WINDOW_SECONDS:
                raise RuntimeError(f"{name} must be <= {MAX_RATE_WINDOW_SECONDS}")
        for name in (
            "auth_rate_limit",
            "totp_failure_limit",
            "entries_rate_limit",
            "processing_rate_limit",
            "read_rate_limit",
            "export_rate_limit",
            "ops_rate_limit",
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
        # 2026-09-21 audit A-8: a budget smaller than one request body can
        # never load even the newest entry — the analysis would run on an
        # empty corpus and silently overwrite stored patterns (the
        # recompute path now refuses that at runtime with 413, but the
        # config should fail fast at boot). No stored blob can exceed
        # max_body_bytes (an entry body carries the blob's own base64), so
        # this floor guarantees the budget always fits at least one entry.
        if self.analysis_blob_budget < self.max_body_bytes:
            raise RuntimeError(
                "analysis_blob_budget must be >= max_body_bytes "
                "(the budget must fit at least one max-size entry)"
            )
        # 2026-09-21 audit A-8: upper bounds — see the MAX_* constants
        # above for the per-knob rationale.
        if self.unlock_threshold_days > MAX_UNLOCK_THRESHOLD_DAYS:
            raise RuntimeError(f"unlock_threshold_days must be <= {MAX_UNLOCK_THRESHOLD_DAYS}")
        if self.max_entries_per_user > MAX_ENTRIES_PER_USER:
            raise RuntimeError(f"max_entries_per_user must be <= {MAX_ENTRIES_PER_USER}")
        if self.max_user_blob_bytes > MAX_USER_BLOB_BYTES:
            raise RuntimeError("max_user_blob_bytes must be <= 8 GiB")
        # 2026-09-26 audit (LOW, batch item f): explicit ceiling — see the
        # MAX_BODY_BYTES constant above (A-8-style fail-fast bound).
        if self.max_body_bytes > MAX_BODY_BYTES:
            raise RuntimeError(f"max_body_bytes must be <= {MAX_BODY_BYTES}")
        # Independent audit 2026-09-27: the audit-chain MAC secret must be
        # usable key material — 32 bytes hex (64 chars). A typo'd value
        # would otherwise explode later inside create_app with an opaque
        # traceback instead of a named boot error.
        explicit_mac = self.audit_mac_secret_explicit.strip()
        if explicit_mac and (
            len(explicit_mac) != 64 or any(c not in "0123456789abcdefABCDEF" for c in explicit_mac)
        ):
            raise RuntimeError("MINDPATTERN_AUDIT_MAC_SECRET must be 32 bytes of hex (64 chars)")
        # 2026-09-26 audit item 9: the edge buffers one complete body per
        # in-flight request, so the deployment's worst-case buffer memory is
        # this product. Refuse the combination up front with the arithmetic
        # in the message — an operator raising either knob alone must see
        # exactly which budget they blew.
        if not 1 <= self.body_buffer_concurrency <= 100_000:
            raise RuntimeError("body_buffer_concurrency must be between 1 and 100000")
        if self.max_body_bytes * self.body_buffer_concurrency > MAX_BODY_BUFFER_BUDGET_BYTES:
            raise RuntimeError(
                "max_body_bytes * body_buffer_concurrency exceeds the edge "
                f"body-buffer memory budget ({MAX_BODY_BUFFER_BUDGET_BYTES} bytes): "
                f"{self.max_body_bytes} * {self.body_buffer_concurrency}. Lower one of "
                "them (or raise the budget with eyes open) — a body-size flood "
                "otherwise buffers past the container's memory."
            )
        if self.db_pool_timeout > MAX_DB_POOL_TIMEOUT:
            raise RuntimeError(f"db_pool_timeout must be <= {MAX_DB_POOL_TIMEOUT}")
        # 2026-09-21 audit B-3: sub-second server timeouts are a self-DoS
        # (every ordinary query would race its own clock); the ceilings
        # keep a typo from disabling them outright.
        for name, ceiling in (
            ("db_statement_timeout_ms", 600_000),
            ("db_idle_in_transaction_timeout_ms", 3_600_000),
        ):
            value = getattr(self, name)
            if not 1_000 <= value <= ceiling:
                raise RuntimeError(f"{name} must be between 1000 and {ceiling}")
        # Retention gets an explicit two-sided bound (M-29, 2026-09-20):
        # 0 or negative would prune the ENTIRE therapist access-audit table
        # on the first startup sweep — the audit trail is a compliance
        # artifact, not a tuning knob with a floor of "any int". The
        # 10-year ceiling bounds the un-prunable worst case against the
        # documented 730-day default.
        if not 1 <= self.access_log_retention_days <= 3_650:
            raise RuntimeError("access_log_retention_days must be between 1 and 3650")
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
            token_secret=_secret_env("MINDPATTERN_TOKEN_SECRET", DEFAULT_INSECURE_SECRET),
            auth_token_secret_explicit=_secret_env("MINDPATTERN_AUTH_TOKEN_SECRET"),
            totp_wrap_secret_explicit=_secret_env("MINDPATTERN_TOTP_WRAP_SECRET"),
            pairing_secret_explicit=_secret_env("MINDPATTERN_PAIRING_SECRET"),
            # Independent audit 2026-09-27: same file-mount resolution as
            # every other secret — the metrics bearer token was the last
            # one still readable via `docker inspect` env.
            metrics_token=_secret_env("MINDPATTERN_METRICS_TOKEN"),
            audit_mac_secret_explicit=_secret_env("MINDPATTERN_AUDIT_MAC_SECRET"),
            audit_journal_path=os.getenv("MINDPATTERN_AUDIT_JOURNAL", "").strip(),
            scrypt_n=_int_env("MINDPATTERN_SCRYPT_N", 2**17),
            decoy_secret=_secret_env("MINDPATTERN_DECOY_SECRET"),
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
            body_buffer_concurrency=_int_env("MINDPATTERN_BODY_BUFFER_CONCURRENCY", 100),
            max_entries_per_user=_int_env("MINDPATTERN_MAX_ENTRIES_PER_USER", 10_000),
            max_user_blob_bytes=_int_env("MINDPATTERN_MAX_USER_BLOB_BYTES", 256 * 1024 * 1024),
            recompute_entry_limit=_int_env("MINDPATTERN_RECOMPUTE_ENTRY_LIMIT", 2_000),
            analysis_blob_budget=_int_env("MINDPATTERN_ANALYSIS_BLOB_BUDGET", 8 * 1024 * 1024),
            db_pool_size=_int_env("MINDPATTERN_DB_POOL_SIZE", 5),
            db_max_overflow=_int_env("MINDPATTERN_DB_MAX_OVERFLOW", 10),
            db_pool_timeout=_int_env("MINDPATTERN_DB_POOL_TIMEOUT", 30),
            db_statement_timeout_ms=_int_env("MINDPATTERN_DB_STATEMENT_TIMEOUT_MS", 30_000),
            db_idle_in_transaction_timeout_ms=_int_env(
                "MINDPATTERN_DB_IDLE_IN_TX_TIMEOUT_MS", 300_000
            ),
            export_rate_limit=_int_env("MINDPATTERN_EXPORT_RATE_LIMIT", 5),
            export_rate_window=_int_env("MINDPATTERN_EXPORT_RATE_WINDOW", 60),
            totp_failure_limit=_int_env("MINDPATTERN_TOTP_FAILURE_LIMIT", 10),
            ops_rate_limit=_int_env("MINDPATTERN_OPS_RATE_LIMIT", 240),
            ops_rate_window=_int_env("MINDPATTERN_OPS_RATE_WINDOW", 60),
            access_log_retention_days=_int_env("MINDPATTERN_ACCESS_LOG_RETENTION_DAYS", 730),
            llm_url=os.getenv("MINDPATTERN_LLM_URL", ""),
            # 2026-09-28 deep audit: file-mount resolution like every other
            # credential-bearing secret — these two were the last still
            # plain-env-only, readable via `docker inspect` despite the
            # comment above claiming the class was closed.
            llm_api_key=_secret_env("MINDPATTERN_LLM_API_KEY"),
            llm_model=os.getenv("MINDPATTERN_LLM_MODEL", "gpt-4o-mini"),
            llm_provider_name=os.getenv("MINDPATTERN_LLM_PROVIDER_NAME", ""),
            llm_data_retention=os.getenv("MINDPATTERN_LLM_DATA_RETENTION", ""),
            llm_policy_version=os.getenv("MINDPATTERN_LLM_POLICY_VERSION", "v1"),
            therapist_sharing_enabled=_optional_bool_env("MINDPATTERN_THERAPIST_SHARING_ENABLED"),
            therapist_enrollment_token=_secret_env("MINDPATTERN_THERAPIST_ENROLLMENT_TOKEN"),
            cors_origins=_cors_origins(),
            trust_proxy_headers=_bool_env("MINDPATTERN_TRUST_PROXY_HEADERS"),
            trusted_proxy_ips=_trusted_proxy_ips(),
        )


settings = Settings.from_env()
