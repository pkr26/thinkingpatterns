"""Wave-4 semantic pins from the 2026-09-30 campaign: the highest-density
behavioral survivor clusters in the wiring layer (see
reports/mutation_report_2026-09-30.md's residual census).

Each cluster survived every covering test file: these contracts were
real, observable behaviors with zero pins — object-storage transport
budgets, the CORS method surface, the export/admission limiter budgets,
the LLM token-budget formula, token-parse failure prose, and the 422
detail assembly. Every test here was verified to kill its cluster's
mutants during the campaign's per-mutant verification loop.
"""

from __future__ import annotations

import pytest
from starlette.middleware.cors import CORSMiddleware

from app.config import Settings
from app.main import create_app
from app.security.tokens import TokenError, verify_token
from app.services.audio_store import S3AudioStore


def _dev_settings(**kw) -> Settings:
    s = Settings(environment="development")
    s.database_url = "sqlite+aiosqlite://"
    s.token_secret = "test-secret-not-for-production"
    for k, v in kw.items():
        setattr(s, k, v)
    return s


# -- S3 transport budgets (the M-series voice budget contract) --------------


class _CapturedConfig:
    def __init__(self, cfg):
        self.connect_timeout = cfg.connect_timeout
        self.read_timeout = cfg.read_timeout
        self.retries = cfg.retries
        self.s3 = cfg.s3


def _capture_boto3(monkeypatch):
    captured: dict[str, object] = {}

    class _FakeBoto3:
        @staticmethod
        def client(**kwargs):
            captured.update(kwargs)
            cfg = kwargs.get("config")
            captured["_cfg"] = _CapturedConfig(cfg)
            return object()

    monkeypatch.setattr("boto3.client", _FakeBoto3.client)
    return captured


def test_s3_transport_budgets_default_endpoint(monkeypatch):
    """Five seconds to connect, ten to read, one retry — object storage
    for bounded blobs, never a patient-facing hang."""
    captured = _capture_boto3(monkeypatch)
    store = S3AudioStore(bucket="bkt", region="us-east-1")
    store._s3()
    cfg = captured["_cfg"]
    assert cfg.connect_timeout == 5
    assert cfg.read_timeout == 10
    assert cfg.retries == {"max_attempts": 1, "mode": "standard"}
    assert captured["service_name"] == "s3"
    assert captured["region_name"] == "us-east-1"
    assert "endpoint_url" not in captured


def test_s3_transport_budgets_s3_compatible_endpoint(monkeypatch):
    """The MinIO/dev parity branch: path-style addressing, same budgets."""
    captured = _capture_boto3(monkeypatch)
    store = S3AudioStore(bucket="bkt", region="", endpoint="http://minio:9000")
    store._s3()
    cfg = captured["_cfg"]
    assert captured["endpoint_url"] == "http://minio:9000"
    assert cfg.s3 == {"addressing_style": "path"}
    assert cfg.connect_timeout == 5
    assert cfg.read_timeout == 10
    assert cfg.retries == {"max_attempts": 1, "mode": "standard"}


# -- app wiring: CORS surface + limiter budgets ------------------------------


def test_cors_method_surface_and_limiter_budgets():
    s = _dev_settings(db_pool_size=5, db_max_overflow=10)
    app = create_app(s)
    cors = [mw for mw in app.user_middleware if mw.cls is CORSMiddleware][0]
    assert cors.kwargs["allow_methods"] == [
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
    ]
    # capacity budgets: the expensive recompute and auth admission are
    # bounded at 4 concurrent each; exports at pool capacity minus one
    # connection reserved for ordinary traffic (clamped to [1, 2]).
    assert app.state.analyze_limiter.total_tokens == 4
    assert app.state.auth_admission_limiter.total_tokens == 4
    assert app.state.export_limiter.total_tokens == 2


def test_export_limiter_follows_pool_capacity():
    """The formula, at its clamps: capacity-1 bounded to [1, 2]."""
    assert (
        create_app(
            _dev_settings(db_pool_size=1, db_max_overflow=0)
        ).state.export_limiter.total_tokens
        == 1
    )  # 1+0-1 = 0 -> clamped to 1
    assert (
        create_app(
            _dev_settings(db_pool_size=50, db_max_overflow=50)
        ).state.export_limiter.total_tokens
        == 2
    )  # 99 -> clamped to 2


# -- LLM token-budget formula ------------------------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("text_len", "expected"),
    [
        (1, 512),  # floor: len//2+256 under 512
        (1000, 756),  # len//2 + 256 in range
        (100_000, 4096),  # ceiling (input bounded, tokens clamped)
    ],
)
async def test_translation_token_budget_formula(monkeypatch, text_len, expected):
    """max_tokens = clamp(len(bounded)//2 + 256, 512, 4096) — the S3-grade
    output budget for translations."""
    from app.services import stt

    captured: dict[str, object] = {}

    class _Analyzer:
        def __init__(self, *a, **k):
            pass

        def _post(self, payload):
            captured.update(payload)
            return {
                "choices": [
                    {"finish_reason": "stop", "message": {"content": "Translated transcript."}}
                ]
            }

    # translate_to_english imports LLMAnalyzer from .llm at CALL time —
    # patch it at the source module
    import app.services.llm as llm_mod

    monkeypatch.setattr(llm_mod, "LLMAnalyzer", _Analyzer)
    settings = _dev_settings()
    settings.llm_url = "http://llm.test/v1"
    got = await stt.translate_to_english(settings, "x" * text_len, "es")
    assert got == "Translated transcript."
    assert captured["max_tokens"] == expected
    assert captured["temperature"] == 0.0


# -- token parse failure prose ------------------------------------------------


@pytest.mark.parametrize(
    ("token", "message"),
    [
        ("not-a-token", "malformed token"),  # wrong structure (dots)
        ("a.b", "bad signature"),  # parseable structure, bad sig
    ],
)
def test_verify_token_malformed_inputs(token, message):
    """Malformed inputs raise TokenError with the exact tier prose:
    structure failures say 'malformed token', unverifiable ones say
    'bad signature', payload-shape failures 'malformed payload' — an
    attacker learns nothing about WHICH check failed beyond the tier."""
    with pytest.raises(TokenError, match=rf"^{message}$"):
        verify_token(token, "secret")


def test_verify_token_signed_but_malformed_payload():
    """A correctly-SIGNED token whose payload is not JSON: the signature
    tier passed, the payload tier refused — 'malformed payload'."""
    import base64
    import hmac
    import hashlib

    secret = "secret"
    header = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(b"not-json").rstrip(b"=").decode()
    signing_input = f"{header}.{payload}".encode()
    sig = (
        base64.urlsafe_b64encode(hmac.new(secret.encode(), signing_input, hashlib.sha256).digest())
        .rstrip(b"=")
        .decode()
    )
    with pytest.raises(TokenError, match=r"^malformed payload$"):
        verify_token(f"{header}.{payload}.{sig}", secret)


# -- 422 request-validation detail assembly ---------------------------------


@pytest.mark.anyio
async def test_validation_detail_assembly():
    """The machine-readable 422 shape: 'loc: msg' parts joined by '; ',
    body stripped from locs, capped at 500 chars, with the envelope code."""
    from httpx import ASGITransport, AsyncClient

    app = create_app(_dev_settings())
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post("/api/v1/auth/login", json={"username": "u!"})
    assert r.status_code == 422
    body = r.json()
    assert body["code"] == "validation_error"
    assert body["detail"] == (
        "username: String should match pattern '^[a-zA-Z0-9_.-]{3,64}$'; verifier: Field required"
    )
