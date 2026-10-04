"""Wave-5 semantic pins from the 2026-09-30 campaign: the LLM client's
external contract (see reports/mutation_report_2026-09-30.md).

149 final survivors concentrated in llm.py: the processing-policy
fingerprint inputs, the allowed-kinds tuple woven into the prompt, label
sanitization (the spelled-contact rejection the pentest suites rely on),
and the response-size guard. None were pinned: the fingerprint's exact
value (the thing users' persisted consents compare against) could drift
with nothing failing.
"""

from __future__ import annotations

import pytest

from app.config import Settings
from app.services import llm


def _llm_settings() -> Settings:
    s = Settings(environment="development")
    s.llm_url = "https://llm.example.com/v1/"
    s.llm_model = "model-x"
    s.llm_provider_name = "prov"
    s.llm_data_retention = "30d"
    s.llm_policy_version = "v1"
    return s


def test_processing_policy_fingerprint_is_frozen():
    """The exact fingerprint for a fixed deployment config — this value is
    what persisted user consents compare against; drift here silently
    invalidates (or worse, re-validates) consents."""
    assert llm.processing_policy_fingerprint(_llm_settings()) == (
        "e38f3ce72b769f4901edb48a0cc89ecb86c2307663d194656c9405a7ea4ff9e5"
    )


def test_processing_policy_url_canonicalization():
    """L-20: trailing whitespace and slash are the same provider — one
    fingerprint, never two; a different model is a different policy."""
    base = llm.processing_policy_fingerprint(_llm_settings())
    same = _llm_settings()
    same.llm_url = "  https://llm.example.com/v1  "
    assert llm.processing_policy_fingerprint(same) == base
    other = _llm_settings()
    other.llm_model = "model-y"
    assert llm.processing_policy_fingerprint(other) != base


def test_allowed_kinds_tuple_is_frozen():
    """The narratable-kinds contract, in order: the prompt enumerates them
    and the narration filter accepts exactly these."""
    assert llm._ALLOWED_KINDS == ("temporal", "mood_correlation", "recurring_phrase", "mood_shift")


def test_clean_label_boundaries():
    """Labels survive control-char scrubbing, die on emptiness, length
    overruns, and any URL/phone/spelled-contact signal — the label path
    is what the LLM's prose gets compressed into for pattern cards."""
    # control chars become spaces (no collapse) — the sanitizer's exact form
    assert llm._clean_label("  sleep \x00 pressure ") == "sleep   pressure"
    assert llm._clean_label("") is None
    assert llm._clean_label("x" * 81) is None
    assert llm._clean_label("x" * 80) == "x" * 80
    assert llm._clean_label("see https://x.example") is None
    assert llm._clean_label("call 55512 34567") is None


def test_clean_label_rejects_spelled_contacts():
    """Spelled-out contact handles are rejected even without punctuation —
    the red-team suites pin the behavior; this pins the seam itself."""
    assert llm._clean_label("email me at foo at example dot com") is None
    assert llm._clean_label("work stress after hours") == "work stress after hours"


@pytest.mark.parametrize(
    ("declared", "raises"),
    [
        (0, False),
        (llm.LLM_MAX_RESPONSE_BYTES, False),
        (llm.LLM_MAX_RESPONSE_BYTES + 1, True),
    ],
)
def test_response_size_guard_boundary(declared, raises, monkeypatch):
    """The response-size ceiling is a memory-exhaustion boundary: at most
    LLM_MAX_RESPONSE_BYTES declared bytes pass, one more refuses."""
    import asyncio

    import httpx

    from app.services.llm import LLMResponseTooLarge

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-length": str(declared)},
            content=b"{}",
        )

    analyzer = llm.LLMAnalyzer("http://x", "", "m")

    class _Client(httpx.AsyncClient):
        def __init__(self, **kw):
            super().__init__(transport=httpx.MockTransport(handler), **kw)

    # httpx is imported lazily INSIDE _post_async ("import httpx"), so the
    # module-level attribute of the httpx package itself is the seam
    import httpx as _hx

    real_client = _hx.AsyncClient

    def patched_client(**kw):
        kw["transport"] = _hx.MockTransport(handler)
        return real_client(**kw)

    monkeypatch.setattr(_hx, "AsyncClient", patched_client)

    if raises:
        with pytest.raises(LLMResponseTooLarge):
            analyzer._post({})
    else:
        assert analyzer._post({}) == {}
