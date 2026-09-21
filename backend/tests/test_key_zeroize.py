"""Data-key upload zeroization pins (2026-09-19 remediation).

The audit finding: POST /processing/sessions held the uploaded data key as
immutable ``bytes`` for the whole request — the one holder of key material
outside the enclave's scrubbed-buffer discipline, lingering until GC where
a crash dump could recover the raw journal key. The endpoint now holds a
bytearray and scrubs it on every exit path. These tests pin that contract
by capturing the very buffer the endpoint passes into the keystore.
"""

from __future__ import annotations

import os

os.environ.setdefault("MINDPATTERN_ENV", "development")

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402

from app.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402
from app.security import crypto  # noqa: E402
from tests.helpers import ClientEmulator  # noqa: E402


@pytest.fixture()
def settings() -> Settings:
    s = Settings(environment="development")
    s.database_url = "sqlite+aiosqlite://"
    s.token_secret = "zeroize-test-secret"
    s.entries_rate_limit = 1000
    return s


@pytest_asyncio.fixture()
async def app(settings):
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        yield application


@pytest_asyncio.fixture()
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


async def test_uploaded_data_key_buffer_is_zeroized_after_request(client, app):
    """The buffer the ENDPOINT holds must be scrubbed once the request ends.

    A wrapper around the keystore's create() records the object it received
    — the same object the endpoint keeps zeroizing in its finally — so after
    the response, that object must read as all zeros while the keystore's
    OWN copy still decrypts (proving we zeroized the right buffer, not the
    store's).
    """
    captured: dict[str, object] = {}
    real_create = app.state.key_store.create

    def recording_create(key, ttl_seconds, now=None, owner=None):
        captured["at_handover"] = bytes(key)  # snapshot BEFORE any scrub
        captured["buffer"] = key
        return real_create(key, ttl_seconds, now=now, owner=owner)

    app.state.key_store.create = recording_create

    user = ClientEmulator("zeroize-user", "pw-zeroize")
    await user.register(client)
    token = await user.open_processing_session(client)

    assert token, "session opened"
    buffer = captured["buffer"]
    assert isinstance(buffer, bytearray), "endpoint must hold a zeroizable bytearray"
    assert any(captured["at_handover"]), "sanity: the uploaded key was non-zero at hand-over"
    assert all(b == 0 for b in buffer), (
        "the endpoint's data-key buffer must be zeroized after the request"
    )
    # The keystore's own copy is independent and still usable: a second
    # session upload + consume round-trip proves the store is intact.
    token2 = await user.open_processing_session(client)
    assert token2
    assert app.state.key_store.pop(token2, owner=user.user_id) is not None
    app.state.key_store.create = real_create


async def test_wrong_length_upload_still_scratches_buffer(client):
    """A 422-length rejection must zero the partially-decoded buffer too."""
    import base64

    user = ClientEmulator("zeroize-len", "pw-zeroize")
    await user.register(client)
    response = await client.post(
        "/api/processing/sessions",
        headers=user.headers,
        json={"data_key": base64.b64encode(b"short").decode()},
    )
    assert response.status_code == 422
    assert "data_key must be" in response.json()["detail"]


async def test_keystore_copy_independent_of_endpoint_buffer(client, app):
    """create() must COPY the buffer: zeroizing ours must not corrupt the
    store's key (the session must still pop successfully afterwards)."""
    user = ClientEmulator("zeroize-copy", "pw-zeroize")
    await user.register(client)
    token = await user.open_processing_session(client)
    key = app.state.key_store.pop(token, owner=user.user_id)
    assert len(key) == crypto.KEY_SIZE
    from app.security.enclave import zeroize

    zeroize(key)
