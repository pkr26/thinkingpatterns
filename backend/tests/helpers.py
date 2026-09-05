"""ClientEmulator: a faithful mirror of the mobile client's crypto stack.

Uses the same key schedule (PBKDF2 -> HKDF auth/data keys), the same
AES-256-GCM envelope format and the same AAD bindings as mobile/src/crypto,
so every API test exercises the exact bytes a real device would send.
"""

from __future__ import annotations

import base64
import json
import os
from datetime import date

from httpx import AsyncClient

from app.security import crypto, kdf

FAST_ITERATIONS = 1_000  # test-only KDF cost; server never re-derives keys


class ClientEmulator:
    def __init__(self, username: str, password: str, salt: bytes | None = None):
        self.username = username
        self.password = password
        self.salt = salt or os.urandom(16)
        self.master_key = kdf.derive_master_key(password, self.salt, FAST_ITERATIONS)
        self.auth_key = kdf.derive_auth_key(self.master_key)
        self.data_key = kdf.derive_data_key(self.master_key)
        self.user_id: str | None = None
        self.token: str | None = None

    # ---- key material encodings -------------------------------------------------

    @property
    def salt_b64(self) -> str:
        return base64.b64encode(self.salt).decode("ascii")

    @property
    def auth_key_b64(self) -> str:
        return base64.b64encode(self.auth_key).decode("ascii")

    @property
    def data_key_b64(self) -> str:
        return base64.b64encode(self.data_key).decode("ascii")

    # ---- envelope helpers (identical contract to the mobile app) ----------------

    def encrypt_entry(self, text: str, entry_date: date, client_entry_id: str,
                      sentiment: float | None = None) -> str:
        payload = {
            "v": 1,
            "text": text,
            "sentiment": sentiment,
            "created_at": entry_date.isoformat(),
        }
        aad = crypto.build_aad("entry", self.user_id or "", client_entry_id)
        blob = crypto.encrypt(self.data_key, json.dumps(payload).encode("utf-8"), aad)
        return base64.b64encode(blob).decode("ascii")

    def decrypt_blob(self, blob_b64: str, aad: bytes) -> dict:
        blob = base64.b64decode(blob_b64)
        plaintext = crypto.decrypt(self.data_key, blob, aad)
        return json.loads(plaintext.decode("utf-8"))

    # ---- API flows --------------------------------------------------------------

    @property
    def headers(self) -> dict:
        if not self.token:
            raise RuntimeError("not logged in")
        return {"Authorization": f"Bearer {self.token}"}

    async def register(self, client: AsyncClient) -> dict:
        response = await client.post("/api/auth/register", json={
            "username": self.username,
            "salt": self.salt_b64,
            "verifier": self.auth_key_b64,
        })
        assert response.status_code == 201, response.text
        body = response.json()
        self.user_id = body["user_id"]
        self.token = body["token"]
        return body

    async def login(self, client: AsyncClient) -> dict:
        response = await client.post("/api/auth/login", json={
            "username": self.username,
            "verifier": self.auth_key_b64,
        })
        assert response.status_code == 200, response.text
        body = response.json()
        self.user_id = body["user_id"]
        self.token = body["token"]
        return body

    async def backdate_account(self, client: AsyncClient, days: int) -> None:
        """Move this account's created_at back *days* days.

        The server rejects entries dated before the account existed (minus a
        timezone-grace day) so the 30-day threshold cannot be fast-forwarded
        by backdated entries; tests that legitimately seed historical corpora
        must age the account first — exactly what a real 30-day user has.
        """
        from datetime import timedelta

        from sqlalchemy import update

        from app.models import User, utcnow

        app = client._transport.app  # noqa: SLF001 — test reachability into state
        async with app.state.sessionmaker() as session:
            await session.execute(
                update(User)
                .where(User.id == self.user_id)
                .values(created_at=utcnow() - timedelta(days=days))
            )
            await session.commit()

    async def delete_account(self, client: AsyncClient) -> int:
        """Delete this account with the required password-equivalent proof."""
        response = await client.request(
            "DELETE", "/api/account", headers=self.headers,
            json={"verifier": self.auth_key_b64},
        )
        return response.status_code

    async def create_entry(self, client: AsyncClient, text: str, entry_date: date,
                           client_entry_id: str | None = None,
                           sentiment: float | None = None) -> dict:
        client_entry_id = client_entry_id or f"e-{entry_date.isoformat()}-{os.urandom(4).hex()}"
        blob = self.encrypt_entry(text, entry_date, client_entry_id, sentiment)
        response = await client.post("/api/entries", headers=self.headers, json={
            "client_entry_id": client_entry_id,
            "blob": blob,
            "entry_date": entry_date.isoformat(),
        })
        assert response.status_code == 201, response.text
        return response.json()

    async def open_processing_session(self, client: AsyncClient) -> str:
        response = await client.post("/api/processing/sessions", headers=self.headers,
                                     json={"data_key": self.data_key_b64})
        assert response.status_code == 201, response.text
        return response.json()["session_token"]

    async def recompute(self, client: AsyncClient) -> dict:
        """Open a fresh (single-use) processing session and recompute."""
        token = await self.open_processing_session(client)
        response = await client.post(
            "/api/insights/recompute",
            headers={**self.headers, "X-Processing-Token": token},
        )
        assert response.status_code == 200, response.text
        return response.json()

    async def salt_for(self, client: AsyncClient) -> dict:
        response = await client.post("/api/auth/salt", json={"username": self.username})
        assert response.status_code == 200, response.text
        return response.json()

    async def decrypt_insights(self, client: AsyncClient) -> dict:
        response = await client.get("/api/insights", headers=self.headers)
        assert response.status_code == 200, response.text
        blob = response.json()["blob"]
        assert blob is not None
        return self.decrypt_blob(blob, crypto.build_aad("insights", self.user_id, "patterns"))

    async def decrypt_question(self, client: AsyncClient, for_date: date) -> dict:
        response = await client.get("/api/questions/today", headers=self.headers)
        assert response.status_code == 200, response.text
        return self.decrypt_blob(
            response.json()["blob"], crypto.build_aad("question", self.user_id, for_date.isoformat())
        )


def daterange(days: int, end: date) -> list[date]:
    """The last *days* calendar days ending at *end* (inclusive)."""
    from datetime import timedelta
    return [end - timedelta(days=offset) for offset in range(days - 1, -1, -1)]
