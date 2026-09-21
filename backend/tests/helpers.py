"""ClientEmulator: a faithful mirror of the mobile client's crypto stack.

Uses the same key schedule (PBKDF2 -> HKDF auth/data keys), the same
AES-256-GCM envelope format and the same AAD bindings as mobile/src/crypto,
so every API test exercises the exact bytes a real device would send.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import date

from httpx import AsyncClient

from app.security import crypto, kdf

# Test-only KDF cost. The shipping library floors iterations at
# kdf.MIN_ITERATIONS (2026-09-16 remediation), so the emulator derives its
# fast master key with hashlib DIRECTLY: the floor protects production
# callers, and this emulator is harness code, not the product. The key
# schedule below (HKDF auth/data keys) is still the real library.
FAST_ITERATIONS = 1_000


class ClientEmulator:
    def __init__(self, username: str, password: str, salt: bytes | None = None):
        self.username = username
        self.password = password
        self.salt = salt or os.urandom(16)
        self.master_key = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self.salt, FAST_ITERATIONS
        )
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

    def encrypt_entry(
        self,
        text: str,
        entry_date: date,
        client_entry_id: str,
        sentiment: float | None = None,
        content_version: int | None = None,
        tod: str | None = None,
    ) -> str:
        """Encrypt an entry payload. ``content_version=None`` reproduces the
        LEGACY v1 three-part AAD (pre-2026-09-20 blobs, and the shape every
        pre-existing test pins); an int produces the v2 version-bound AAD a
        current client sends — mirroring the mobile app's migration ladder.
        ``tod`` (P3, 2026-09-21) rides the v2 payload's optional coarse
        writing-window bucket exactly as the mobile app sends it."""
        payload = {
            "v": 1,
            "text": text,
            "sentiment": sentiment,
            "created_at": entry_date.isoformat(),
        }
        if tod is not None:
            payload["v"] = 2
            payload["tod"] = tod
        if content_version is None:
            aad = crypto.entry_aad_v1(self.user_id or "", client_entry_id)
        else:
            aad = crypto.entry_aad_v2(self.user_id or "", client_entry_id, content_version)
        blob = crypto.encrypt(self.data_key, json.dumps(payload).encode("utf-8"), aad)
        return base64.b64encode(blob).decode("ascii")

    def decrypt_entry(self, blob_b64: str, client_entry_id: str, content_version: int) -> dict:
        """Decrypt an entry with the v2-then-v1 candidate ladder (the same
        acceptance rule the server's recompute and rekey paths use)."""
        blob = base64.b64decode(blob_b64)
        failure: Exception | None = None
        for aad in crypto.entry_aad_candidates(
            self.user_id or "", client_entry_id, content_version
        ):
            try:
                return json.loads(crypto.decrypt(self.data_key, blob, aad).decode("utf-8"))
            except crypto.TamperError as exc:
                failure = exc
        assert failure is not None
        raise failure

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
        response = await client.post(
            "/api/auth/register",
            json={
                "username": self.username,
                "salt": self.salt_b64,
                "verifier": self.auth_key_b64,
            },
        )
        assert response.status_code == 201, response.text
        body = response.json()
        self.user_id = body["user_id"]
        self.token = body["token"]
        return body

    async def login(self, client: AsyncClient) -> dict:
        response = await client.post(
            "/api/auth/login",
            json={
                "username": self.username,
                "verifier": self.auth_key_b64,
            },
        )
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
            "DELETE",
            "/api/account",
            headers=self.headers,
            json={"verifier": self.auth_key_b64},
        )
        return response.status_code

    async def create_entry(
        self,
        client: AsyncClient,
        text: str,
        entry_date: date,
        client_entry_id: str | None = None,
        sentiment: float | None = None,
        content_version: int | None = None,
        tod: str | None = None,
    ) -> dict:
        """POST an entry. ``content_version`` selects the v2 AAD generation
        (None = legacy v1 bytes, the pre-2026-09-20 contract older tests and
        older deployed clients produce) and rides the JSON body when set."""
        client_entry_id = client_entry_id or f"e-{entry_date.isoformat()}-{os.urandom(4).hex()}"
        blob = self.encrypt_entry(
            text,
            entry_date,
            client_entry_id,
            sentiment,
            content_version=content_version,
            tod=tod,
        )
        body = {
            "client_entry_id": client_entry_id,
            "blob": blob,
            "entry_date": entry_date.isoformat(),
        }
        if content_version is not None:
            body["content_version"] = content_version
        response = await client.post("/api/entries", headers=self.headers, json=body)
        assert response.status_code == 201, response.text
        return response.json()

    async def get_entry(self, client: AsyncClient, client_entry_id: str) -> dict:
        """GET /entries/{id} — the idempotency-verification primitive."""
        response = await client.get(f"/api/entries/{client_entry_id}", headers=self.headers)
        assert response.status_code == 200, response.text
        return response.json()

    async def replace_entry(
        self,
        client: AsyncClient,
        client_entry_id: str,
        text: str,
        entry_date: date,
        content_version: int | None = None,
    ) -> dict:
        """PUT /entries/{id} — the atomic replacement path."""
        blob = self.encrypt_entry(
            text, entry_date, client_entry_id, content_version=content_version
        )
        body: dict = {"blob": blob, "entry_date": entry_date.isoformat()}
        if content_version is not None:
            body["content_version"] = content_version
        response = await client.put(
            f"/api/entries/{client_entry_id}", headers=self.headers, json=body
        )
        assert response.status_code == 200, response.text
        return response.json()

    async def open_processing_session(self, client: AsyncClient) -> str:
        response = await client.post(
            "/api/processing/sessions", headers=self.headers, json={"data_key": self.data_key_b64}
        )
        assert response.status_code == 201, response.text
        return response.json()["session_token"]

    # ---- rotation flow (2026-09-20, audit fix H-1/M-3) ---------------------

    def derive_new_generation(self, password: str, salt: bytes | None = None) -> None:
        """Derive the NEXT key generation in place (new salt by default).

        Mirrors the client's change-password derivation: a fresh random salt,
        a new master key from the NEW password, and the same HKDF labels.
        The previous generation's keys must be captured by the caller BEFORE
        this call (old_data_key) — rekey needs both.
        """
        self.password = password
        self.salt = salt or os.urandom(16)
        self.master_key = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self.salt, FAST_ITERATIONS
        )
        self.auth_key = kdf.derive_auth_key(self.master_key)
        self.data_key = kdf.derive_data_key(self.master_key)

    async def open_processing_session_for(self, client: AsyncClient, key: bytes) -> str:
        response = await client.post(
            "/api/processing/sessions",
            headers=self.headers,
            json={"data_key": base64.b64encode(key).decode("ascii")},
        )
        assert response.status_code == 201, response.text
        return response.json()["session_token"]

    async def rekey(
        self,
        client: AsyncClient,
        old_key: bytes,
        new_key: bytes,
        verifier: str | None = None,
    ) -> dict:
        """POST /processing/rekey — re-encrypt every stored blob old→new."""
        old_token = await self.open_processing_session_for(client, old_key)
        new_token = await self.open_processing_session_for(client, new_key)
        response = await client.post(
            "/api/processing/rekey",
            headers={
                **self.headers,
                "X-Processing-Token": old_token,
                "X-New-Processing-Token": new_token,
                "X-Account-Verifier": verifier or self.auth_key_b64,
            },
        )
        assert response.status_code == 200, response.text
        return response.json()

    async def rotate_credential(
        self,
        client: AsyncClient,
        old_verifier_b64: str,
        new_salt: bytes,
        new_verifier_b64: str,
    ) -> int:
        """PUT /account/credential — retire the phishable login credential."""
        response = await client.put(
            "/api/account/credential",
            headers=self.headers,
            json={
                "verifier": old_verifier_b64,
                "new_salt": base64.b64encode(new_salt).decode("ascii"),
                "new_verifier": new_verifier_b64,
            },
        )
        return response.status_code

    async def rewrap_consent(
        self,
        client: AsyncClient,
        consent_id: str,
        therapist_pub_b64: str,
        therapist_id: str,
        verifier: str | None = None,
    ) -> dict:
        """PUT /consents/{id}/rewrap — wrap the CURRENT data key to the same
        therapist (the client's post-rekey step for every active grant)."""
        wrap = patient_wrap_for(self, therapist_pub_b64, therapist_id)
        response = await client.put(
            f"/api/consents/{consent_id}/rewrap",
            headers={**self.headers, "X-Account-Verifier": verifier or self.auth_key_b64},
            json=wrap,
        )
        return {
            "status": response.status_code,
            "body": response.json() if response.content else None,
        }

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
            response.json()["blob"],
            crypto.build_aad("question", self.user_id, for_date.isoformat()),
        )

    # ---- sharing flows (2026-09-16, additive) -------------------------------

    async def pairing_lookup(self, client: AsyncClient, code: str) -> dict:
        response = await client.post(
            "/api/consents/pairing/lookup", headers=self.headers, json={"code": code}
        )
        return {
            "status": response.status_code,
            "body": response.json() if response.content else None,
        }

    async def grant_consent(
        self,
        client: AsyncClient,
        code: str,
        therapist_pub_b64: str,
        therapist_id: str,
        verifier: str | None = None,
        disclosure: str | None = None,
    ) -> dict:
        """POST /consents with the X-Account-Verifier re-auth, wrapping the
        data key to the therapist's public key first (mobile parity). The
        disclosure version defaults to the server's CURRENT one (imported,
        not hardcoded, so a future bump keeps the emulator honest); tests
        that exercise the stale-disclosure path pass an explicit override."""
        from app.api.consents import SHARING_DISCLOSURE_VERSION

        wrap = patient_wrap_for(self, therapist_pub_b64, therapist_id)
        response = await client.post(
            "/api/consents",
            headers={**self.headers, "X-Account-Verifier": verifier or self.auth_key_b64},
            json={
                "code": code,
                **wrap,
                "disclosure": disclosure or SHARING_DISCLOSURE_VERSION,
            },
        )
        return {
            "status": response.status_code,
            "body": response.json() if response.content else None,
        }

    async def list_consents(self, client: AsyncClient) -> dict:
        response = await client.get("/api/consents", headers=self.headers)
        assert response.status_code == 200, response.text
        return response.json()

    async def revoke_consent(
        self, client: AsyncClient, consent_id: str, verifier: str | None = None
    ) -> int:
        response = await client.request(
            "DELETE",
            f"/api/consents/{consent_id}",
            headers={**self.headers, "X-Account-Verifier": verifier or self.auth_key_b64},
        )
        return response.status_code


def daterange(days: int, end: date) -> list[date]:
    """The last *days* calendar days ending at *end* (inclusive)."""
    from datetime import timedelta

    return [end - timedelta(days=offset) for offset in range(days - 1, -1, -1)]


# ---------------------------------------------------------------------------
# Therapist sharing (2026-09-16, additive): a faithful mirror of the portal's
# crypto stack — same key schedule (portal wrap/notes HKDF labels), a real
# P-256 keypair, the same wrap construction as security.sharing — so the
# sharing API tests exercise the exact bytes a real browser would send.
# ---------------------------------------------------------------------------

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from app.security import sharing as sharing_crypto  # noqa: E402
from app.security.kdf import hkdf_sha256  # noqa: E402


class TherapistEmulator:
    def __init__(self, username: str, password: str, display_name: str | None = None):
        self.username = username
        self.password = password
        self.display_name = display_name or f"Dr. {username.title()}"
        self.salt = os.urandom(16)
        self.master_key = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self.salt, FAST_ITERATIONS
        )
        self.auth_key = kdf.derive_auth_key(self.master_key)
        # The portal's two HKDF subkeys (contract lives in security.sharing).
        self.wrap_kek = hkdf_sha256(self.master_key, None, sharing_crypto.PORTAL_WRAP_INFO)
        self.notes_key = hkdf_sha256(self.master_key, None, sharing_crypto.PORTAL_NOTES_INFO)
        # A real P-256 keypair, generated once per emulator instance.
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.wrap_pub_key = base64.b64encode(
            self.private_key.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            )
        ).decode("ascii")
        self.user_id: str | None = None
        self.token: str | None = None

    # ---- key material encodings ---------------------------------------------

    @property
    def salt_b64(self) -> str:
        return base64.b64encode(self.salt).decode("ascii")

    @property
    def auth_key_b64(self) -> str:
        return base64.b64encode(self.auth_key).decode("ascii")

    def _pkcs8(self) -> bytes:
        return self.private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())

    def wrap_key_blob_b64(self) -> str:
        """The private key, encrypted under the portal wrap KEK — exactly
        what a real portal uploads at registration."""
        blob = crypto.encrypt(
            self.wrap_kek,
            self._pkcs8(),
            crypto.build_aad(sharing_crypto.THERAPIST_KEY_CONTEXT, self.username),
        )
        return base64.b64encode(blob).decode("ascii")

    def unlock_private_key(self) -> ec.EllipticCurvePrivateKey:
        """Mirror of the portal's post-login unlock: derive the KEK from the
        password, decrypt the stored blob."""
        blob = base64.b64decode(getattr(self, "stored_key_blob_b64", self.wrap_key_blob_b64()))
        plain = crypto.decrypt(
            self.wrap_kek,
            blob,
            crypto.build_aad(sharing_crypto.THERAPIST_KEY_CONTEXT, self.username),
        )
        return sharing_crypto.load_private_key_pkcs8(plain)

    def unwrap_patient_data_key(
        self, patient: "ClientEmulator", ephemeral_pub_b64: str, wrapped_key_b64: str
    ) -> bytes:
        """The portal-side unwrap of a patient's data key."""
        assert patient.user_id and self.user_id
        return sharing_crypto.unwrap_data_key(
            self.unlock_private_key(),
            ephemeral_pub_b64,
            base64.b64decode(wrapped_key_b64),
            patient.user_id,
            self.user_id,
            therapist_pub_der=base64.b64decode(self.wrap_pub_key),
        )

    def encrypt_note(self, patient: "ClientEmulator", client_note_id: str, text: str) -> str:
        payload = {"v": 1, "text": text}
        aad = crypto.build_aad(
            sharing_crypto.NOTE_CONTEXT, self.user_id or "", patient.user_id or "", client_note_id
        )
        blob = crypto.encrypt(self.notes_key, json.dumps(payload).encode("utf-8"), aad)
        return base64.b64encode(blob).decode("ascii")

    def decrypt_note(self, patient: "ClientEmulator", client_note_id: str, blob_b64: str) -> dict:
        aad = crypto.build_aad(
            sharing_crypto.NOTE_CONTEXT, self.user_id or "", patient.user_id or "", client_note_id
        )
        plain = crypto.decrypt(self.notes_key, base64.b64decode(blob_b64), aad)
        return json.loads(plain.decode("utf-8"))

    # ---- API flows ------------------------------------------------------------

    @property
    def headers(self) -> dict:
        if not self.token:
            raise RuntimeError("not logged in")
        return {"Authorization": f"Bearer {self.token}"}

    async def register(self, client: AsyncClient) -> dict:
        response = await client.post(
            "/api/therapist/register",
            json={
                "username": self.username,
                "salt": self.salt_b64,
                "verifier": self.auth_key_b64,
                "display_name": self.display_name,
                "wrap_pub_key": self.wrap_pub_key,
                "wrap_key_blob": self.wrap_key_blob_b64(),
            },
        )
        assert response.status_code == 201, response.text
        body = response.json()
        self.user_id = body["user_id"]
        self.token = body["token"]
        return body

    async def login(self, client: AsyncClient) -> dict:
        response = await client.post(
            "/api/auth/login",
            json={
                "username": self.username,
                "verifier": self.auth_key_b64,
            },
        )
        assert response.status_code == 200, response.text
        body = response.json()
        self.user_id = body["user_id"]
        self.token = body["token"]
        # The portal persists the server-held blob at login (it arrives via
        # GET /therapist/me); remember it so unlock uses the stored bytes.
        me = await client.get("/api/therapist/me", headers=self.headers)
        assert me.status_code == 200, me.text
        self.stored_key_blob_b64 = me.json()["wrap_key_blob"]
        return body

    async def create_pairing_code(self, client: AsyncClient) -> str:
        response = await client.post("/api/therapist/pairing-codes", headers=self.headers)
        assert response.status_code == 201, response.text
        return response.json()["code"]


def patient_wrap_for(patient: ClientEmulator, therapist_pub_b64: str, therapist_id: str) -> dict:
    """The patient-side grant body fields, mirroring the mobile app's wrap."""
    assert patient.user_id
    eph_b64, wrapped_b64 = sharing_crypto.wrap_data_key(
        patient.data_key, therapist_pub_b64, patient.user_id, therapist_id
    )
    return {"ephemeral_pub": eph_b64, "wrapped_key": wrapped_b64}


# ---------------------------------------------------------------------------
# Added 2026-09-07 (additive only): the preferred verifier transport for
# DELETE /account is the X-Account-Verifier header; the JSON body remains as
# a deprecated fallback and keeps its coverage through delete_account() above.
# ---------------------------------------------------------------------------


async def delete_account_via_header(client: AsyncClient, emu: ClientEmulator) -> int:
    """DELETE /account with the verifier in X-Account-Verifier (preferred)."""
    response = await client.request(
        "DELETE",
        "/api/account",
        headers={**emu.headers, "X-Account-Verifier": emu.auth_key_b64},
    )
    return response.status_code
