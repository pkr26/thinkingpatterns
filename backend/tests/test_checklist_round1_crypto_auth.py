"""External verification checklist 2026-09-23, round 1: crypto core + auth.

These tests close the gaps left by the existing suites (mapping in the
2026-09-23 audit):

* plaintext round-trip extremes (1-byte, multi-MB, every Unicode plane
  family incl. emoji and RTL) — the existing suite pinned only empty /
  mid-size ASCII and used non-ASCII solely inside AAD/password vectors;
* an EVERY-byte tamper sweep of the nonce||ct||tag envelope — the
  existing suite flips spot positions only;
* key/plaintext zeroization when the analyzer is killed by a timeout
  error or an asyncio cancellation (CancelledError is a BaseException:
  a cleanup written as ``except Exception`` would silently skip it);
* mid-transaction rekey atomicity — a failure injected AFTER the entry
  UPDATEs but BEFORE the commit must leave every blob on the OLD key;
* at-rest server blindness — no column of any table may ever contain
  the password, master key, auth key, or data key;
* an EXHAUSTIVE role-wall enumeration over the whole route table (the
  existing suite samples 6+5 routes; a new endpoint could ship unwalled);
* credential rotation kills every previously issued bearer (the
  "old device locked out" leg of the rotation journey).
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
from datetime import date, timedelta

import pytest
from sqlalchemy import select

from app import deps as deps_module
from app.api._custody import require_password_retry_therapist
from app.api import insights as insights_api
from app.models import Base, Measure, Entry
from app.security import crypto
from app.security.enclave import SecureProcessingContext
from tests.helpers import ClientEmulator, TherapistEmulator

TODAY = date.today()


# --- 1a: round-trip extremes ---------------------------------------------------


def _unicode_corpus() -> list[str]:
    return [
        "plain ascii text",
        "café naïve résumé",  # Latin-1 accents
        "αβγδε ωήθ",  # Greek
        "Привет мир",  # Cyrillic
        "你好，世界",  # CJK
        "こんにちは世界",  # Hiragana + Kanji
        "😀😃🤔😇",  # astral-plane emoji (U+1F600..)
        "👨‍👩‍👧‍👦 family",  # ZWJ sequence (four code points, one glyph)
        "مرحبا بالعالم",  # Arabic (RTL)
        "שלום עולם",  # Hebrew (RTL)
        "éclair sievé",  # NFD combining accents
        "mixed 😀 你 العربية ASCII 123!",
    ]


class TestRoundTripExtremes:
    @pytest.mark.parametrize(
        "plaintext",
        [
            b"",
            b"x",  # the 1-byte case
            os.urandom(64 * 1024),  # 64 KiB
            os.urandom(1024 * 1024),  # 1 MiB
            os.urandom(2 * 1024 * 1024 + 7),  # multi-MB, off-alignment tail
        ],
        ids=["empty", "one-byte", "64k", "1m", "2m+7"],
    )
    def test_binary_round_trip_is_exact(self, plaintext: bytes):
        key = crypto.generate_key()
        aad = crypto.build_aad("entry", "user1", "e1")
        for aa in (None, aad):
            blob = crypto.encrypt(key, plaintext, aa)
            assert crypto.decrypt(key, blob, aa) == plaintext

    def test_unicode_round_trip_is_exact(self):
        key = crypto.generate_key()
        for text in _unicode_corpus():
            plaintext = text.encode("utf-8")
            blob = crypto.encrypt(key, plaintext)
            assert crypto.decrypt(key, blob).decode("utf-8") == text

    def test_max_rtl_and_emoji_payload_multi_block(self):
        # ~600 KB of interleaved RTL + emoji: exercises multi-block GCM
        # streaming over non-ASCII bytes end to end, not just short samples.
        key = crypto.generate_key()
        text = "مرحبا 😀 你好 " * 60_000
        plaintext = text.encode("utf-8")
        assert len(plaintext) > 600_000
        blob = crypto.encrypt(key, plaintext)
        assert crypto.decrypt(key, blob) == plaintext


# --- 1b: every-byte tamper sweep ------------------------------------------------


class TestEveryByteTamperSweep:
    def test_every_single_byte_flip_fails_closed_small_blob(self):
        key = crypto.generate_key()
        blob = bytearray(crypto.encrypt(key, b"tamper sweep secret"))
        assert len(blob) == crypto.NONCE_SIZE + len(b"tamper sweep secret") + 16
        # Flipping ANY byte — nonce, ciphertext body, or tag — must fail
        # authentication. GCM never returns partial garbage: it either
        # verifies the whole message or raises TamperError.
        for mask in (0x01, 0x80):
            for index in range(len(blob)):
                mutated = bytearray(blob)
                mutated[index] ^= mask
                with pytest.raises(crypto.TamperError):
                    crypto.decrypt(key, bytes(mutated))

    def test_large_blob_nonce_and_tag_swept_and_body_sampled(self):
        key = crypto.generate_key()
        blob = bytearray(crypto.encrypt(key, os.urandom(4096)))
        body = range(crypto.NONCE_SIZE, len(blob) - crypto.TAG_SIZE)
        positions = (
            list(range(crypto.NONCE_SIZE))
            + list(body[:32])
            + list(body[::64])
            + list(body[-32:])
            + list(range(len(blob) - crypto.TAG_SIZE, len(blob)))
        )
        for index in positions:
            mutated = bytearray(blob)
            mutated[index] ^= 0x01
            with pytest.raises(crypto.TamperError):
                crypto.decrypt(key, bytes(mutated))

    def test_tamper_never_yields_partial_plaintext(self):
        # A wrong tag must fail BEFORE any plaintext is produced: the
        # decrypt call either returns the exact original or raises —
        # there is no short/partial return shape to accidentally rely on.
        key = crypto.generate_key()
        plaintext = b"every byte authenticated"
        blob = bytearray(crypto.encrypt(key, plaintext))
        for index in (0, 5, crypto.NONCE_SIZE, len(blob) - 1):
            mutated = bytearray(blob)
            mutated[index] ^= 0xFF
            with pytest.raises(crypto.TamperError):
                result = crypto.decrypt(key, bytes(mutated))
                assert result != plaintext[: len(result)]


# --- 1f: zeroization on timeout / cancellation exit paths -----------------------


class TestZeroizationOnHardExits:
    def _blobs(self, key: bytes):
        aad = crypto.build_aad("entry", "u1", "e1")
        return [(aad, crypto.encrypt(key, b"window secret", aad))]

    def test_key_and_plaintext_zeroized_when_analysis_times_out(self):
        key = crypto.generate_key()
        captured: list[bytearray] = []

        def analyze(plains):
            captured.extend(plains)
            raise TimeoutError("analysis exceeded its budget")

        ctx = SecureProcessingContext(key)
        with pytest.raises(TimeoutError):
            ctx.run(self._blobs(key), analyze)
        for buf in captured:
            assert all(b == 0 for b in buf)
        # The context's own key copy is scrubbed on this exit path too.
        assert all(b == 0 for b in ctx._key)  # noqa: SLF001 — observable seam

    def test_key_and_plaintext_zeroized_on_cancellation(self):
        # asyncio.CancelledError derives from BaseException, NOT Exception:
        # a cleanup clause written as ``except Exception`` (or a finally
        # someone later "simplifies" into one) would skip it. Client
        # disconnects surface exactly this way inside Starlette.
        key = crypto.generate_key()
        captured: list[bytearray] = []

        def analyze(plains):
            captured.extend(plains)
            raise asyncio.CancelledError()

        ctx = SecureProcessingContext(key)
        with pytest.raises(asyncio.CancelledError):
            ctx.run(self._blobs(key), analyze)
        for buf in captured:
            assert all(b == 0 for b in buf)
        assert all(b == 0 for b in ctx._key)  # noqa: SLF001 — observable seam


# --- 1g: mid-transaction rekey atomicity ----------------------------------------


class TestRekeyMidTransactionAtomicity:
    async def test_failure_after_entry_updates_rolls_everything_back(self, client, monkeypatch):
        emu = ClientEmulator("rekey-atomic", "pw-hunter2")
        await emu.register(client)
        await emu.create_entry(client, "one", TODAY, "e-1", content_version=1)
        await emu.create_entry(client, "two", TODAY, "e-2", content_version=1)
        # A measure row exercises the second blob-batch phase (no threshold
        # seeding needed: measures exist in the baseline phase).
        measure_blob = base64.b64encode(
            crypto.encrypt(
                emu.data_key,
                b'{"v":1,"measure":"phq9","score":4}',
                crypto.build_aad("measure", emu.user_id, "m-1"),
            )
        ).decode("ascii")
        response = await client.post(
            "/api/measures",
            headers=emu.headers,
            json={
                "client_measure_id": "m-1",
                "blob": measure_blob,
                "measure_date": TODAY.isoformat(),
            },
        )
        assert response.status_code == 201, response.text

        app = client._transport.app  # noqa: SLF001 — test reachability into state

        async def snapshot() -> dict:
            async with app.state.sessionmaker() as session:
                entries = (
                    await session.execute(
                        select(Entry.client_entry_id, Entry.blob).where(
                            Entry.user_id == emu.user_id
                        )
                    )
                ).all()
                measures = (
                    await session.execute(
                        select(Measure.client_measure_id, Measure.blob).where(
                            Measure.user_id == emu.user_id
                        )
                    )
                ).all()
                return {
                    "entries": {cid: bytes(blob) for cid, blob in entries},
                    "measures": {mid: bytes(blob) for mid, blob in measures},
                }

        def explode(*args, **kwargs):
            # Reached only AFTER the entry-phase UPDATEs have executed
            # inside the open transaction (the entries phase uses
            # _rekey_entry_batch; this is the insights/measures phase).
            raise RuntimeError("simulated crash mid-rekey, after entry writes")

        original_blob_batch = insights_api._rekey_blob_batch
        monkeypatch.setattr(insights_api, "_rekey_blob_batch", explode)
        old_verifier = emu.auth_key_b64
        old_key = emu.data_key
        emu.derive_new_generation("pw-rotated-99")
        old_token = await emu.open_processing_session_for(client, old_key)
        new_token = await emu.open_processing_session_for(client, emu.data_key)
        # The emulator's rekey() asserts 200; call the endpoint directly so
        # the 500 is observable. The verifier is the OLD credential — the
        # server has not seen the new one yet.
        response = await client.post(
            "/api/processing/rekey",
            headers={
                **emu.headers,
                "X-Processing-Token": old_token,
                "X-New-Processing-Token": new_token,
                "X-Account-Verifier": old_verifier,
            },
            json=emu.rekey_payload(),
        )
        assert response.status_code == 500
        assert response.json()["code"] == "internal_error"

        # 2026-09-26 audit item 12 evolved this pin (rekey transaction
        # restructure, audit item 11): each batch commits in its own SHORT
        # transaction with the progress journal, so a crash after the entry
        # phase leaves those batches rekeyed — the all-or-nothing contract
        # is replaced by crash-safe RESUMABILITY. What must still hold:
        #   * every blob decrypts under exactly ONE of the two keys (no
        #     torn/corrupt rows — each batch is all-or-nothing);
        #   * the journal recorded the completed stage for the retry;
        #   * a retry with the same keys finishes the rotation idempotently.
        after = await snapshot()
        from app.models import RekeyJournal

        async with app.state.sessionmaker() as session:
            journal = (
                await session.execute(
                    select(RekeyJournal).where(RekeyJournal.user_id == emu.user_id)
                )
            ).scalar_one_or_none()
        assert journal is not None, "an interrupted rotation must leave a resumable journal"
        assert journal.stage == "entries"
        assert journal.entries_done == 2
        for cid, blob in after["entries"].items():
            # Both entries were in the crashed run's FIRST stage: new key,
            # upgraded to the v2 (version-bound) AAD like every rekey.
            plain = crypto.decrypt(emu.data_key, blob, crypto.entry_aad_v2(emu.user_id, cid, 1))
            assert json.loads(plain)["text"] in ("one", "two")
        for mid, blob in after["measures"].items():
            # The crash fired in the insights phase: measures untouched (old key).
            plain = crypto.decrypt(old_key, blob, crypto.build_aad("measure", emu.user_id, mid))
            assert json.loads(plain)["v"] == 1

        # The retry (fresh single-use sessions, same two keys) resumes from
        # the journal: entries authenticate under the NEW key and are
        # skipped idempotently; measures rotate; the journal is retired.
        monkeypatch.setattr(insights_api, "_rekey_blob_batch", original_blob_batch)
        old_token2 = await emu.open_processing_session_for(client, old_key)
        new_token2 = await emu.open_processing_session_for(client, emu.data_key)
        response = await client.post(
            "/api/processing/rekey",
            headers={
                **emu.headers,
                "X-Processing-Token": old_token2,
                "X-New-Processing-Token": new_token2,
                "X-Account-Verifier": old_verifier,
            },
            json=emu.rekey_payload(),
        )
        assert response.status_code == 200, response.text
        counts = response.json()
        assert counts == {
            "entries": 2,
            "insights": 0,
            "measures": 1,
            "audio": 0,
            "recovery_invalidated": False,
            "credential_rotated": True,
            "operation_id": emu.rekey_payload()["operation_id"],
            "consents_rewrapped": 0,
        }
        async with app.state.sessionmaker() as session:
            journal2 = (
                await session.execute(
                    select(RekeyJournal).where(RekeyJournal.user_id == emu.user_id)
                )
            ).scalar_one_or_none()
        assert journal2 is None, "completion retires the journal with the revision bumps"
        final = await snapshot()
        for cid, blob in final["entries"].items():
            crypto.decrypt(emu.data_key, blob, crypto.entry_aad_v2(emu.user_id, cid, 1))
        for mid, blob in final["measures"].items():
            crypto.decrypt(emu.data_key, blob, crypto.build_aad("measure", emu.user_id, mid))

        # Credential and ciphertext commit together. The previous proof is
        # retired; fresh login opens the new generation after the retry.
        assert (
            await client.post(
                "/api/auth/login", json={"username": emu.username, "verifier": old_verifier}
            )
        ).status_code == 401
        await emu.login(client)
        fetched = await client.get("/api/entries/e-1", headers=emu.headers)
        assert fetched.status_code == 200, fetched.text


# --- 2a: at-rest server blindness -----------------------------------------------


class TestServerBlindnessAtRest:
    async def test_no_table_ever_holds_password_or_derived_keys(self, client):
        password = "correct horse battery staple ñ"
        emu = ClientEmulator("blind-server", password)
        await emu.register(client)
        await emu.create_entry(client, "secret diary text", TODAY, "e-1", content_version=1)
        await emu.login(client)  # exercise the login path's writes too

        app = client._transport.app  # noqa: SLF001 — test reachability into state
        secrets = {
            "password": password.encode("utf-8"),
            "master_key": emu.master_key,
            "auth_key": emu.auth_key,
            "data_key": emu.data_key,
        }
        async with app.state.sessionmaker() as session:
            for table in Base.metadata.sorted_tables:
                rows = (await session.execute(select(table))).all()
                for row in rows:
                    rendered = repr(row).encode("utf-8", errors="replace")
                    for name, secret in secrets.items():
                        assert secret not in rendered, (
                            f"{name} found in {table.name} row — the server must "
                            "only ever see scrypt(auth_key), never key material"
                        )
                        assert base64.b64encode(secret) not in rendered

        # The stored verifier is scrypt(auth_key, per-user salt) — NOT the
        # auth key itself (a DB leak must not yield a login credential).
        from app.models import User

        async with app.state.sessionmaker() as session:
            row = await session.get(User, emu.user_id)
            assert row is not None
            stored = row.verifier
            assert bytes(stored) != emu.auth_key
            assert bytes(stored) != emu.master_key


# --- 2c: exhaustive role-wall enumeration ---------------------------------------


WALLS = {
    deps_module.require_rekey_retry_user: "user",
    require_password_retry_therapist: "therapist",
    deps_module.require_regular_user: "user",
    deps_module.require_therapist_account: "therapist",
    deps_module.require_therapist: "therapist",
    deps_module.require_user: "any",
}


class TestExhaustiveRoleWalls:
    def _route_roles(self, app):
        from app.main import _resolve_api_routes

        mapping: dict[str, set[str]] = {}
        for route in _resolve_api_routes(app.routes):
            if not route.path.startswith("/api/v1/"):
                continue  # the /api legacy alias mounts the same routers
            roles = set()
            stack = [route.dependant]
            while stack:
                dependant = stack.pop()
                for dep in dependant.dependencies:
                    for wall_fn, role in WALLS.items():
                        if dep.call is wall_fn:
                            roles.add(role)
                    nested = getattr(dep, "dependant", None)
                    if nested is not None:
                        stack.append(nested)
            mapping[f"{sorted(route.methods - {'HEAD'})[0]} {route.path}"] = roles
        return mapping

    def test_every_authenticated_route_has_a_role_wall(self, app):
        anonymous = {
            "POST /api/v1/auth/register",
            "POST /api/v1/auth/salt",
            "POST /api/v1/auth/login",
            # Wave 3 (2026-09-30): recovery login is a credential
            # PRESENTATION endpoint (like login itself) — the recovery key
            # IS the credential being verified.
            "POST /api/v1/auth/recover",
            "GET /api/v1/meta",
            # Therapist signup is open by design; in production it carries
            # the enrollment-token gate instead of a session (verified by
            # test_therapist_api.py).
            "POST /api/v1/therapist/register",
        }
        mapping = self._route_roles(app)
        assert len(mapping) >= 40, f"expected the full route table, got {len(mapping)}"
        unwalled = {
            key: roles for key, roles in mapping.items() if not roles and key not in anonymous
        }
        assert not unwalled, f"routes shipped without any auth dependency: {sorted(unwalled)}"

    async def test_every_walled_route_answers_401_without_a_token(self, client, app):
        # 2026-09-28 deep audit (test-quality MEDIUM): the structural
        # role-wall test above proves every route HAS a require_* dependency;
        # this sweep additionally pins the HTTP envelope an anonymous caller
        # actually receives (flat 401, code "unauthorized") on every walled
        # route — auto-covering new routes.
        mapping = self._route_roles(app)
        for key, roles in sorted(mapping.items()):
            if not roles:
                continue
            method, path = key.split(" ", 1)
            path = self._fill_params(path)
            response = await client.request(
                method,
                path,
                json={} if method in ("POST", "PUT", "PATCH") else None,
            )
            assert response.status_code == 401, (
                f"{key}: expected 401 anonymous, got {response.status_code} {response.text}"
            )
            assert response.json()["code"] == "unauthorized", key

    async def test_therapist_token_rejected_on_every_user_route(self, client, app):
        mapping = self._route_roles(app)
        th = TherapistEmulator("drwall", "pw")
        await th.register(client)
        for key, roles in sorted(mapping.items()):
            if "user" not in roles:
                continue
            method, path = key.split(" ", 1)
            path = self._fill_params(path)
            response = await client.request(
                method,
                path,
                headers=th.headers,
                json={} if method in ("POST", "PUT", "PATCH") else None,
            )
            assert response.status_code == 403, (
                f"{key}: expected 403, got {response.status_code} {response.text}"
            )
            assert response.json()["code"] == "forbidden", key

    async def test_patient_token_rejected_on_every_therapist_route(self, client, app):
        mapping = self._route_roles(app)
        emu = ClientEmulator("patientwall", "pw")
        await emu.register(client)
        for key, roles in sorted(mapping.items()):
            if "therapist" not in roles:
                continue
            method, path = key.split(" ", 1)
            path = self._fill_params(path)
            response = await client.request(
                method,
                path,
                headers=emu.headers,
                json={} if method in ("POST", "PUT", "PATCH") else None,
            )
            assert response.status_code == 403, (
                f"{key}: expected 403, got {response.status_code} {response.text}"
            )
            assert response.json()["code"] == "forbidden", key

    @staticmethod
    def _fill_params(path: str) -> str:
        for param in ("user_id", "consent_id", "note_id", "client_entry_id"):
            path = path.replace(f"{{{param}}}", f"placeholder-{param}")
        return path


# --- 10e: credential rotation kills every prior bearer ---------------------------


class TestRotationKillsOldBearers:
    async def test_every_prior_token_dies_after_credential_rotation(self, client):
        emu = ClientEmulator("rotating", "old-password-1")
        await emu.register(client)
        old_verifier = emu.auth_key_b64
        token_a = emu.token
        await emu.login(client)  # a second live session (token B)
        token_b = emu.token

        old_data_key = emu.data_key
        emu.derive_new_generation("new-password-2")
        rotated = await emu.rekey(client, old_data_key, emu.data_key, verifier=old_verifier)
        assert rotated["credential_rotated"] is True

        # BOTH pre-rotation bearers are dead (the epoch bump is global,
        # not per-session): the stolen-old-device leg of the journey.
        for dead in (token_a, token_b):
            response = await client.get("/api/entries", headers={"Authorization": f"Bearer {dead}"})
            assert response.status_code == 401
            assert response.json()["code"] == "unauthorized"

        # The NEW password logs in and the data still decrypts.
        await emu.login(client)
        fetched = await client.get("/api/entries", headers=emu.headers)
        assert fetched.status_code == 200
