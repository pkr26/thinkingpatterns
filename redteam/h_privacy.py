"""H-series: privacy audits against a synthetic operator view.

H1 metadata inference — what the SERVER (and any backup) can learn from
   plaintext metadata alone, with a concrete inference report.
H2 export bundle — cleartext fields, enumeration resistance.
H3 erasure completeness — live DB after account deletion.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import uuid
from datetime import datetime, timedelta, timezone

from common import (
    auth_headers,
    derive_keys,
    direct_insert_entry,
    guard,
    make_app,
    make_client,
    make_settings,
    register_user,
    run,
    section,
    verdict,
)
from export_evidence import inspect_export
from sqlalchemy import select


async def h1_metadata_inference() -> None:
    section("H1: metadata inference from the operator's view")
    app = await make_app(make_settings(entries_rate_limit=1000))
    async with make_client(app) as client:
        # A realistic private pattern: journals only on Sunday nights, skipped
        # two weeks in August (a bereavement, say), long entries when low.
        u = await register_user(client, "h1_subject", "pw-h1", iterations=1000)
        today = datetime.now(timezone.utc).date()
        for i in range(120, 0, -1):
            d = today - timedelta(days=i)
            august_gap = d.month == 8 and 4 <= d.day <= 18
            if august_gap:
                continue
            if d.weekday() != 6:  # Sundays only
                continue
            length = 4000 if i % 3 == 0 else 400
            await direct_insert_entry(app, u["user_id"], u["data_key"], "x" * length, d)

        # Operator view: no decryption, just the DB
        from app.models import Entry

        rows = []
        async with app.state.sessionmaker() as s:
            result = await s.execute(
                select(Entry.entry_date, Entry.blob).where(Entry.user_id == u["user_id"])
            )
            rows = result.all()

    dates = sorted(d for d, _ in rows)
    sizes = [len(b) for _, b in rows]
    weekdays = sorted({d.strftime("%A") for d in dates})
    gaps = [(dates[i + 1] - dates[i]).days for i in range(len(dates) - 1)]
    max_gap = max(gaps, default=0)
    gap_start = next(
        (dates[i + 1] - timedelta(days=g) for i, g in enumerate(gaps) if g == max_gap),
        None,
    )
    long_share = sum(1 for x in sizes if x > 2000) / max(1, len(sizes))
    inference = (
        f"subject journals on {weekdays} exclusively "
        f"({len(dates)} entries over 120 days); a {max_gap}-day silence ending "
        f"{gap_start}; {long_share:.0%} of entries are 10x longer than the rest "
        f"(crisis-length writes vs routine updates) — an operator can infer "
        f"religious observance or work schedules, episode timing, and possibly "
        f"severity from SIZE alone, with zero decryption"
    )
    verdict(
        "H1.metadata-inference",
        "FINDING",
        f"operator-view inference from entry_date+length only: {inference}",
    )


async def h2_export() -> None:
    section("H2: export bundle contents")
    settings = make_settings(
        audio_enabled=True,
        stt_url="https://stt.redteam.example/v1",
        stt_api_key="redteam-fixture-key",
    )
    settings.audio_local_dir = tempfile.mkdtemp(prefix="redteam-export-audio-")
    app = await make_app(settings)
    async with make_client(app) as client:
        from app.security import crypto, envelope, kdf

        issues = []
        recovered = []
        for scheme in ("v1", "v2"):
            password = f"h2-password-secret-{uuid.uuid4().hex}"
            journal = f"h2-journal-secret-{uuid.uuid4().hex}"
            username = f"H2_{scheme}_Binding"
            # Account names are case-sensitive; canonical means the exact
            # registered immutable name, never a client-side case fold.
            canonical = username
            wrapped = None
            params = None
            if scheme == "v1":
                u = await register_user(client, username, password)
            else:
                salt = os.urandom(16)
                auth_key, _ = derive_keys(password, salt)
                data_key = os.urandom(32)
                params = kdf.validate_kdf_params(kdf.KDF_PARAMS_DEFAULT)
                master = hashlib.pbkdf2_hmac(
                    "sha256", password.encode(), salt, int(params["iterations"])
                )
                wrapped = base64.b64encode(
                    envelope.wrap_data_key(
                        data_key,
                        kek=envelope.envelope_kek(master, salt),
                        username=canonical,
                        kdf_params=params,
                        nonce=os.urandom(12),
                    )
                ).decode()
                registration = await client.post(
                    "/api/v1/auth/register",
                    json={
                        "username": username,
                        "salt": base64.b64encode(salt).decode(),
                        "verifier": base64.b64encode(auth_key).decode(),
                        "age_attestation": "minimum_age_confirmed_v1",
                        "wrapped_data_key": wrapped,
                        "kdf_params": params,
                    },
                )
                registration.raise_for_status()
                u = {
                    "username": canonical,
                    "salt": salt,
                    "auth_key": auth_key,
                    "data_key": data_key,
                    **registration.json(),
                }
            entry_id = f"e-h2-{scheme}"
            await direct_insert_entry(
                app,
                u["user_id"],
                u["data_key"],
                journal,
                datetime.now(timezone.utc).date(),
                entry_id,
            )
            voice = b"RIFF-redteam-export-voice-" + uuid.uuid4().hex.encode()
            voice_consent = await client.put(
                "/api/v1/account/voice-consent",
                headers=auth_headers(u["token"]),
                json={
                    "enabled": True,
                    "verifier": base64.b64encode(u["auth_key"]).decode(),
                },
            )
            voice_consent.raise_for_status()
            audio_blob = crypto.encrypt(
                u["data_key"],
                voice,
                crypto.build_aad("audio", u["user_id"], entry_id, "1"),
            )
            upload = await client.post(
                "/api/v1/audio/attachments",
                headers=auth_headers(u["token"]),
                json={
                    "client_entry_id": entry_id,
                    "blob": base64.b64encode(audio_blob).decode(),
                    "mime": "audio/m4a",
                    "duration_seconds": 1,
                },
            )
            upload.raise_for_status()
            response = await client.get("/api/v1/account/export", headers=auth_headers(u["token"]))
            response.raise_for_status()
            bundle = response.json()
            expected = {
                "version": 3,
                "username": canonical,
                "user_id": u["user_id"],
                "salt": base64.b64encode(u["salt"]).decode(),
                "key_scheme": scheme,
                "wrapped_data_key": wrapped,
                "kdf_params": params,
                "recovery_enabled": False,
                "recovery_scheme": None,
                "recovery_set_at": None,
                "voice_consent": True,
            }
            case_issues = inspect_export(
                bundle,
                expected,
                {
                    "journal": journal,
                    "password": password,
                    "data key": bytes(u["data_key"]),
                    "authentication verifier": bytes(u["auth_key"]),
                    "voice recording": voice,
                },
            )
            if not case_issues:
                try:
                    salt = base64.b64decode(bundle["salt"], validate=True)
                    if len(salt) != 16:
                        raise ValueError("invalid client salt")
                    if scheme == "v1":
                        _, recovery_key = derive_keys(password, salt)
                    else:
                        recovery_params = kdf.validate_kdf_params(bundle["kdf_params"])
                        master = hashlib.pbkdf2_hmac(
                            "sha256",
                            password.encode(),
                            salt,
                            int(recovery_params["iterations"]),
                        )
                        recovery_key = envelope.unwrap_data_key(
                            base64.b64decode(bundle["wrapped_data_key"], validate=True),
                            kek=envelope.envelope_kek(master, salt),
                            username=bundle["username"],
                            kdf_params=recovery_params,
                        )
                    row = next(
                        row for row in bundle["entries"] if row["client_entry_id"] == entry_id
                    )
                    plaintext = crypto.decrypt(
                        recovery_key,
                        base64.b64decode(row["blob"], validate=True),
                        crypto.entry_aad_v1(bundle["user_id"], entry_id),
                    )
                    if json.loads(plaintext)["text"] != journal:
                        raise ValueError("exported ciphertext lost the expected journal")
                    audio = next(
                        row
                        for row in bundle["audio"]
                        if row["id"] == upload.json()["attachment_id"]
                    )
                    if (
                        audio["client_entry_id"] != entry_id
                        or audio["content_version"] != 1
                        or audio["mime_type"] != "audio/m4a"
                        or audio["size_bytes"] != len(audio_blob)
                    ):
                        raise ValueError("exported audio metadata changed its binding")
                    restored_voice = crypto.decrypt(
                        recovery_key,
                        base64.b64decode(audio["blob"], validate=True),
                        crypto.build_aad(
                            "audio",
                            bundle["user_id"],
                            entry_id,
                            str(audio["content_version"]),
                        ),
                    )
                    if restored_voice != voice:
                        raise ValueError("exported recording lost its expected plaintext")
                    recovered.append(scheme)
                except (
                    ValueError,
                    KeyError,
                    StopIteration,
                    crypto.TamperError,
                ) as error:
                    case_issues.append(f"offline recovery failed: {type(error).__name__}")
            issues.extend(f"{scheme}: {issue}" for issue in case_issues)
        verdict(
            "H2.export-cleartext-fields",
            "BLOCKED" if not issues else "FINDING",
            "canonical username/UUID, version3 and salt are intentional public offline-recovery metadata; "
            f"password-only journal+recording recovery authenticated schemes={recovered}; plaintext journal/voice/password/data-key/verifier leakage or broken recovery={issues or 'NONE'}",
        )
        # Cross-account enumeration: export is token-scoped
        r2 = await client.get("/api/v1/account/export")
        verdict(
            "H2.export-auth-scoped",
            "BLOCKED" if r2.status_code == 401 else "FINDING",
            f"unauthenticated export: {r2.status_code}",
        )


async def h3_erasure() -> None:
    section("H3: erasure completeness")
    app = await make_app(make_settings())
    async with make_client(app) as client:
        u = await register_user(client, "h3_gone", "pw-h3", iterations=1000)
        await direct_insert_entry(
            app,
            u["user_id"],
            u["data_key"],
            "text",
            datetime.now(timezone.utc).date(),
            "e-h3-1",
        )
        r = await client.post(
            "/api/v1/processing/sessions",
            headers=auth_headers(u["token"]),
            json={"data_key": base64.b64encode(bytes(u["data_key"])).decode()},
        )
        r = await client.delete(
            "/api/v1/account",
            headers={
                **auth_headers(u["token"]),
                "X-Account-Verifier": base64.b64encode(u["auth_key"]).decode(),
            },
        )
        assert r.status_code == 204, r.text

        from app.models import Entry, Insight, User

        async with app.state.sessionmaker() as s:
            users = (
                (await s.execute(select(User).where(User.username == "h3_gone"))).scalars().all()
            )
            entries = (
                (await s.execute(select(Entry).where(Entry.user_id == u["user_id"])))
                .scalars()
                .all()
            )
            insights = (
                (await s.execute(select(Insight).where(Insight.user_id == u["user_id"])))
                .scalars()
                .all()
            )
        # Hard attribute access on purpose (2026-09-28 audit): a getattr
        # default of {} would silently report "0 keys held" forever after a
        # keystore rename — the crash into an ERROR verdict is the honest
        # failure mode for a drifted probe.
        keys_held = len(app.state.key_store._keys)
        # keys_held gates the verdict too (2026-09-19 audit, M-34): a
        # keystore still holding the deleted user's data key after 204 is
        # a FINDING even when every DB row is gone — the old gate printed
        # the count but never let it affect the verdict.
        rows_remain = bool(users or entries or insights)
        verdict(
            "H3.erasure-live-db",
            "BLOCKED" if not (rows_remain or keys_held) else "FINDING",
            f"after DELETE /account: users={len(users)}, entries={len(entries)}, "
            f"insights={len(insights)} rows remain; in-memory keystore holds "
            f"{keys_held} keys — "
            + (
                "the measured live rows and processing keys were removed in this run"
                if not (rows_remain or keys_held)
                else "live rows or processing keys remain; the erasure control failed"
            )
            + " (backup retention is a separate scope: see G1)",
        )


async def main() -> None:
    await guard("H1", h1_metadata_inference)
    await guard("H2", h2_export)
    await guard("H3", h3_erasure)


if __name__ == "__main__":
    run(main, "h_privacy")
