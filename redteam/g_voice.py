"""Voice-journaling red-team campaign (VOICE_PLAN.md P6; EXECUTABLE since the
2026-09-29 remediation — the audit found this file was a docstring that had
never been wired into run_all.sh, so the P6 "triaged to zero highs" gate was
satisfied by a no-op).

Same posture as every other campaign in this repo: attacks the developers'
OWN code, in-process (httpx ASGI transport against a scratch SQLite app),
with the STT upstream patched at the client seam — never a third-party
endpoint. The docstring threat inventory this used to be is preserved as the
V-numbering; the deployment gates it listed now live in docs/OPERATOR_PACK
terms (unchanged).

  V-1  Flag-off discovery ................ every /audio route flat-404s; the
        therapist audio route and the share-voice toggle too (M1 fix); an
        anonymous probe keeps the standard 401 (the role wall runs first).
  V-2  Consent gate ...................... no consent / stale fingerprint
        both fail closed with 403 voice_consent_required.
  V-4  Route-scoped caps ................. oversized DECODED audio → 413
        audio_too_large; duration over the bound → 422.
  V-5  Rate/cost abuse ................... transcription bucket 429s past
        its limit (run with limit 3).
  V-7  IDOR on attachments ............... cross-user fetch/delete answers
        a flat 404; the owner still reads.
  V-8  Therapist voice gate .............. no share_voice → 403 with NO
        audit row; granted → served with exactly one audio_access row.
  V-9  Retention ........................ lazy expiry kills row AND object
        on the fetch path (a missed sweep cycle cannot extend retention).
  V-11 Translation consent scope (H4) .... a CONFIGURED LLM endpoint
        receives nothing (null translation) without the CURRENT llm
        consent; with it, translation flows.
  V-12 Upstream retry (M8) .............. exactly one retry on a transient
        429, none on a 400 — driven against the real SpeechToText client.
"""

from __future__ import annotations

import asyncio
import base64
import os
import tempfile
from datetime import datetime, timedelta, timezone

from common import (
    derive_keys,
    encrypt_entry,
    make_app,
    make_client,
    make_settings,
    run,
    section,
    verdict,
)

TODAY = datetime.now(timezone.utc).date()
FAKE_AUDIO = b"RIFF-redteam-voice-take" * 64


def _audio_body(
    audio: bytes = FAKE_AUDIO, duration: int = 60, mime: str = "audio/webm"
):
    return {
        "audio_b64": base64.b64encode(audio).decode("ascii"),
        "mime": mime,
        "duration_seconds": duration,
    }


async def _register(client, username, password="correct horse battery staple"):
    salt = os.urandom(16)
    auth_key, data_key = derive_keys(password, salt, 600_000)
    r = await client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "salt": base64.b64encode(salt).decode(),
            "verifier": base64.b64encode(auth_key).decode(),
            "age_attestation": "minimum_age_confirmed_v1",
        },
    )
    r.raise_for_status()
    body = r.json()
    return {
        "headers": {"Authorization": f"Bearer {body['token']}"},
        "user_id": body["user_id"],
        "verifier": base64.b64encode(auth_key).decode(),
        "data_key": data_key,
    }


async def _consent_voice(client, user):
    r = await client.put(
        "/api/account/voice-consent",
        headers=user["headers"],
        json={"enabled": True, "verifier": user["verifier"]},
    )
    assert r.status_code == 200, r.text


async def _make_entry(client, user, entry_id):
    blob = encrypt_entry(
        user["data_key"], user["user_id"], entry_id, "voice day", TODAY.isoformat()
    )
    r = await client.post(
        "/api/v1/entries",
        headers=user["headers"],
        json={
            "client_entry_id": entry_id,
            "blob": blob,
            "entry_date": TODAY.isoformat(),
        },
    )
    assert r.status_code in (200, 201), r.text
    return entry_id


async def _upload(client, user, entry_id, audio=b"RIFF-take" + b"1" * 40, duration=30):
    r = await client.post(
        "/api/v1/audio/attachments",
        headers=user["headers"],
        json={
            "client_entry_id": entry_id,
            "blob": base64.b64encode(audio).decode("ascii"),
            "mime": "audio/webm",
            "duration_seconds": duration,
        },
    )
    assert r.status_code == 201, r.text
    return r.json()


async def main() -> None:
    settings = make_settings(
        audio_enabled=True,
        stt_url="https://stt.redteam.example/v1",
        stt_api_key="redteam-key",
        audio_transcribe_rate_limit=30,
        audio_transcribe_rate_window=3600,
        audio_bucket="",
    )
    settings.audio_local_dir = tempfile.mkdtemp(prefix="redteam-voice-") + "/audio"

    app = await make_app(settings)
    client = make_client(app)

    from app.services.stt import SpeechToText

    async def fake_post(self, files, data):
        return {"text": "Redteam transcript.", "language": "spanish"}

    original_post = SpeechToText._post_audio
    SpeechToText._post_audio = fake_post
    try:
        await _campaign(app, client, settings)
    finally:
        SpeechToText._post_audio = original_post
        await client.aclose()


async def _campaign(app, client, settings) -> None:
    from app.models import AccessLog, AudioAttachment, Consent, utcnow
    from app.models import User as UserModel
    from app.services import stt as stt_service
    from app.services.audio_store import get_audio_store
    from sqlalchemy import select

    # --- V-1: flag-off hides every voice surface ------------------------------------
    section("V-1: flag-off hides every voice surface (patient, therapist, toggle)")
    probe = await _register(client, "gvoice-flag-probe")
    settings.audio_enabled = False
    anon = await client.post("/api/v1/audio/transcriptions", json=_audio_body())
    patient_off = await client.post(
        "/api/v1/audio/transcriptions", headers=probe["headers"], json=_audio_body()
    )
    toggle_off = await client.put(
        "/api/consents/" + "f" * 32 + "/share-voice",
        headers={**probe["headers"], "X-Account-Verifier": probe["verifier"]},
        json={"enabled": True},
    )
    role_wall = await client.get(
        f"/api/therapist/patients/{probe['user_id']}/audio/{'f' * 32}",
        headers=probe["headers"],  # patient token: the role wall answers first
    )
    anon_toggle = await client.put(
        "/api/consents/" + "f" * 32 + "/share-voice", json={"enabled": True}
    )
    settings.audio_enabled = True
    ok = (
        anon.status_code == 401
        and anon_toggle.status_code == 401
        and patient_off.status_code == 404
        and patient_off.json()["code"] == "not_found"
        and toggle_off.status_code == 404
        and role_wall.status_code == 403
    )
    verdict(
        "G-VOICE.V-1-flag-off",
        "BLOCKED" if ok else "FINDING",
        f"anonymous={anon.status_code} anon-toggle={anon_toggle.status_code} "
        f"patient={patient_off.status_code} share-toggle={toggle_off.status_code} "
        f"role-wall={role_wall.status_code} "
        "(want 401/401/404/404/403 — auth and role run before the flag; the flag "
        "hides the feature; the M1 remediation covers the therapist route + toggle)",
    )

    # --- V-2: consent wall -------------------------------------------------------------
    section("V-2: consent wall (none / stale fingerprint)")
    no_consent = await _register(client, "gvoice-noconsent")
    denied = await client.post(
        "/api/v1/audio/transcriptions",
        headers=no_consent["headers"],
        json=_audio_body(),
    )
    consented = await _register(client, "gvoice-consented")
    await _consent_voice(client, consented)
    allowed = await client.post(
        "/api/v1/audio/transcriptions", headers=consented["headers"], json=_audio_body()
    )
    # Stale: the operator rotates the policy fingerprint under the recorded yes.
    old_version = settings.stt_policy_version
    settings.stt_policy_version = "v2-rotated"
    stale = await client.post(
        "/api/v1/audio/transcriptions", headers=consented["headers"], json=_audio_body()
    )
    settings.stt_policy_version = old_version
    ok = (
        denied.status_code == 403
        and denied.json()["code"] == "voice_consent_required"
        and allowed.status_code == 200
        and stale.status_code == 403
    )
    verdict(
        "G-VOICE.V-2-consent",
        "BLOCKED" if ok else "FINDING",
        f"no-consent={denied.status_code}/{denied.json().get('code')} "
        f"consented={allowed.status_code} stale-fingerprint={stale.status_code} "
        "(want 403/voice_consent_required, 200, 403)",
    )

    # --- V-4: decoded-size + duration caps ------------------------------------------------
    section("V-4: route-scoped caps refuse oversized decoded audio / duration")
    big = b"\x00" * (settings.audio_max_body_bytes + 1)
    oversized = await client.post(
        "/api/v1/audio/transcriptions",
        headers=consented["headers"],
        json=_audio_body(big),
    )
    over_duration = await client.post(
        "/api/v1/audio/transcriptions",
        headers=consented["headers"],
        json=_audio_body(duration=86_401),
    )
    edge_code = oversized.json().get("code")
    ok = (
        oversized.status_code == 413
        and edge_code in ("audio_too_large", "payload_too_large")
        and over_duration.status_code == 422
    )
    verdict(
        "G-VOICE.V-4-caps",
        "BLOCKED" if ok else "FINDING",
        f"over-cap={oversized.status_code}/{edge_code} "
        f"duration-over-bound={over_duration.status_code} "
        "(want 413 with a too-large code, 422 — the edge middleware fires first by "
        "construction: edge and decoded caps share one knob, the route's decoded "
        "check is the backstop if they are ever decoupled)",
    )

    # --- V-5: rate bucket -------------------------------------------------------------------
    section("V-5: transcription rate bucket (limit 3, dedicated fresh app)")
    rate_settings = make_settings(
        audio_enabled=True,
        stt_url="https://stt.redteam.example/v1",
        stt_api_key="redteam-key",
        audio_transcribe_rate_limit=3,
        audio_transcribe_rate_window=3600,
        audio_bucket="",
    )
    rate_settings.audio_local_dir = tempfile.mkdtemp(prefix="redteam-rate-") + "/audio"
    rate_app = await make_app(rate_settings)
    rate_client = make_client(rate_app)
    try:
        rate_user = await _register(rate_client, "gvoice-rate")
        await _consent_voice(rate_client, rate_user)
        codes = [
            (
                await rate_client.post(
                    "/api/v1/audio/transcriptions",
                    headers=rate_user["headers"],
                    json=_audio_body(),
                )
            ).status_code
            for _ in range(6)
        ]
    finally:
        await rate_client.aclose()
    ok = 429 in codes and codes.count(429) >= 2
    verdict(
        "G-VOICE.V-5-rate",
        "BLOCKED" if ok else "FINDING",
        f"status sequence={codes} (want 429s once past the 3/h bucket — the "
        "third-party spend valve)",
    )

    # --- V-7: IDOR on attachments ------------------------------------------------------------
    section("V-7: cross-user attachment access")
    owner = await _register(client, "gvoice-owner")
    await _consent_voice(client, owner)
    entry_id = await _make_entry(client, owner, "e-redteam-1")
    created = await _upload(client, owner, entry_id, b"RIFF-owned-take" + b"1" * 40)
    attachment_id = created["attachment_id"]
    stranger = await _register(client, "gvoice-stranger")
    idor_get = await client.get(
        f"/api/v1/audio/attachments/{attachment_id}", headers=stranger["headers"]
    )
    idor_delete = await client.request(
        "DELETE",
        f"/api/v1/audio/attachments/{attachment_id}",
        headers=stranger["headers"],
    )
    still_there = await client.get(
        f"/api/v1/audio/attachments/{attachment_id}", headers=owner["headers"]
    )
    ok = (
        idor_get.status_code == 404
        and idor_delete.status_code == 404
        and still_there.status_code == 200
    )
    verdict(
        "G-VOICE.V-7-idor",
        "BLOCKED" if ok else "FINDING",
        f"stranger-get={idor_get.status_code} stranger-delete={idor_delete.status_code} "
        f"owner-still-reads={still_there.status_code} (want 404/404/200 — flat 404, no oracle)",
    )

    # --- V-8: therapist share_voice gate + per-fetch audit --------------------------------------
    section("V-8: therapist voice gate (share_voice + per-fetch audit)")
    shared = await _register(client, "gvoice-shared")
    await _consent_voice(client, shared)
    shared_entry = await _make_entry(client, shared, "e-redteam-shared")
    shared_created = await _upload(
        client, shared, shared_entry, b"RIFF-shared-take" + b"2" * 40
    )

    therapist = await _register(client, "gvoice-therapist")
    async with app.state.sessionmaker() as session:
        t_row = (
            (
                await session.execute(
                    select(UserModel).where(UserModel.id == therapist["user_id"])
                )
            )
            .scalars()
            .one()
        )
        t_row.role = "therapist"
        session.add(t_row)
        now = datetime.now(timezone.utc)
        session.add(
            Consent(
                user_id=shared["user_id"],
                therapist_id=therapist["user_id"],
                status="active",
                granted_at=now,
            )
        )
        await session.commit()
        consent_id = (
            (
                await session.execute(
                    select(Consent.id).where(Consent.user_id == shared["user_id"])
                )
            )
            .scalars()
            .one()
        )

    # Promotion changes the authoritative role. The old patient-purpose
    # token must remain invalid, and cannot exercise a therapist consent
    # gate. Obtain the real role-bound login before testing voice access.
    login = await client.post(
        "/api/v1/auth/login",
        json={"username": "gvoice-therapist", "verifier": therapist["verifier"]},
    )
    assert login.status_code == 200, login.text
    therapist["headers"] = {"Authorization": "Bearer " + login.json()["token"]}

    audio_url = (
        f"/api/therapist/patients/{shared['user_id']}/audio/"
        f"{shared_created['attachment_id']}"
    )
    denied_fetch = await client.get(audio_url, headers=therapist["headers"])
    async with app.state.sessionmaker() as session:
        audit_before = (
            (
                await session.execute(
                    select(AccessLog).where(
                        AccessLog.user_id == shared["user_id"],
                        AccessLog.action == "audio_access",
                    )
                )
            )
            .scalars()
            .all()
        )
    grant = await client.put(
        f"/api/consents/{consent_id}/share-voice",
        headers={**shared["headers"], "X-Account-Verifier": shared["verifier"]},
        json={"enabled": True},
    )
    assert grant.status_code == 200, grant.text
    served = await client.get(audio_url, headers=therapist["headers"])
    async with app.state.sessionmaker() as session:
        audit_after = (
            (
                await session.execute(
                    select(AccessLog).where(
                        AccessLog.user_id == shared["user_id"],
                        AccessLog.action == "audio_access",
                    )
                )
            )
            .scalars()
            .all()
        )
    ok = (
        denied_fetch.status_code == 403
        and denied_fetch.json()["code"] == "consent_voice_share_required"
        and len(audit_before) == 0
        and served.status_code == 200
        and len(audit_after) == 1
        and audit_after[0].actor_id == therapist["user_id"]
    )
    verdict(
        "G-VOICE.V-8-therapist-gate",
        "BLOCKED" if ok else "FINDING",
        f"no-grant={denied_fetch.status_code}/{denied_fetch.json().get('code')} "
        f"audit-before-grant={len(audit_before)} granted-fetch={served.status_code} "
        f"audit-rows={len(audit_after)} (want 403/consent_voice_share_required, 0, 200, 1)",
    )

    # --- V-11: translation consent scope (H4) -----------------------------------------------------
    section("V-11: translation dispatch requires the CURRENT llm consent (H4)")
    settings.llm_url = "https://llm.redteam.example/v1"
    settings.llm_api_key = "redteam-llm-key"
    dispatched: list[str] = []

    async def fake_translate(s, text, source_lang):
        dispatched.append(text)
        return "translated"

    original_translate = stt_service.translate_to_english
    stt_service.translate_to_english = fake_translate
    try:
        no_llm_consent = await client.post(
            "/api/v1/audio/transcriptions",
            headers=consented["headers"],
            json=_audio_body(),
        )
        # Snapshot BEFORE the consented call: the post-grant dispatch is
        # the EXPECTED second half of the assertion.
        suppressed_dispatches = len(dispatched)
        granted_llm = await client.put(
            "/api/account/llm-consent",
            headers=consented["headers"],
            json={"enabled": True, "verifier": consented["verifier"]},
        )
        assert granted_llm.status_code == 200, granted_llm.text
        with_llm_consent = await client.post(
            "/api/v1/audio/transcriptions",
            headers=consented["headers"],
            json=_audio_body(),
        )
    finally:
        stt_service.translate_to_english = original_translate
    settings.llm_url = ""
    settings.llm_api_key = ""
    ok = (
        no_llm_consent.status_code == 200
        and no_llm_consent.json()["english_text"] is None
        and suppressed_dispatches == 0
        and with_llm_consent.status_code == 200
        and with_llm_consent.json()["english_text"] == "translated"
    )
    verdict(
        "G-VOICE.V-11-translation-consent",
        "BLOCKED" if ok else "FINDING",
        f"no-llm-consent english_text={no_llm_consent.json().get('english_text')} "
        f"dispatches={suppressed_dispatches} after-grant={with_llm_consent.json().get('english_text')} "
        "(want null/0/'translated' — a configured LLM must not receive journal text "
        "through the voice path without its own current consent)",
    )

    # --- V-12: upstream retry against the REAL SpeechToText client ---------------------------------
    section("V-12: upstream retry — exactly once on 429, never on 400")
    import httpx
    from app.services.stt import SpeechToText

    engine = SpeechToText("https://stt.redteam.example/v1", "k")
    calls = {"n": 0}

    async def transient(self, files, data):
        calls["n"] += 1
        if calls["n"] == 1:
            request = httpx.Request("POST", engine.url + "/audio/transcriptions")
            raise httpx.HTTPStatusError(
                "busy",
                request=request,
                response=httpx.Response(
                    429, request=request, headers={"retry-after": "0"}
                ),
            )
        return {"text": "after retry", "language": "english"}

    async def instant_sleep(_seconds):
        return None

    real_sleep = asyncio.sleep
    asyncio.sleep = instant_sleep
    engine._post_audio = transient.__get__(engine, SpeechToText)
    try:
        retried = await engine.transcribe(b"audio", "audio/webm")
    finally:
        asyncio.sleep = real_sleep

    engine2 = SpeechToText("https://stt.redteam.example/v1", "k")
    calls2 = {"n": 0}

    async def bad_request(self, files, data):
        calls2["n"] += 1
        request = httpx.Request("POST", engine2.url + "/audio/transcriptions")
        raise httpx.HTTPStatusError(
            "nope", request=request, response=httpx.Response(400, request=request)
        )

    engine2._post_audio = bad_request.__get__(engine2, SpeechToText)
    raised = False
    try:
        await engine2.transcribe(b"audio", "audio/webm")
    except httpx.HTTPStatusError:
        raised = True
    ok = (
        retried.text == "after retry"
        and calls["n"] == 2
        and raised
        and calls2["n"] == 1
    )
    verdict(
        "G-VOICE.V-12-retry",
        "BLOCKED" if ok else "FINDING",
        f"429: calls={calls['n']} result={retried.text!r}; 400: calls={calls2['n']} "
        f"raised={raised} (want 2/'after retry' and 1/True — one bounded retry, "
        "never for client errors)",
    )

    # --- V-9 spot: lazy expiry kills row AND object on the fetch path -------------------------------
    section("V-9 spot: lazy expiry enforces retention on the fetch path")
    async with app.state.sessionmaker() as session:
        row = (
            (
                await session.execute(
                    select(AudioAttachment).where(
                        AudioAttachment.id == shared_created["attachment_id"]
                    )
                )
            )
            .scalars()
            .one()
        )
        row.expires_at = utcnow() - timedelta(seconds=1)
        expired_key = row.storage_key
        await session.commit()
    store = get_audio_store(app.state.settings)
    expired_object_path = store.root / expired_key
    assert expired_object_path.exists(), "fixture setup: object expected present"
    expired = await client.get(
        f"/api/v1/audio/attachments/{shared_created['attachment_id']}",
        headers=shared["headers"],
    )
    async with app.state.sessionmaker() as session:
        remaining = (
            (
                await session.execute(
                    select(AudioAttachment).where(
                        AudioAttachment.id == shared_created["attachment_id"]
                    )
                )
            )
            .scalars()
            .all()
        )
    ok = (
        expired.status_code == 410
        and remaining == []
        and not expired_object_path.exists()
    )
    verdict(
        "G-VOICE.V-9-lazy-expiry",
        "BLOCKED" if ok else "FINDING",
        f"expired-fetch={expired.status_code} rows-left={len(remaining)} "
        f"object-gone={not expired_object_path.exists()} (want 410/0/True — a missed "
        "sweep cycle cannot extend retention)",
    )


if __name__ == "__main__":
    run(main, "g_voice")
