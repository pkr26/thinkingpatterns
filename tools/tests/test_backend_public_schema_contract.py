"""Released API schemas are an observable client compatibility contract."""

from __future__ import annotations

import importlib
import json
import os
from datetime import date, datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "tools/tests/fixtures/public_openapi.json"


def _runtime_modules(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "backend"))
    for name in tuple(os.environ):
        if name.startswith("MINDPATTERN_"):
            monkeypatch.delenv(name)
    monkeypatch.setenv("MINDPATTERN_ENV", "development")
    return importlib.import_module("app.main"), importlib.import_module("app.schemas")


def test_released_public_openapi_schema_is_compatible(monkeypatch):
    main, _ = _runtime_modules(monkeypatch)
    expected = json.loads(CONTRACT.read_text())
    first = main.create_app().openapi()
    second = main.create_app().openapi()
    assert first == second == expected


def test_local_analysis_accepts_iso_dates_and_refuses_invalid_input(monkeypatch):
    _, schemas = _runtime_modules(monkeypatch)
    valid = {
        "base_state_seq": 0,
        "state_blob": "AA==",
        "patterns_blob": "AA==",
        "analysis_dates": ["2026-10-05"],
        "patterns_count": 1,
    }
    request = schemas.LocalRecomputeRequest(**valid)
    assert request.model_dump() == valid
    for dates in ([], [""], ["2026/10/05"], ["2026-10-05"] * 367):
        with pytest.raises(ValueError):
            schemas.LocalRecomputeRequest(**{**valid, "analysis_dates": dates})
    for count in (-1, 10_001):
        with pytest.raises(ValueError):
            schemas.LocalRecomputeRequest(**{**valid, "patterns_count": count})


def test_export_defaults_and_legacy_entry_generation_remain_portable(monkeypatch):
    _, schemas = _runtime_modules(monkeypatch)
    stamp = datetime(2026, 10, 5, tzinfo=timezone.utc)
    insight = schemas.InsightOut(
        kind="brain", for_date=None, blob="AA==", created_at=stamp
    )
    audio = schemas.AudioExportRow(
        id="recording",
        client_entry_id="entry",
        mime_type="audio/mp4",
        duration_seconds=3,
        size_bytes=5,
        expires_at=stamp,
        blob="AA==",
    )
    event = schemas.ConsentEventOut(
        id="event", kind="voice", action="granted", occurred_at=stamp
    )
    assert insight.state_seq == 0
    assert audio.content_version == 1 and audio.created_at is None
    assert event.model_dump() == {
        "id": "event",
        "kind": "voice",
        "action": "granted",
        "disclosure": None,
        "policy": None,
        "consent_id": None,
        "share_voice": None,
        "event_version": 1,
        "occurred_at": stamp,
    }
    required = {
        "version": 3,
        "exported_at": stamp,
        "user_id": "owner",
        "salt": "AA==",
        "llm_consent": False,
        "entries": [],
        "insights": [insight],
    }
    expected = {
        **required,
        "insights": [insight.model_dump()],
        "username": None,
        "age_attestation_version": None,
        "age_attested_at": None,
        "recovery_enabled": False,
        "recovery_set_at": None,
        "recovery_scheme": None,
        "llm_consent_at": None,
        "llm_consent_disclosure": None,
        "llm_consent_policy": None,
        "voice_consent": False,
        "voice_consent_at": None,
        "voice_consent_disclosure": None,
        "voice_consent_policy": None,
        "shares": [],
        "consent_events": [],
        "access_log": [],
        "audio": [],
        "measures": [],
        "key_scheme": "v1",
        "wrapped_data_key": None,
        "kdf_params": None,
    }
    first = schemas.ExportBundle(**required)
    second = schemas.ExportBundle(**required)
    assert first.model_dump() == second.model_dump() == expected
    first.audio.append(audio)
    assert second.audio == [], "separate exports must not share mutable defaults"
    for scheme in ("v1", "v2"):
        assert (
            schemas.ExportBundle(
                **{**required, "recovery_scheme": scheme}
            ).recovery_scheme
            == scheme
        )
    with pytest.raises(ValueError):
        schemas.ExportBundle(**{**required, "recovery_scheme": "unsupported"})
    consent = schemas.ShareRecord(
        id="share",
        therapist_id="therapist",
        therapist_username="clinician",
        therapist_display_name="Therapist",
        status="active",
        scope="insights",
        granted_at=stamp,
    )
    assert (
        consent.revoked_at is None
        and consent.disclosure is None
        and consent.share_voice is False
    )
    for version in (None, 4):
        row = SimpleNamespace(
            id="entry",
            client_entry_id="client-entry",
            blob=b"opaque",
            entry_date=date(2026, 10, 5),
            received_at=stamp,
            content_version=version,
        )
        assert schemas.entry_out(row).content_version == (
            1 if version is None else version
        )


def test_signed_generation_limits_are_exact_in_validated_request_values(monkeypatch):
    _, schemas = _runtime_modules(monkeypatch)
    maximum = 9_223_372_036_854_775_807
    records = [
        (
            "EntryCreate",
            {"client_entry_id": "entry", "blob": "AA==", "entry_date": "2026-10-05"},
            "content_version",
            1,
            maximum,
        ),
        (
            "EntryReplace",
            {"blob": "AA==", "entry_date": "2026-10-05"},
            "content_version",
            1,
            maximum,
        ),
        (
            "TherapistCustodyRequest",
            {
                "verifier": "AA==",
                "operation_id": "00000000-0000-0000-0000-000000000000",
                "custody_version": 1,
                "notes_keyring_blob": "AA==",
            },
            "expected_custody_version",
            0,
            maximum - 1,
        ),
        (
            "TherapistCustodyRequest",
            {
                "verifier": "AA==",
                "operation_id": "00000000-0000-0000-0000-000000000000",
                "expected_custody_version": 0,
                "notes_keyring_blob": "AA==",
            },
            "custody_version",
            1,
            maximum,
        ),
        (
            "WrapKeyRotateRequest",
            {"wrap_pub_key": "AA==", "wrap_key_blob": "AA=="},
            "expected_custody_version",
            0,
            maximum,
        ),
        (
            "NoteCreateRequest",
            {"client_note_id": "note", "blob": "AA=="},
            "custody_version",
            0,
            maximum,
        ),
        (
            "NoteRekeyItem",
            {"note_id": "note", "blob": "AA=="},
            "base_version",
            1,
            maximum,
        ),
        (
            "NoteRekeyRequest",
            {"items": [{"note_id": "note", "blob": "AA==", "base_version": 1}]},
            "custody_version",
            0,
            maximum,
        ),
        ("NoteUpdateRequest", {"blob": "AA=="}, "base_version", 1, maximum),
        ("NoteUpdateRequest", {"blob": "AA=="}, "custody_version", 0, maximum),
    ]
    for name, values, field, lower, upper in records:
        model = getattr(schemas, name)
        for value in (lower, upper):
            assert getattr(model(**{**values, field: value}), field) == value
        for value in (lower - 1, upper + 1):
            with pytest.raises(ValueError):
                model(**{**values, field: value})
