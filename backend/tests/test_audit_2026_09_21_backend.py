"""Regression tests for the 2026-09-21 audit, Part 1.3 (backend correctness).

Each test names its finding (audit IDs from AUDIT_2026-09-21.md):

* A-1: rekey mutates every entry/measure blob without advancing the
  collection revision — mid-pagination clients must see collection_changed.
* A-2: export insight pagination dropped rows queued past the first
  metadata chunk when a page processed partially.
* A-3: measures reads had no byte bound, no continuation header and no
  revision marker (patient + therapist paths).
* A-5: consent revoke/rewrap answered 500 (StaleDataError) when a
  concurrent therapist deletion cascade-deleted the grant mid-request.
* A-6: the export shares keyset rode the mutable granted_at column — a
  re-grant mid-export dropped the share.
* A-8: the legacy /api mount served no Deprecation header; an analysis
  budget too small to load a single entry silently overwrote stored
  patterns with an empty-corpus recompute instead of refusing.
"""

from __future__ import annotations

import base64
import json
from datetime import date, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import update
from sqlalchemy.orm.exc import StaleDataError

from app.api import account as account_module
from app.api.measures import MEASURE_PAGE_BLOB_BYTES
from app.deps import ApiError
from app.models import Consent, Insight, Measure
from tests.helpers import ClientEmulator, TherapistEmulator, patient_wrap_for

TODAY = date.today()


def _measure_payload(client_measure_id: str, blob: bytes, measure_date: date) -> dict:
    return {
        "client_measure_id": client_measure_id,
        "blob": base64.b64encode(blob).decode("ascii"),
        "measure_date": measure_date.isoformat(),
    }


async def _grant(client, patient: ClientEmulator, therapist: TherapistEmulator) -> dict:
    code = await therapist.create_pairing_code(client)
    lookup = await patient.pairing_lookup(client, code)
    granted = await patient.grant_consent(
        client, code, lookup["body"]["wrap_pub_key"], lookup["body"]["therapist_id"]
    )
    assert granted["status"] == 201, granted
    return granted


# --- A-1: rekey advances the collection revisions -----------------------------------


async def test_rekey_advances_entries_and_measures_revision(client):
    from app.security import crypto

    emu = ClientEmulator("rekey-rev", "deep-password")
    await emu.register(client)
    await emu.backdate_account(client, days=30)
    for i in range(3):
        await emu.create_entry(
            client, f"entry number {i}", TODAY - timedelta(days=i), client_entry_id=f"rekey-e-{i}"
        )
    # A real encrypted measure blob: the rekey authenticates EVERY stored
    # blob under the old key, so a raw-bytes row would abort it.
    measure_payload = json.dumps({"v": 1, "measure": "phq9", "score": 8}).encode("utf-8")
    measure_blob = crypto.encrypt(
        emu.data_key,
        measure_payload,
        crypto.build_aad("measure", emu.user_id or "", "rekey-m-1"),
    )
    await client.post(
        "/api/measures",
        headers=emu.headers,
        json=_measure_payload("rekey-m-1", measure_blob, TODAY),
    )

    before_entries = await client.get("/api/entries", headers=emu.headers, params={"limit": 10})
    assert before_entries.status_code == 200
    rev_entries_before = int(before_entries.headers["X-Entries-Revision"])
    before_measures = await client.get("/api/measures", headers=emu.headers)
    assert before_measures.status_code == 200
    rev_measures_before = int(before_measures.headers["X-Measures-Revision"])

    new_key = bytes(range(32))
    await emu.rekey(client, emu.data_key, new_key)

    after_entries = await client.get("/api/entries", headers=emu.headers, params={"limit": 10})
    assert int(after_entries.headers["X-Entries-Revision"]) == rev_entries_before + 1
    after_measures = await client.get("/api/measures", headers=emu.headers)
    assert int(after_measures.headers["X-Measures-Revision"]) == rev_measures_before + 1

    # A mid-pagination client that captured the pre-rekey snapshot marker
    # must be told the collection moved, never handed mixed-key rows.
    stale = await client.get(
        "/api/entries",
        headers=emu.headers,
        params={"limit": 10, "expected_revision": str(rev_entries_before)},
    )
    assert stale.status_code == 409
    assert stale.json()["code"] == "collection_changed"
    stale_measures = await client.get(
        "/api/measures",
        headers=emu.headers,
        params={"expected_revision": str(rev_measures_before)},
    )
    assert stale_measures.status_code == 409
    assert stale_measures.json()["code"] == "collection_changed"


# --- A-2: export insight pagination keeps every queued chunk ------------------------


async def test_export_insights_never_drop_rows_past_the_first_chunk(client, app, monkeypatch):
    emu = ClientEmulator("export-tail", "deep-password")
    await emu.register(client)

    # 10 dated question rows (the unique constraint is (user_id, kind,
    # for_date), so undated rows cannot repeat), blobs small enough that a
    # monkeypatched 150-byte page budget processes ~1 row per short page —
    # the exact shape that used to discard every id queued past the first
    # 3-row metadata chunk.
    async with app.state.sessionmaker() as session:
        session.add_all(
            Insight(
                user_id=emu.user_id,
                kind="question",
                for_date=TODAY - timedelta(days=i),
                blob=bytes([65 + i]) * 100,
            )
            for i in range(10)
        )
        await session.commit()

    monkeypatch.setattr(account_module, "EXPORT_METADATA_PAGE_SIZE", 3)
    monkeypatch.setattr(account_module, "EXPORT_PAGE_BLOB_BYTES", 150)

    response = await client.get("/api/account/export", headers=emu.headers)
    assert response.status_code == 200, response.text
    bundle = response.json()
    assert len(bundle["insights"]) == 10, "export dropped rows queued past the first chunk"


# --- A-6: export shares survive a re-grant mid-download -----------------------------


class _RegrantOnSecondPage:
    """Wraps the app sessionmaker: on the Nth page session open, rewrites a
    not-yet-emitted share's granted_at past the export cutoff — exactly the
    mid-download re-grant that used to drop the share from the bundle."""

    def __init__(self, real, mutation_session_factory, consent_id, fire_on_open: int):
        self._real = real
        self._factory = mutation_session_factory
        self._consent_id = consent_id
        self._fire_on_open = fire_on_open
        self.opens = 0

    def __call__(self):
        self.opens += 1
        real_cm = self._real()
        outer = self

        class _CM:
            async def __aenter__(self):
                if outer.opens == outer._fire_on_open:
                    async with outer._factory() as mutation:
                        await mutation.execute(
                            update(Consent)
                            .where(Consent.id == outer._consent_id)
                            .values(granted_at=datetime(2031, 1, 1))
                        )
                        await mutation.commit()
                return await real_cm.__aenter__()

            async def __aexit__(self, *exc):
                return await real_cm.__aexit__(*exc)

        return _CM()


async def test_export_share_survives_regrant_mid_download(client, app, monkeypatch):
    patient = ClientEmulator("share-snap", "deep-password")
    await patient.register(client)
    therapists = []
    granted = []
    for i in range(3):
        th = TherapistEmulator(f"share-dr-{i}", "pw-therapist", f"Dr {i}")
        await th.register(client)
        result = await _grant(client, patient, th)
        therapists.append(th)
        granted.append(result["body"])

    # One share per metadata page: pages 1-3 are the share chunks; fire the
    # re-grant when page 2 opens (share #1 emitted, share #3 still pending).
    monkeypatch.setattr(account_module, "EXPORT_METADATA_PAGE_SIZE", 1)
    real_sessionmaker = app.state.sessionmaker
    mutator = _RegrantOnSecondPage(
        real_sessionmaker, real_sessionmaker, granted[2]["id"], fire_on_open=2
    )
    app.state.sessionmaker = mutator
    try:
        response = await client.get("/api/account/export", headers=patient.headers)
    finally:
        app.state.sessionmaker = real_sessionmaker
    assert response.status_code == 200, response.text
    usernames = {s["therapist_username"] for s in response.json()["shares"]}
    assert usernames == {f"share-dr-{i}" for i in range(3)}, (
        "a re-grant mid-export dropped a share from the bundle"
    )


# --- A-5: concurrent therapist deletion during revoke/rewrap ------------------------


class _VanishingConsentSession:
    """Serves the revoke/rewrap query ladder, then fails the commit with
    StaleDataError — the therapist row (and its cascade-deleted consent)
    vanished between the read and the flush (audit A-5)."""

    def __init__(self, user, consent, therapist):
        self.user = user
        self.consent = consent
        self.therapist = therapist
        self.added = []

    async def get(self, _model, _pk, **_kw):
        return self.user

    async def execute(self, statement):
        text = str(statement).lower()
        if "consent" in text:
            return SimpleNamespace(
                first=lambda: (self.consent, self.therapist),
                scalars=lambda: SimpleNamespace(first=lambda: self.consent),
            )
        return SimpleNamespace(
            first=lambda: None, scalars=lambda: SimpleNamespace(first=lambda: None)
        )

    async def scalar(self, _statement):
        return None

    async def refresh(self, *_a, **_k):
        pass

    def add(self, row):
        self.added.append(row)

    async def commit(self):
        raise StaleDataError(
            "UPDATE statement on table 'consents' expected to update 1 row(s); 0 were matched."
        )

    async def rollback(self):
        pass


async def _real_user(app, emu) -> object:
    async with app.state.sessionmaker() as session:
        from sqlalchemy import select

        from app.models import User

        return (
            (
                await session.execute(
                    select(User)
                    .where(User.id == emu.user_id)
                    .execution_options(populate_existing=True)
                )
            )
            .scalars()
            .first()
        )


async def test_revoke_maps_stale_consent_to_404(client, app):
    from app.api import consents as consents_module

    emu = ClientEmulator("revoke-race", "deep-password")
    await emu.register(client)
    th = TherapistEmulator("revoke-race-dr", "pw-therapist")
    await th.register(client)
    granted = await _grant(client, emu, th)

    user = await _real_user(app, emu)
    fake_consent = SimpleNamespace(
        id=granted["body"]["id"],
        user_id=emu.user_id,
        therapist_id=th.user_id,
        status="active",
    )
    session = _VanishingConsentSession(user, fake_consent, SimpleNamespace())
    with pytest.raises(ApiError) as excinfo:
        await consents_module.revoke_consent(
            consent_id=granted["body"]["id"],
            request=SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace())),
            user=user,
            session=session,
            x_account_verifier=emu.auth_key_b64,
        )
    assert excinfo.value.status_code == 404
    assert excinfo.value.code == "not_found"


async def test_rewrap_maps_stale_consent_to_404(client, app):
    from app.api import consents as consents_module

    emu = ClientEmulator("rewrap-race", "deep-password")
    await emu.register(client)
    th = TherapistEmulator("rewrap-race-dr", "pw-therapist")
    await th.register(client)
    granted = await _grant(client, emu, th)

    user = await _real_user(app, emu)
    fake_consent = SimpleNamespace(
        id=granted["body"]["id"],
        user_id=emu.user_id,
        therapist_id=th.user_id,
        status="active",
    )
    wrap = patient_wrap_for(emu, th.wrap_pub_key, th.user_id or "")
    session = _VanishingConsentSession(user, fake_consent, SimpleNamespace())
    with pytest.raises(ApiError) as excinfo:
        await consents_module.rewrap_consent(
            consent_id=granted["body"]["id"],
            body=consents_module.ConsentRewrapRequest(**wrap),
            request=SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace())),
            user=user,
            session=session,
            x_account_verifier=emu.auth_key_b64,
        )
    assert excinfo.value.status_code == 404
    assert excinfo.value.code == "not_found"


# --- A-3: measures pagination contract (patient + therapist) ------------------------


async def _seed_measures(app, emu, ids_and_sizes):
    async with app.state.sessionmaker() as session:
        session.add_all(
            Measure(
                user_id=emu.user_id,
                client_measure_id=cid,
                blob=b"m" * size,
                measure_date=TODAY - timedelta(days=i),
            )
            for i, (cid, size) in enumerate(ids_and_sizes)
        )
        await session.commit()


async def test_measures_byte_paginate_and_legacy_413(client, app):
    emu = ClientEmulator("meas-page", "deep-password")
    await emu.register(client)
    half = MEASURE_PAGE_BLOB_BYTES // 2
    await _seed_measures(app, emu, [("mp-1", half), ("mp-2", half), ("mp-3", half)])

    # Legacy client: a page over the hard budget is an explicit 413, never
    # a silently truncated or 4 MB wire response.
    legacy = await client.get("/api/measures", headers=emu.headers, params={"limit": 500})
    assert legacy.status_code == 413
    assert legacy.json()["code"] == "payload_too_large"

    # Modern opt-in: two bounded rows + the exact continuation.
    first = await client.get(
        "/api/measures",
        headers=emu.headers,
        params={"limit": 500, "page_bytes": MEASURE_PAGE_BLOB_BYTES},
    )
    assert first.status_code == 200, first.text
    rows = first.json()
    assert len(rows) == 2
    assert first.headers["X-Next-Offset"] == "2"
    assert "X-Measures-Revision" in first.headers
    revision = first.headers["X-Measures-Revision"]

    second = await client.get(
        "/api/measures",
        headers=emu.headers,
        params={"limit": 500, "offset": 2, "page_bytes": MEASURE_PAGE_BLOB_BYTES},
    )
    assert second.status_code == 200
    assert [r["client_measure_id"] for r in second.json()] == ["mp-3"]
    assert "X-Next-Offset" not in second.headers
    assert second.headers["X-Measures-Revision"] == revision

    assert {r["client_measure_id"] for r in rows + second.json()} == {"mp-1", "mp-2", "mp-3"}


async def test_measures_budget_smaller_than_first_blob_is_413(client, app):
    emu = ClientEmulator("meas-small", "deep-password")
    await emu.register(client)
    await _seed_measures(app, emu, [("ms-1", 2_048)])
    response = await client.get(
        "/api/measures",
        headers=emu.headers,
        params={"limit": 10, "page_bytes": 1_024},
    )
    assert response.status_code == 413
    assert response.json()["code"] == "payload_too_large"


async def test_measures_create_advances_revision_and_conflicts_stale_snapshots(client):
    emu = ClientEmulator("meas-rev", "deep-password")
    await emu.register(client)
    created = await client.post(
        "/api/measures",
        headers=emu.headers,
        json=_measure_payload("mr-1", b"k" * 96, TODAY),
    )
    assert created.status_code == 201, created.text
    page1 = await client.get("/api/measures", headers=emu.headers)
    revision = page1.headers["X-Measures-Revision"]

    # A create between pages bumps the marker...
    created2 = await client.post(
        "/api/measures",
        headers=emu.headers,
        json=_measure_payload("mr-2", b"k" * 96, TODAY - timedelta(days=1)),
    )
    assert created2.status_code == 201, created2.text

    # ...so the client holding the old snapshot gets collection_changed,
    # not silently duplicated/skipped offsets on the DESC list.
    stale = await client.get(
        "/api/measures",
        headers=emu.headers,
        params={"expected_revision": revision},
    )
    assert stale.status_code == 409
    assert stale.json()["code"] == "collection_changed"

    fresh = await client.get("/api/measures", headers=emu.headers)
    assert fresh.headers["X-Measures-Revision"] != revision
    assert [r["client_measure_id"] for r in fresh.json()] == ["mr-1", "mr-2"]


async def test_therapist_measures_mirror_the_pagination_contract(client, app):
    patient = ClientEmulator("meas-th-p", "deep-password")
    await patient.register(client)
    await patient.backdate_account(client, days=14)
    half = MEASURE_PAGE_BLOB_BYTES // 2
    async with app.state.sessionmaker() as session:
        session.add_all(
            Measure(
                user_id=patient.user_id,
                client_measure_id=f"tm-{i}",
                blob=b"t" * size,
                measure_date=TODAY - timedelta(days=i),
            )
            for i, size in enumerate([half, half, half])
        )
        await session.commit()
    th = TherapistEmulator("meas-th-dr", "pw-therapist", "Dr Page")
    await th.register(client)
    await _grant(client, patient, th)

    legacy = await client.get(
        f"/api/therapist/patients/{patient.user_id}/measures",
        headers=th.headers,
        params={"limit": 500},
    )
    assert legacy.status_code == 413
    assert legacy.json()["code"] == "payload_too_large"

    first = await client.get(
        f"/api/therapist/patients/{patient.user_id}/measures",
        headers=th.headers,
        params={"limit": 500, "page_bytes": MEASURE_PAGE_BLOB_BYTES},
    )
    assert first.status_code == 200, first.text
    assert len(first.json()) == 2
    assert first.headers["X-Next-Offset"] == "2"
    revision = first.headers["X-Measures-Revision"]

    # A patient-side create between pages must break the portal's snapshot
    # too (the marker is the patient's own measures_revision).
    created = await client.post(
        "/api/measures",
        headers=patient.headers,
        json=_measure_payload("tm-new", b"t" * 96, TODAY),
    )
    assert created.status_code == 201, created.text
    stale = await client.get(
        f"/api/therapist/patients/{patient.user_id}/measures",
        headers=th.headers,
        params={
            "limit": 500,
            "offset": 2,
            "page_bytes": MEASURE_PAGE_BLOB_BYTES,
            "expected_revision": revision,
        },
    )
    assert stale.status_code == 409
    assert stale.json()["code"] == "collection_changed"


# --- A-8: legacy mount Deprecation header -------------------------------------------


async def test_legacy_api_mount_sends_deprecation_header(client):
    # The deprecated unversioned mount must announce itself on the wire;
    # the canonical /api/v1 mount must not.
    legacy = await client.get("/api/meta")
    assert legacy.status_code == 200
    assert legacy.headers["deprecation"] == "true"
    canonical = await client.get("/api/v1/meta")
    assert canonical.status_code == 200
    assert "deprecation" not in canonical.headers


# --- A-8: an empty-corpus recompute refuses instead of overwriting --------------------


async def test_recompute_budget_below_every_entry_refuses_413(client, settings):
    from sqlalchemy import select

    emu = ClientEmulator("budget-413", "deep-password")
    await emu.register(client)
    await emu.backdate_account(client, days=42)
    for i in range(40):
        await emu.create_entry(
            client, f"budget probe day {i}", TODAY - timedelta(days=i), client_entry_id=f"b413-{i}"
        )
    # Below every stored blob (attribute mutation post-construction, the
    # way an operator override would misconfigure a live system): the
    # load can keep nothing, and the recompute used to run the brain on
    # the resulting empty corpus and store the empty run.
    settings.analysis_blob_budget = 1
    try:
        token = await emu.open_processing_session(client)
        response = await client.post(
            "/api/insights/recompute",
            headers={**emu.headers, "X-Processing-Token": token},
        )
        assert response.status_code == 413
        assert response.json()["code"] == "payload_too_large"
        # Refused BEFORE any write: no brain state may exist for an
        # account whose only recompute was refused.
        app = client._transport.app  # noqa: SLF001 — test reachability into state
        async with app.state.sessionmaker() as session:
            rows = (
                (
                    await session.execute(
                        select(Insight).where(Insight.user_id == emu.user_id)
                    )
                )
                .scalars()
                .all()
            )
        assert all(row.kind != "brain" for row in rows)
    finally:
        settings.analysis_blob_budget = 8 * 1024 * 1024
