"""API-workstream regression pins for the 2026-09-20 audit wave.

(The infra-workstream pins for the same audit live in
test_infra_pins.py; this file covers the account/insights/
measures/therapist/consents + services findings.)

  * H-3  — the account export streams every Measure row, decryptable with
           the client's own measure AAD context.
  * H-12 — the day's question is pinned on first write; a same-day
           recompute with an extra pattern serves the SAME question text.
  * H-14 — sharing disclosure v2: a legacy v1 consent refuses the measures
           read with 409 disclosure_outdated (+ meta) while entries and
           insights stay readable; GET /therapist/patients writes an
           access_log row per listed patient.
  * H-16 — the caseload summary in the patient list is suppressed unless
           the patient is CURRENTLY insight-phase; the therapist insights
           read reports the stored state_seq instead of 0.
  * M-2/M-3 — the in-fence re-authorization includes token_epoch.
  * M-4  — measures reads page deterministically by offset on both the
           patient and therapist paths (cap raised to 500).
  * M-5  — the LLM enricher branch keeps muted cards behind the capped
           unmuted cards (a flat [:MAX_SURFACED] cut removed them).
  * M-11 — the threshold phase is re-evaluated INSIDE the lifecycle fence;
           entries deleted while the recompute waited return baseline.
  * M-30 — audit rows survive the 409 paths raised AFTER ciphertext was
           fetched (entries read + notes read).
  * L-5  — entry/measure date bounds use the server-UTC calendar day.
  * L-6  — the duplicate check precedes the quota check, so an idempotent
           retry at the quota boundary answers 409, not 413.
  * L-7  — measures uses the entries error envelope (422/validation_error)
           for identical client-error classes.
  * L-12 — a note insert losing its patient row to concurrent deletion is
           a 404, never a masquerading 409.
  * L-27 — request models reject unknown fields.
  * L-28 — display names reject control/bidi/format characters.
  * L-29 — an empty pattern_pid is a 422, not a silent "general note".
"""

from __future__ import annotations

import base64
import json
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from app.api import insights as insights_api
from app.api import measures as measures_api
from app.deps import ApiError
from app.models import AccessLog, Consent, User
from app.security import crypto
from tests.helpers import ClientEmulator, TherapistEmulator, daterange
from tests.test_insights_api import seed_corpus

TODAY = date.today()


# --- shared helpers -----------------------------------------------------------


def _measure_blob(emu: ClientEmulator, client_measure_id: str, score: int) -> str:
    payload = json.dumps(
        {"v": 1, "measure": "phq9", "score": score, "completed_at": TODAY.isoformat()}
    ).encode("utf-8")
    blob = crypto.encrypt(
        emu.data_key, payload, crypto.build_aad("measure", emu.user_id or "", client_measure_id)
    )
    return base64.b64encode(blob).decode("ascii")


async def _record_measure(
    emu: ClientEmulator, client, client_measure_id: str, score: int, measure_date: date
):
    return await client.post(
        "/api/measures",
        headers=emu.headers,
        json={
            "client_measure_id": client_measure_id,
            "blob": _measure_blob(emu, client_measure_id, score),
            "measure_date": measure_date.isoformat(),
        },
    )


async def _grant_share(client, patient: ClientEmulator, therapist: TherapistEmulator) -> Consent:
    code = await therapist.create_pairing_code(client)
    lookup = await patient.pairing_lookup(client, code)
    granted = await patient.grant_consent(
        client, code, lookup["body"]["wrap_pub_key"], lookup["body"]["therapist_id"]
    )
    assert granted["status"] == 201, granted
    app = client._transport.app  # noqa: SLF001 — test reachability into state
    async with app.state.sessionmaker() as session:
        return (
            (
                await session.execute(
                    select(Consent).where(
                        Consent.user_id == patient.user_id,
                        Consent.therapist_id == therapist.user_id,
                    )
                )
            )
            .scalars()
            .one()
        )


async def _audit_rows(client) -> list[AccessLog]:
    app = client._transport.app  # noqa: SLF001
    async with app.state.sessionmaker() as session:
        return list(
            (await session.execute(select(AccessLog).order_by(AccessLog.at, AccessLog.id)))
            .scalars()
            .all()
        )


def _user(user_id: str, epoch: int) -> User:
    user = User(
        id=user_id,
        username=f"{user_id}-name",
        salt="c2FsdA==",
        verifier=b"v",
        scrypt_salt=b"s",
        is_active=True,
        token_epoch=epoch,
        entries_revision=0,
    )
    user.created_at = datetime.now(timezone.utc)
    return user


# --- H-3: export carries the measure history ----------------------------------


async def test_export_streams_measures_decryptable_with_client_aad(client):
    """The bundle's `measures` list carries the stored ciphertext verbatim;
    decryption with ("measure", user_id, client_measure_id) yields the
    score — the exact contract the offline decrypt tool implements."""
    emu = ClientEmulator("h3-export", "deep-password")
    await emu.register(client)
    await emu.backdate_account(client, days=40)
    for offset, score in ((7, 14), (3, 9), (0, 21)):
        response = await _record_measure(
            emu, client, f"h3-m-{offset}", score, TODAY - timedelta(days=offset)
        )
        assert response.status_code == 201, response.text

    export = await client.get("/api/account/export", headers=emu.headers)
    assert export.status_code == 200, export.text
    bundle = export.json()
    rows = bundle["measures"]
    # (measure_date, id) ascending keyset: oldest completion first.
    assert [row["client_measure_id"] for row in rows] == ["h3-m-7", "h3-m-3", "h3-m-0"]
    for row, expected_score in zip(rows, (14, 9, 21)):
        # Row shape (pinned for the decrypt tool): id, client_measure_id,
        # blob (b64 nonce||ct||tag), measure_date, received_at.
        assert set(row) == {
            "id",
            "client_measure_id",
            "blob",
            "measure_date",
            "received_at",
        }
        plain = crypto.decrypt(
            emu.data_key,
            base64.b64decode(row["blob"]),
            crypto.build_aad("measure", emu.user_id or "", row["client_measure_id"]),
        )
        assert json.loads(plain.decode("utf-8"))["score"] == expected_score


# --- H-12: the day's question is pinned on first write -------------------------


async def test_same_day_recompute_with_extra_pattern_serves_same_question(client):
    emu = ClientEmulator("h12-pin", "deep-password")
    await emu.register(client)
    await seed_corpus(client, emu, days=32)
    await emu.recompute(client)
    first = await emu.decrypt_question(client, TODAY)

    # An evening entry changes the surfaced pool; the recompute must still
    # serve the SAME question text for the day (the user may already have
    # answered it).
    await emu.create_entry(
        client,
        "so tired of the commute, so tired of everything today",
        TODAY,
        client_entry_id="h12-extra",
    )
    await emu.recompute(client)
    second = await emu.decrypt_question(client, TODAY)
    assert second["question"] == first["question"]
    assert second["pattern_pid"] == first["pattern_pid"]


# --- H-14: disclosure v2 — legacy grants do not cover measures -----------------


async def test_v1_consent_refuses_measures_but_keeps_entries_and_insights(client):
    patient = ClientEmulator("h14-v1", "deep-password")
    await patient.register(client)
    await seed_corpus(client, patient, days=32)
    await patient.recompute(client)
    assert (await _record_measure(patient, client, "h14-m", 12, TODAY)).status_code == 201
    th = TherapistEmulator("h14-dr", "pw", "Dr. Legacy")
    await th.register(client)
    consent = await _grant_share(client, patient, th)

    # Simulate the legacy population: a live grant recorded under the v1
    # disclosure, before the copy named measures.
    app = client._transport.app  # noqa: SLF001
    async with app.state.sessionmaker() as session:
        await session.execute(
            update(Consent).where(Consent.id == consent.id).values(disclosure="v1")
        )
        await session.commit()

    entries = await client.get(
        f"/api/therapist/patients/{patient.user_id}/entries", headers=th.headers
    )
    assert entries.status_code == 200  # grandfathered for entries...
    insights_read = await client.get(
        f"/api/therapist/patients/{patient.user_id}/insights", headers=th.headers
    )
    assert insights_read.status_code == 200  # ...and insights

    refused = await client.get(
        f"/api/therapist/patients/{patient.user_id}/measures", headers=th.headers
    )
    assert refused.status_code == 409
    body = refused.json()
    assert body["code"] == "disclosure_outdated"
    # The meta block the mobile client branches on to offer re-consent.
    from app.api.consents import SHARING_DISCLOSURE_VERSION

    assert SHARING_DISCLOSURE_VERSION == "v2"
    assert body["meta"]["sharing_disclosure_version"] == SHARING_DISCLOSURE_VERSION
    # The refusal served no data — and wrote no audit row.
    assert "read_measures" not in [row.action for row in await _audit_rows(client)]

    # A fresh grant under the current disclosure restores the measures read.
    code = await th.create_pairing_code(client)
    lookup = await patient.pairing_lookup(client, code)
    regranted = await patient.grant_consent(
        client, code, lookup["body"]["wrap_pub_key"], lookup["body"]["therapist_id"]
    )
    assert regranted["status"] == 201, regranted
    allowed = await client.get(
        f"/api/therapist/patients/{patient.user_id}/measures", headers=th.headers
    )
    assert allowed.status_code == 200
    assert [row["client_measure_id"] for row in allowed.json()] == ["h14-m"]


async def test_patient_list_is_audited_per_patient(client):
    """H-14: the list moves caseload summaries, so every listed patient
    leaves a list_patients access_log row."""
    patient = ClientEmulator("h14-list", "deep-password")
    await patient.register(client)
    th = TherapistEmulator("h14-list-dr", "pw")
    await th.register(client)
    await _grant_share(client, patient, th)

    listed = await client.get("/api/therapist/patients", headers=th.headers)
    assert listed.status_code == 200
    rows = [row for row in await _audit_rows(client) if row.action == "list_patients"]
    assert [(row.actor_id, row.user_id, row.actor_role) for row in rows] == [
        (th.user_id, patient.user_id, "therapist")
    ]


# --- H-16: summary phase gate + therapist state_seq ----------------------------


async def _summary_patient(client, username: str) -> tuple[ClientEmulator, TherapistEmulator]:
    patient = ClientEmulator(username, "deep-password")
    await patient.register(client)
    await seed_corpus(client, patient, days=32)
    th = TherapistEmulator(f"{username}-dr", "pw")
    await th.register(client)
    await _grant_share(client, patient, th)
    # Recompute AFTER the grant: this is the run that wraps the caseload
    # summary to the therapist's public key.
    await patient.recompute(client)
    return patient, th


async def test_list_suppresses_summary_when_patient_leaves_insight_phase(client):
    patient, th = await _summary_patient(client, "h16-summary")
    listed = (await client.get("/api/therapist/patients", headers=th.headers)).json()
    row = next(r for r in listed if r["user_id"] == patient.user_id)
    assert row["summary_blob"] is not None  # insight-phase: summary served

    # Delete the journal below the threshold: the stored summary must stop
    # being served (nothing is revealed below the threshold, including
    # stored leftovers — the same gate as every patterns read).
    for day in daterange(32, TODAY):
        for prefix in ("c-", "w-"):
            deleted = await client.delete(
                f"/api/entries/{prefix}{day.isoformat()}", headers=patient.headers
            )
            assert deleted.status_code in (204, 404), deleted.text

    relisted = (await client.get("/api/therapist/patients", headers=th.headers)).json()
    row = next(r for r in relisted if r["user_id"] == patient.user_id)
    # The grant is still active (key material survives)...
    assert row["wrapped_key"] is not None
    # ...but the summary is gated off, exactly like the blob reads.
    assert row["summary_blob"] is None
    assert row["summary_eph_pub"] is None
    assert row["summary_updated_at"] is None


async def test_therapist_insights_reports_stored_state_seq(client):
    patient, th = await _summary_patient(client, "h16-seq")
    mine = (await client.get("/api/insights", headers=patient.headers)).json()
    theirs = (
        await client.get(f"/api/therapist/patients/{patient.user_id}/insights", headers=th.headers)
    ).json()
    assert mine["state_seq"] >= 1
    assert theirs["state_seq"] == mine["state_seq"]


# --- M-2 / M-3: the in-fence re-authorization includes token_epoch -------------


class _EpochSession:
    """Serves one user row (the DB truth) for the in-fence session.get()."""

    def __init__(self, user: User):
        self._user = user

    async def get(self, _model, _user_id, *, populate_existing=False):
        return self._user

    async def execute(self, statement):
        raise AssertionError("the epoch re-check must fire before any corpus query")


def _request(state: SimpleNamespace) -> SimpleNamespace:
    return SimpleNamespace(app=SimpleNamespace(state=state))


async def test_recompute_refuses_a_pre_logout_bearer_after_the_fence(monkeypatch):
    """M-2: the bearer authenticated at epoch 1; logout bumped the row to
    epoch 2 while the recompute waited on the lifecycle fence. The in-fence
    re-check must fail closed (401) before decrypting anything."""
    state = SimpleNamespace(
        settings=SimpleNamespace(unlock_threshold_days=1),
        key_store=SimpleNamespace(pop=lambda *_a, **_k: bytearray(crypto.KEY_SIZE)),
    )

    @asynccontextmanager
    async def sessionmaker():
        yield _EpochSession(_user("m2-user", epoch=2))

    state.sessionmaker = sessionmaker

    async def dates(_session, _user_id):
        return [TODAY]

    monkeypatch.setattr(insights_api, "_entry_dates", dates)
    with pytest.raises(ApiError) as excinfo:
        await insights_api.recompute(
            _request(state),
            _user("m2-user", epoch=1),  # what require_user authenticated
            "session-token",
        )
    assert excinfo.value.status_code == 401
    assert excinfo.value.code == "unauthorized"


async def test_create_measure_refuses_a_pre_logout_bearer_after_the_fence():
    """M-3: same invariant on the measures write path — the duplicate and
    quota queries must never run for a retired bearer."""
    body = measures_api.MeasureCreate(
        client_measure_id="m3-measure",
        blob=base64.b64encode(b"x" * 64).decode(),
        measure_date=TODAY,
    )
    request = _request(SimpleNamespace(settings=SimpleNamespace()))
    with pytest.raises(ApiError) as excinfo:
        await measures_api.create_measure(
            body=body,
            request=request,
            user=_user("m3-user", epoch=1),
            session=_EpochSession(_user("m3-user", epoch=2)),
        )
    assert excinfo.value.status_code == 401
    assert excinfo.value.code == "unauthorized"


# --- M-4: deterministic offset paging on both measure read paths ----------------


async def test_measures_page_deterministically_on_both_paths(client):
    assert measures_api.MEASURE_PAGE_LIMIT == 500

    emu = ClientEmulator("m4-page", "deep-password")
    await emu.register(client)
    await emu.backdate_account(client, days=40)
    th = TherapistEmulator("m4-dr", "pw")
    await th.register(client)
    for offset in range(4):
        assert (await _record_measure(emu, client, f"m4-a-{offset}", 5, TODAY)).status_code == 201
    for offset in range(3):
        assert (
            await _record_measure(emu, client, f"m4-b-{offset}", 6, TODAY - timedelta(days=5))
        ).status_code == 201

    collected: list[dict] = []
    offset = 0
    while True:
        page = (
            await client.get(
                "/api/measures", headers=emu.headers, params={"limit": 3, "offset": offset}
            )
        ).json()
        assert page, "a short page must end the walk, never an empty repeat"
        collected.extend(page)
        if len(page) < 3:
            break
        offset += 3
    assert len(collected) == 7
    dates = [row["measure_date"] for row in collected]
    assert dates == sorted(dates, reverse=True)  # newest completion first
    # All four same-day rows survive the walk (the id tiebreaker keeps
    # same-second rows stably ordered across pages).
    assert len([r for r in collected if r["measure_date"] == TODAY.isoformat()]) == 4

    await _grant_share(client, emu, th)
    mirror: list[dict] = []
    offset = 0
    while True:
        page = (
            await client.get(
                f"/api/therapist/patients/{emu.user_id}/measures",
                headers=th.headers,
                params={"limit": 2, "offset": offset},
            )
        ).json()
        assert page
        mirror.extend(page)
        if len(page) < 2:
            break
        offset += 2
    # The therapist mirror walks the SAME deterministic order.
    assert [r["id"] for r in mirror] == [r["id"] for r in collected]


# --- M-5: the enricher branch keeps muted cards ---------------------------------


class _EchoEnricher:
    """A stand-in enricher that 'narrates' nothing (returns findings as-is):
    its mere presence selects the LLM merge branch under test."""

    name = "llm"
    last_error = None

    def extract_patterns(self, _entries, findings=None):
        return list(findings or [])


async def test_enricher_branch_keeps_muted_cards_behind_the_cap(client, monkeypatch):
    from app.services import brain

    emu = ClientEmulator("m5-mute", "deep-password")
    await emu.register(client)
    await seed_corpus(client, emu, days=32)
    # Two recompute days: the replication gate needs an independent second
    # observation before statistical kinds surface.
    await emu.recompute(client)

    class NextDay(date):
        @classmethod
        def today(cls) -> date:
            return date.today() + timedelta(days=1)

    monkeypatch.setattr(insights_api, "date_type", NextDay)
    await emu.recompute(client)
    monkeypatch.undo()

    payload = await emu.decrypt_insights(client)
    patterns = payload["stats"]["patterns"]
    assert len(patterns) >= 2, "the corpus must surface several cards for the cap to bite"
    victim = next(p for p in patterns if p["detail"].get("pattern_pid"))
    pid = victim["detail"]["pattern_pid"]

    # Mute one card through the encrypted feedback channel, then recompute
    # WITH an enricher present and the surfaced cap squeezed to ONE unmuted
    # card — the old flat [:MAX_SURFACED] slice removed exactly the muted
    # cards (the brain appends them last).
    feedback = crypto.encrypt(
        emu.data_key,
        json.dumps({"feedback": [], "muted": [pid]}).encode("utf-8"),
        crypto.build_aad("feedback", emu.user_id or "", insights_api._utc_today().isoformat()),
    )
    monkeypatch.setattr(insights_api.llm, "get_enricher", lambda *_a, **_k: _EchoEnricher())
    monkeypatch.setattr(brain, "MAX_SURFACED", 1)
    token = await emu.open_processing_session(client)
    recompute = await client.post(
        "/api/insights/recompute",
        headers={**emu.headers, "X-Processing-Token": token},
        json={"feedback_blob": base64.b64encode(feedback).decode("ascii")},
    )
    assert recompute.status_code == 200, recompute.text
    assert recompute.json()["analyzer"] == "llm"

    payload = await emu.decrypt_insights(client)
    stored = payload["stats"]["patterns"]
    unmuted = [p for p in stored if not p["detail"].get("muted")]
    muted = [p for p in stored if p["detail"].get("muted")]
    assert len(unmuted) == 1  # the cap applies to the UNMUTED portion only
    assert muted, "the muted card (and its unmute affordance) must survive enrichment"
    assert any(p["detail"].get("pattern_pid") == pid for p in muted)
    # Response counters describe the FINAL stored list (M-5's second half).
    assert recompute.json()["patterns_stored"] == len(stored)
    # …including the new/fading counts, pinned against the decrypted
    # payload itself: pre-fix they described the brain's pre-merge set and
    # could count patterns the client never received.
    assert recompute.json()["patterns_new"] == sum(1 for p in stored if p["detail"].get("is_new"))
    assert recompute.json()["patterns_fading"] == sum(
        1 for p in stored if p["detail"].get("pattern_state") == "fading"
    )


# --- M-11: the phase is re-evaluated inside the fence ---------------------------


async def test_recompute_rechecks_phase_inside_the_fence(monkeypatch):
    """Entries deleted while the recompute waited on the fence drop the
    account back to baseline: nothing may be decrypted or stored."""
    answers = [
        [TODAY - timedelta(days=i) for i in range(30)],  # pre-fence read: insight
        [TODAY - timedelta(days=i) for i in range(5)],  # in-fence re-read: baseline
    ]

    async def dates(_session, _user_id):
        return answers.pop(0)

    executed: list[str] = []

    class _Session:
        async def get(self, _model, _user_id, *, populate_existing=False):
            return _user("m11-user", epoch=1)

        async def execute(self, statement):
            executed.append(str(statement))
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: []))

    @asynccontextmanager
    async def sessionmaker():
        yield _Session()

    state = SimpleNamespace(
        settings=SimpleNamespace(unlock_threshold_days=30),
        key_store=SimpleNamespace(pop=lambda *_a, **_k: bytearray(crypto.KEY_SIZE)),
        sessionmaker=sessionmaker,
    )
    monkeypatch.setattr(insights_api, "_entry_dates", dates)

    response = await insights_api.recompute(
        _request(state), _user("m11-user", epoch=1), "session-token"
    )
    assert response.phase == "baseline"
    assert response.patterns_stored == 0
    assert response.question_stored is False
    assert response.analyzer == "none"
    # Only the authorization read ran — no corpus/blob SELECT escaped the
    # fence after the phase collapsed.
    assert executed == []


# --- M-30: audit rows survive post-fetch 409 paths ------------------------------


async def _seeded_share(client, username: str) -> tuple[ClientEmulator, TherapistEmulator]:
    patient = ClientEmulator(username, "deep-password")
    await patient.register(client)
    await seed_corpus(client, patient, days=32)
    th = TherapistEmulator(f"{username}-dr", "pw")
    await th.register(client)
    await _grant_share(client, patient, th)
    return patient, th


async def test_entries_read_audit_survives_a_collection_changed_409(client, monkeypatch):
    """The revision moved after the blob fetch: the page 409s, but the
    access record for the ciphertext the server DID fetch must survive."""
    from app.api import therapist as therapist_module

    patient, th = await _seeded_share(client, "m30-entries")
    real_revision = therapist_module.current_entries_revision
    calls = {"n": 0}

    async def moving_revision(session, user_id):
        calls["n"] += 1
        revision = await real_revision(session, user_id)
        return revision + (1 if calls["n"] > 1 else 0)

    monkeypatch.setattr(therapist_module, "current_entries_revision", moving_revision)
    refused = await client.get(
        f"/api/therapist/patients/{patient.user_id}/entries", headers=th.headers
    )
    monkeypatch.undo()
    assert refused.status_code == 409, refused.text

    rows = [row for row in await _audit_rows(client) if row.action == "read_entries"]
    assert rows, "the audit row must survive the post-fetch 409"
    assert rows[-1].user_id == patient.user_id


async def test_notes_read_audit_survives_a_collection_changed_409(client, monkeypatch):
    from app.api import therapist as therapist_module

    patient, th = await _seeded_share(client, "m30-notes")
    created = await client.post(
        f"/api/therapist/patients/{patient.user_id}/notes",
        headers=th.headers,
        json={
            "client_note_id": "m30-note",
            "pattern_pid": None,
            "blob": th.encrypt_note(patient, "m30-note", "session note text"),
        },
    )
    assert created.status_code == 201, created.text

    real_revision = therapist_module._current_notes_revision
    calls = {"n": 0}

    async def moving_revision(session, therapist_id):
        calls["n"] += 1
        revision = await real_revision(session, therapist_id)
        return revision + (1 if calls["n"] > 1 else 0)

    monkeypatch.setattr(therapist_module, "_current_notes_revision", moving_revision)
    refused = await client.get(
        f"/api/therapist/patients/{patient.user_id}/notes", headers=th.headers
    )
    monkeypatch.undo()
    assert refused.status_code == 409, refused.text

    rows = [row for row in await _audit_rows(client) if row.action == "read_notes"]
    assert rows, "the audit row must survive the post-fetch 409"
    assert rows[-1].user_id == patient.user_id


# --- L-5: date bounds follow the server-UTC calendar ----------------------------


async def test_entry_and_measure_date_bounds_use_server_utc(monkeypatch):
    """A frozen clock three days AHEAD of the real calendar proves the bound
    consults datetime.now(timezone.utc), not the host-local date.today():
    under the fake clock, real_today+2 is within "utc-today + 1" grace,
    while a local-today reading would reject it."""
    from app.api import entries as entries_api

    real_today = datetime.now(timezone.utc).date()
    fake_now = datetime.combine(
        real_today + timedelta(days=3), datetime.min.time(), tzinfo=timezone.utc
    )

    class _FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return fake_now

    monkeypatch.setattr(entries_api, "datetime", _FrozenDatetime)
    monkeypatch.setattr(measures_api, "datetime", _FrozenDatetime)

    user = _user("l5-user", epoch=1)
    edge_ok = real_today + timedelta(days=2)  # == fake_utc_today - 1
    entries_api._validate_entry_date(edge_ok, user)
    measures_api._validate_measure_date(edge_ok, user)
    with pytest.raises(ApiError):
        entries_api._validate_entry_date(real_today + timedelta(days=5), user)
    with pytest.raises(ApiError):
        measures_api._validate_measure_date(real_today + timedelta(days=5), user)


# --- L-6: duplicate detection wins over the quota check -------------------------


class _QuotaBoundarySession:
    """Duplicate present AND the quota exhausted: the 409 must win."""

    bind = SimpleNamespace(dialect=SimpleNamespace(name="sqlite"))

    def __init__(self, user: User):
        self.user = user

    async def get(self, _model, _user_id, *, populate_existing=False):
        return self.user

    async def execute(self, statement):
        if "measure" in str(statement).lower() and "client_measure_id" in str(statement):
            return SimpleNamespace(scalar_one_or_none=lambda: "existing-row-id")
        raise AssertionError(f"quota query must not run when the duplicate wins: {statement}")

    def add(self, row):
        pass

    async def commit(self):
        raise AssertionError("no insert may happen for an idempotent retry")

    async def rollback(self):
        pass


async def test_duplicate_retry_at_quota_boundary_answers_conflict_not_quota():
    """Measures (and entries — see test_api_resilience_coverage) must answer
    409 for an already-stored client id even at the quota boundary, so an
    offline queue can tell 'already applied' from 'genuinely full'."""
    user = _user("l6-user", epoch=1)
    body = measures_api.MeasureCreate(
        client_measure_id="l6-dup",
        blob=base64.b64encode(b"x" * 64).decode(),
        measure_date=TODAY,
    )
    with pytest.raises(ApiError) as excinfo:
        await measures_api.create_measure(
            body=body,
            request=_request(SimpleNamespace(settings=SimpleNamespace())),
            user=user,
            session=_QuotaBoundarySession(user),
        )
    assert excinfo.value.status_code == 409
    assert excinfo.value.code == "conflict"


# --- L-7: measures uses the entries error envelope -------------------------------


async def test_measure_error_envelope_matches_entries(client):
    emu = ClientEmulator("l7-envelope", "deep-password")
    await emu.register(client)
    not_b64 = await client.post(
        "/api/measures",
        headers=emu.headers,
        json={
            "client_measure_id": "l7-a",
            "blob": "!!not base64!!",
            "measure_date": TODAY.isoformat(),
        },
    )
    assert not_b64.status_code == 422
    assert not_b64.json()["code"] == "validation_error"

    too_small = await client.post(
        "/api/measures",
        headers=emu.headers,
        json={
            "client_measure_id": "l7-b",
            "blob": base64.b64encode(b"tiny").decode(),
            "measure_date": TODAY.isoformat(),
        },
    )
    assert too_small.status_code == 422
    assert too_small.json()["code"] == "validation_error"


# --- L-12: a note insert losing its patient is a 404 ----------------------------


class _FkCommitSession:
    """Serves the create_note query ladder, then fails the note commit
    with a FOREIGN KEY violation (the patient row vanished mid-request).

    2026-09-26: the ladder changed twice — the pre-lock read transaction
    now COMMITS before queueing on the chart lock (LOW, batch item b),
    and the quota aggregate returns FOUR columns (audit H-6: live notes
    plus revision rows/bytes). The first commit (the read release)
    succeeds; the note commit raises the FK error the pin exercises."""

    bind = SimpleNamespace(dialect=SimpleNamespace(name="sqlite"))

    def __init__(self):
        self.executions = 0
        self.commits = 0
        self.rolled_back = False
        self.added = []

    async def execute(self, statement):
        self.executions += 1
        text = str(statement).lower()
        if "consent" in text and "therapist_id" in text:
            return SimpleNamespace(
                scalars=lambda: SimpleNamespace(first=lambda: SimpleNamespace(user_id="l12-gone"))
            )
        if self.executions == 2:  # duplicate pre-check
            return SimpleNamespace(scalars=lambda: SimpleNamespace(first=lambda: None))
        if "count" in text:  # note quota (live + revision aggregate)
            return SimpleNamespace(one=lambda: (0, 0, 0, 0))
        return SimpleNamespace(rowcount=1)  # notes revision increment

    async def scalar(self, _statement):
        return 0

    async def refresh(self, *_a, **_k):
        pass

    def add(self, row):
        self.added.append(row)

    async def commit(self):
        self.commits += 1
        if self.commits == 1:
            return  # the pre-lock read-release commit (LOW batch item b)
        raise IntegrityError("INSERT", {}, Exception("foreign key constraint failed"))

    async def rollback(self):
        self.rolled_back = True


async def test_note_fk_violation_is_not_a_conflict():
    """The patient account vanished between the consent read and the commit:
    404 (the pair no longer exists), never 409 'already exists'."""
    from app.api import therapist as therapist_module

    therapist = _user("l12-therapist", epoch=1)
    therapist.role = "therapist"
    session = _FkCommitSession()
    body = therapist_module.NoteCreateRequest(
        client_note_id="l12-note", pattern_pid=None, blob=base64.b64encode(b"y" * 64).decode()
    )
    with pytest.raises(ApiError) as excinfo:
        await therapist_module.create_note(
            body=body, user_id="l12-gone", user=therapist, session=session
        )
    assert excinfo.value.status_code == 404
    assert excinfo.value.code == "not_found"
    assert session.rolled_back is True


# --- L-27 / L-28 / L-29: schema strictness ---------------------------------------


async def test_request_models_reject_unknown_fields(client):
    emu = ClientEmulator("l27-strict", "deep-password")
    await emu.register(client)
    # A mistyped field must be a 422, not a silently-dropped value.
    note = await client.post(
        "/api/entries",
        headers=emu.headers,
        json={
            "client_entry_id": "l27-e",
            "blob": base64.b64encode(b"z" * 64).decode(),
            "entry_date": TODAY.isoformat(),
            "entry_dat": TODAY.isoformat(),  # typo: silently dropped before L-27
        },
    )
    assert note.status_code == 422


async def test_display_name_rejects_control_and_bidi_characters(client):
    th = TherapistEmulator("l28-display", "pw")
    await th.register(client)
    base_body = {
        "salt": th.salt_b64,
        "verifier": th.auth_key_b64,
        "wrap_pub_key": th.wrap_pub_key,
        "wrap_key_blob": th.wrap_key_blob_b64(),
    }
    hostile_names = [
        "Dr. \u202eevil",  # RTL override: re-renders the name on screen
        "Dr.\u200fOmega",  # RTL mark
        "Dr.\u200bZero",  # zero-width space: invisible padding
        "Dr.\u2028Split",  # line separator
        "Dr.\x0bOmega",  # vertical-tab control character
        "Dr.\ufeffOmega",  # BOM
        "Dr.\u2066Omega",  # bidi isolate
    ]
    for index, display_name in enumerate(hostile_names):
        response = await client.post(
            "/api/therapist/register",
            json={**base_body, "username": f"l28-bad-{index}", "display_name": display_name},
        )
        assert response.status_code == 422, display_name
    # Ordinary names — accents, CJK, punctuation — still pass.
    ok = await client.post(
        "/api/therapist/register",
        json={**base_body, "username": "l28-ok", "display_name": "Dra. Omega-Çelik 小林"},
    )
    assert ok.status_code == 201, ok.text


async def test_empty_pattern_pid_is_rejected(client):
    patient = ClientEmulator("l29-pid", "deep-password")
    await patient.register(client)
    th = TherapistEmulator("l29-dr", "pw")
    await th.register(client)
    await _grant_share(client, patient, th)
    created = await client.post(
        f"/api/therapist/patients/{patient.user_id}/notes",
        headers=th.headers,
        # "" used to coerce to the NULL "general note" semantics silently.
        json={
            "client_note_id": "l29-note",
            "pattern_pid": "",
            "blob": th.encrypt_note(patient, "l29-note", "text"),
        },
    )
    assert created.status_code == 422
    assert created.json()["code"] == "validation_error"
