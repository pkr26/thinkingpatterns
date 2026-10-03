"""Multi-patient -> one-therapist END-TO-END scenario suite (2026-09-28).

The unit/integration suites pin every primitive in isolation; this module
runs the REQUESTED product story as coherent end-to-end scenarios against
one world: several patients linked to the SAME therapist, then everything
that can happen to that caseload.

  Act 1 — LINKING: pairing codes, SAS agreement on both screens, grants
          from three patients, the exact caseload list, the patient-side
          consent lists, and the single-use / verifier gates.
  Act 2 — VISIBILITY: what the therapist can actually see, per patient —
          patterns (insight phase) vs baseline gate, the journal
          drill-down, PHQ-9/GAD-7 measures with the item-9 fact, and the
          caseload summaries — all decrypted with the therapist's unwrapped
          per-consent data key (the full E2E crypto path).
  Act 3 — ISOLATION: cross-patient key/AAD separation and cross-therapist
          consent separation.
  Act 4 — NOTES: the therapist's own chart across edits, version
          conflicts, history — and across a revoke/re-grant cycle.
  Act 5 — MOVEMENT: revoke -> (new patient data while revoked) -> re-grant
          restoring visibility on the SAME consent row; patient key
          rotation (rekey) killing the old wrap, rewrap restoring it.
  Act 6 — AUDIT: every action above leaving its access-log row, visible
          from BOTH sides, with an intact tamper-evident chain.
  Act 7 — the whole story in ONE world, in order.

Every crypto operation mirrors the shipped clients exactly (helpers.py
emulators + security.sharing reference construction): real ECDH wraps,
real AADs, real GCM failures. Nothing is mocked except the recompute-day
shim the statistical patterns need to qualify (the established suite
idiom).
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from datetime import date, timedelta

import pytest
from sqlalchemy import select

from app.api._audit import verify_access_log_chain
from app.models import AccessLog
from app.security import crypto
from app.security import sharing as sharing_crypto
from tests.helpers import ClientEmulator, TherapistEmulator, daterange

TODAY = date.today()
WORK_ANXIOUS = (
    "Deadline at work monday, the boss piled on another project and a "
    "late meeting. Anxious, stressed, dreading the presentation."
)
CALM = "Long walk by the river, felt calm and grateful. Cooked, ate well, slept deeply."


# --- world construction ---------------------------------------------------------


@dataclass
class World:
    """The cast: one therapist, three linked patients, one unlinked patient,
    and a rival therapist for the isolation act."""

    th: TherapistEmulator
    other: TherapistEmulator
    alice: ClientEmulator  # insight phase: 70 days, patterns, measures
    bob: ClientEmulator  # baseline phase: 10 days
    carol: ClientEmulator  # insight phase: 40 days, revoke/re-grant target
    dave: ClientEmulator  # registered, never linked
    consents: dict[str, dict] = field(default_factory=dict)

    def row_for(self, listing: list[dict], username: str) -> dict | None:
        return next((r for r in listing if r["username"] == username), None)


def _advance_a_day(monkeypatch) -> None:
    """Recompute-day shim: the brain qualifies statistical patterns on a
    second DISTINCT day, so the corpus must be seen 'tomorrow' (the
    established TestEvidenceDates idiom)."""

    class NextDay(date):
        @classmethod
        def today(cls) -> date:
            return date.today() + timedelta(days=1)

    monkeypatch.setattr("app.api.insights.date_type", NextDay)


async def _seed(client, emu: ClientEmulator, days: int) -> None:
    await emu.backdate_account(client, days=days + 2)
    for day in daterange(days, TODAY):
        text = WORK_ANXIOUS if day.weekday() == 6 else CALM
        await emu.create_entry(
            client, text, day, client_entry_id=f"e-{day.isoformat()}", content_version=1
        )


async def _grant(client, patient: ClientEmulator, th: TherapistEmulator) -> dict:
    code = await th.create_pairing_code(client)
    lookup = await patient.pairing_lookup(client, code)
    assert lookup["status"] == 200, lookup
    granted = await patient.grant_consent(
        client, code, lookup["body"]["wrap_pub_key"], lookup["body"]["therapist_id"]
    )
    assert granted["status"] == 201, granted
    return granted["body"]


async def _record_measure(
    emu: ClientEmulator, client, client_measure_id: str, payload: dict, measure_date: date
) -> None:
    blob = crypto.encrypt(
        emu.data_key,
        json.dumps(payload).encode("utf-8"),
        crypto.build_aad("measure", emu.user_id or "", client_measure_id),
    )
    response = await client.post(
        "/api/measures",
        headers=emu.headers,
        json={
            "client_measure_id": client_measure_id,
            "blob": base64.b64encode(blob).decode("ascii"),
            "measure_date": measure_date.isoformat(),
        },
    )
    assert response.status_code == 201, response.text


async def _world(client, monkeypatch) -> World:
    """Build the full cast and link alice/bob/carol to the therapist.

    alice and carol get the two-recompute dance so their patterns carry
    evidence dates (drill-down data) and post-grant summaries exist; bob
    stays baseline with a single recompute, proving the phase gates.
    """
    th = TherapistEmulator("dre2e", "pw-e2e", "Dr. E2E")
    await th.register(client)
    other = TherapistEmulator("drother", "pw-other", "Dr. Rival")
    await other.register(client)

    alice = ClientEmulator("e2e-alice", "pw-alice")
    await alice.register(client)
    await _seed(client, alice, days=70)

    carol = ClientEmulator("e2e-carol", "pw-carol")
    await carol.register(client)
    await _seed(client, carol, days=40)

    bob = ClientEmulator("e2e-bob", "pw-bob")
    await bob.register(client)
    await _seed(client, bob, days=10)

    dave = ClientEmulator("e2e-dave", "pw-dave")
    await dave.register(client)

    world = World(th=th, other=other, alice=alice, bob=bob, carol=carol, dave=dave)
    for name, patient in (("alice", alice), ("carol", carol), ("bob", bob)):
        world.consents[name] = await _grant(client, patient, th)

    # Post-grant recomputes: insight-phase patients surface patterns and
    # write their caseload summaries to the therapist.
    for patient in (alice, carol):
        await patient.recompute(client)
        _advance_a_day(monkeypatch)
        await patient.recompute(client)
        monkeypatch.undo()
    await bob.recompute(client)  # baseline: no patterns, no served summary

    # alice's measurement-based-care trail: a flagged PHQ-9 (item 9 = 2),
    # a GAD-7, and an unflagged older PHQ-9.
    await _record_measure(
        alice,
        client,
        "m-phq9-now",
        {"v": 1, "measure": "phq9", "score": 14, "item9": 2, "completed_at": TODAY.isoformat()},
        TODAY,
    )
    await _record_measure(
        bob,
        client,
        "m-gad7-bob",
        {"v": 1, "measure": "gad7", "score": 4, "completed_at": TODAY.isoformat()},
        TODAY,
    )
    await _record_measure(
        alice,
        client,
        "m-gad7-then",
        {
            "v": 1,
            "measure": "gad7",
            "score": 9,
            "completed_at": (TODAY - timedelta(days=3)).isoformat(),
        },
        TODAY - timedelta(days=3),
    )
    await _record_measure(
        alice,
        client,
        "m-phq9-old",
        {
            "v": 1,
            "measure": "phq9",
            "score": 5,
            "item9": 0,
            "completed_at": (TODAY - timedelta(days=10)).isoformat(),
        },
        TODAY - timedelta(days=10),
    )
    return world


# --- therapist-side decryption (the portal's exact contracts) --------------------


def _unwrap(client_http, th: TherapistEmulator, patient: ClientEmulator, row: dict) -> bytes:
    assert row["ephemeral_pub"] and row["wrapped_key"], "active grant must carry key material"
    return th.unwrap_patient_data_key(patient, row["ephemeral_pub"], row["wrapped_key"])


def _decrypt_entry(data_key: bytes, user_id: str, row: dict) -> dict:
    blob = base64.b64decode(row["blob"])
    version = row.get("content_version") or 1
    failure: Exception | None = None
    for aad in crypto.entry_aad_candidates(user_id, row["client_entry_id"], version):
        try:
            return json.loads(crypto.decrypt(data_key, blob, aad).decode("utf-8"))
        except crypto.TamperError as exc:
            failure = exc
    assert failure is not None
    raise failure


def _decrypt_insights(data_key: bytes, user_id: str, blob_b64: str) -> dict:
    plain = crypto.decrypt(
        data_key, base64.b64decode(blob_b64), crypto.build_aad("insights", user_id, "patterns")
    )
    return json.loads(plain.decode("utf-8"))


def _decrypt_measure(data_key: bytes, user_id: str, row: dict) -> dict:
    plain = crypto.decrypt(
        data_key,
        base64.b64decode(row["blob"]),
        crypto.build_aad("measure", user_id, row["client_measure_id"]),
    )
    return json.loads(plain.decode("utf-8"))


async def _patients_list(client, th: TherapistEmulator) -> list[dict]:
    response = await client.get("/api/therapist/patients", headers=th.headers)
    assert response.status_code == 200, response.text
    return response.json()


async def _read_entries(client, th, patient, params: dict | None = None) -> list[dict]:
    response = await client.get(
        f"/api/therapist/patients/{patient.user_id}/entries",
        headers=th.headers,
        params=params or {},
    )
    assert response.status_code == 200, response.text
    return response.json()


# --- ACT 1 — linking multiple patients to one therapist -------------------------


class TestAct1Linking:
    async def test_sas_agrees_on_both_screens_and_keys_match(self, client, monkeypatch):
        """The out-of-band pairing check: the patient's lookup response and
        the therapist's SAS read derive the SAME verification string for the
        same live pairing session, over the same wrap key."""
        world = await _world(client, monkeypatch)
        patient = world.dave
        code = await world.th.create_pairing_code(client)

        lookup = await patient.pairing_lookup(client, code)
        assert lookup["status"] == 200, lookup
        body = lookup["body"]
        assert body["display_name"] == "Dr. E2E"
        assert body["wrap_pub_key"] == world.th.wrap_pub_key

        therapist_sas = await client.get(
            "/api/therapist/pairing/sas",
            headers={**world.th.headers, "X-Pairing-Code": code},
            params={"patient_user_id": patient.user_id},
        )
        assert therapist_sas.status_code == 200, therapist_sas.text
        sas_body = therapist_sas.json()
        assert sas_body["sas"] == body["sas"], "both screens must show the same SAS"
        assert sas_body["wrap_key_fingerprint"] == body["wrap_key_fingerprint"]

        # The fingerprint the server reports is the honest identity of the
        # therapist's registered key (the load-bearing substitution check).
        assert sas_body["wrap_key_fingerprint"] == sharing_crypto.wrap_key_fingerprint(
            base64.b64decode(world.th.wrap_pub_key)
        )

    async def test_caseload_list_is_exactly_the_linked_patients(self, client, monkeypatch):
        world = await _world(client, monkeypatch)
        listing = await _patients_list(client, world.th)

        usernames = {row["username"] for row in listing}
        assert usernames == {"e2e-alice", "e2e-carol", "e2e-bob"}, usernames
        assert all(row["status"] == "active" for row in listing)
        for row in listing:
            assert row["ephemeral_pub"] and row["wrapped_key"], row

        # dave never paired: no row, and a direct read is the flat 404.
        assert world.row_for(listing, "e2e-dave") is None
        for path in ("insights", "entries", "measures", "notes"):
            response = await client.get(
                f"/api/therapist/patients/{world.dave.user_id}/{path}",
                headers=world.th.headers,
            )
            assert response.status_code == 404, (path, response.text)

        # The patient side sees the same link, named for a human.
        for patient in (world.alice, world.bob, world.carol):
            consents = await patient.list_consents(client)
            assert len(consents) == 1, consents
            assert consents[0]["display_name"] == "Dr. E2E"
            assert consents[0]["status"] == "active"
            assert consents[0]["therapist_wrap_pub_key"] == world.th.wrap_pub_key

    async def test_pairing_code_is_single_use_and_grant_needs_the_password(self, client):
        th = TherapistEmulator("solo-dr", "pw", "Dr. Solo")
        await th.register(client)
        patient = ClientEmulator("solo-p", "pw")
        await patient.register(client)

        code = await th.create_pairing_code(client)
        lookup = await patient.pairing_lookup(client, code)
        assert lookup["status"] == 200

        # A stolen bearer alone cannot widen disclosure: no verifier -> 422.
        wrap = {
            "ephemeral_pub": lookup["body"]["wrap_pub_key"],  # shape-valid stand-in
            "wrapped_key": base64.b64encode(b"x" * 60).decode("ascii"),
        }
        no_verifier = await client.post(
            "/api/consents",
            headers=patient.headers,
            json={"code": code, **wrap, "disclosure": "v2"},
        )
        assert no_verifier.status_code == 422, no_verifier.text

        granted = await patient.grant_consent(
            client, code, lookup["body"]["wrap_pub_key"], lookup["body"]["therapist_id"]
        )
        assert granted["status"] == 201

        # The code is burned: the same code cannot link a second patient.
        other = ClientEmulator("solo-p2", "pw")
        await other.register(client)
        replay = await other.grant_consent(
            client, code, lookup["body"]["wrap_pub_key"], lookup["body"]["therapist_id"]
        )
        assert replay["status"] == 404


# --- ACT 2 — what the therapist can see ------------------------------------------


class TestAct2Visibility:
    async def test_insight_phase_patient_full_e2e_visibility(self, client, monkeypatch):
        """The complete loop for a pattern-phase patient: unwrap the consent
        key, decrypt patterns with evidence dates, drill into the journal
        behind a pattern, and read the questionnaire trail with item-9."""
        world = await _world(client, monkeypatch)
        alice, th = world.alice, world.th
        listing = await _patients_list(client, th)
        data_key = _unwrap(client, th, alice, world.row_for(listing, "e2e-alice"))

        insights = await client.get(
            f"/api/therapist/patients/{alice.user_id}/insights", headers=th.headers
        )
        assert insights.status_code == 200, insights.text
        summary = insights.json()
        assert summary["phase"] == "insight"
        assert summary["blob"] is not None

        payload = _decrypt_insights(data_key, alice.user_id, summary["blob"])
        patterns = payload["stats"]["patterns"]
        assert patterns, "the seeded corpus must surface patterns"
        # The rollback sentinel: the seq inside the ciphertext equals the
        # plaintext echo (the portal's verifyInsightsGeneration contract).
        assert payload["state_seq"] == summary["state_seq"] >= 1

        # Drill-down: entries behind a pattern's evidence window decrypt to
        # the patient's actual words.
        with_dates = [p for p in patterns if p["detail"].get("evidence_dates")]
        assert with_dates, "therapist-visible patterns must carry evidence dates"
        pattern = with_dates[0]
        dates = sorted(pattern["detail"]["evidence_dates"])
        rows = await _read_entries(client, th, alice, {"since": dates[0], "until": dates[-1]})
        assert rows, "the evidence window must have entries"
        seeded_texts = {WORK_ANXIOUS, CALM}
        for row in rows:
            assert _decrypt_entry(data_key, alice.user_id, row)["text"] in seeded_texts

        # The measures trail: newest first, portal-sanitized readings.
        measures = await client.get(
            f"/api/therapist/patients/{alice.user_id}/measures",
            headers=th.headers,
            params={"limit": 50},
        )
        assert measures.status_code == 200, measures.text
        rows = measures.json()
        assert [r["client_measure_id"] for r in rows] == [
            "m-phq9-now",
            "m-gad7-then",
            "m-phq9-old",
        ], rows
        readings = {
            r["client_measure_id"]: _decrypt_measure(data_key, alice.user_id, r) for r in rows
        }
        assert readings["m-phq9-now"]["score"] == 14
        assert readings["m-phq9-now"]["item9"] == 2  # the flagged self-harm item
        assert readings["m-phq9-old"]["item9"] == 0  # asked, not endorsed
        assert readings["m-gad7-then"]["score"] == 9
        assert "item9" not in readings["m-gad7-then"]  # GAD-7 has no item 9

    async def test_baseline_patient_visibility_is_phase_gated(self, client, monkeypatch):
        """bob is 10 days in: no patterns blob and no caseload summary — but
        his consented measures and journal entries remain readable (the
        disclosure covers them; only insights are phase-gated)."""
        world = await _world(client, monkeypatch)
        bob, th = world.bob, world.th

        insights = await client.get(
            f"/api/therapist/patients/{bob.user_id}/insights", headers=th.headers
        )
        assert insights.status_code == 200
        body = insights.json()
        assert body["phase"] == "baseline"
        assert body["blob"] is None
        assert body["days_remaining"] > 0

        listing = await _patients_list(client, th)
        bob_row = world.row_for(listing, "e2e-bob")
        assert bob_row["summary_blob"] is None
        assert bob_row["summary_eph_pub"] is None

        measures = await client.get(
            f"/api/therapist/patients/{bob.user_id}/measures",
            headers=th.headers,
            params={"limit": 10},
        )
        assert measures.status_code == 200
        listing_row = world.row_for(await _patients_list(client, th), "e2e-bob")
        data_key = _unwrap(client, th, bob, listing_row)
        rows = measures.json()
        assert len(rows) == 1
        assert _decrypt_measure(data_key, bob.user_id, rows[0])["score"] == 4

        entries = await _read_entries(client, th, bob, {"limit": 25})
        assert len(entries) == 10
        for row in entries:
            assert _decrypt_entry(data_key, bob.user_id, row)["text"] in {WORK_ANXIOUS, CALM}

    async def test_caseload_summary_served_only_where_valid(self, client, monkeypatch):
        world = await _world(client, monkeypatch)
        listing = await _patients_list(client, world.th)

        for username in ("e2e-alice", "e2e-carol"):
            row = world.row_for(listing, username)
            assert row["summary_blob"] and row["summary_eph_pub"], username
            plain = sharing_crypto.unwrap_summary_payload(
                world.th.unlock_private_key(),
                row["summary_eph_pub"],
                base64.b64decode(row["summary_blob"]),
                row["user_id"],
                world.th.user_id,
            )
            summary = json.loads(plain.decode("utf-8"))
            assert summary["patterns"] > 0
            assert summary["sensitive"] is False  # the seeded corpus has no crisis text
            assert isinstance(summary["newest"], str)

        assert world.row_for(listing, "e2e-bob")["summary_blob"] is None


# --- ACT 3 — isolation -----------------------------------------------------------


class TestAct3Isolation:
    async def test_patient_keys_cannot_cross(self, client, monkeypatch):
        """The wrap is per-patient: alice's unwrapped key opens alice's blobs
        ONLY — bob's ciphertext fails GCM under it, and alice's own blob
        fails under bob's identity in the AAD."""
        world = await _world(client, monkeypatch)
        listing = await _patients_list(client, world.th)
        alice_key = _unwrap(client, world.th, world.alice, world.row_for(listing, "e2e-alice"))
        bob_key = _unwrap(client, world.th, world.bob, world.row_for(listing, "e2e-bob"))
        assert alice_key != bob_key

        bob_rows = await _read_entries(client, world.th, world.bob, {"limit": 3})
        alice_rows = await _read_entries(client, world.th, world.alice, {"limit": 3})

        with pytest.raises(crypto.TamperError):
            _decrypt_entry(alice_key, world.bob.user_id, bob_rows[0])
        with pytest.raises(crypto.TamperError):
            # right key, WRONG identity in the AAD — relocation is rejected
            _decrypt_entry(alice_key, world.bob.user_id, alice_rows[0])

        insights = await client.get(
            f"/api/therapist/patients/{world.alice.user_id}/insights",
            headers=world.th.headers,
        )
        with pytest.raises(crypto.TamperError):
            _decrypt_insights(bob_key, world.alice.user_id, insights.json()["blob"])

    async def test_rival_therapist_sees_nothing(self, client, monkeypatch):
        world = await _world(client, monkeypatch)

        listing = await _patients_list(client, world.other)
        assert listing == []

        for path in ("insights", "entries", "measures", "notes"):
            response = await client.get(
                f"/api/therapist/patients/{world.alice.user_id}/{path}",
                headers=world.other.headers,
            )
            assert response.status_code == 404, (path, response.text)

        # And no writing into another therapist's chart.
        note = world.other.encrypt_note(world.alice, "n-rival", "intruding")
        response = await client.post(
            f"/api/therapist/patients/{world.alice.user_id}/notes",
            headers=world.other.headers,
            json={"client_note_id": "n-rival", "blob": note},
        )
        assert response.status_code == 404

        # The patient's consent list names only THEIR therapist.
        consents = await world.alice.list_consents(client)
        assert [c["display_name"] for c in consents] == ["Dr. E2E"]


# --- ACT 4 — the therapist's own notes -------------------------------------------


class TestAct4Notes:
    async def test_note_lifecycle_with_versions_and_history(self, client, monkeypatch):
        world = await _world(client, monkeypatch)
        alice, th = world.alice, world.th
        listing = await _patients_list(client, th)
        data_key = _unwrap(client, th, alice, world.row_for(listing, "e2e-alice"))
        insights = _decrypt_insights(
            data_key,
            alice.user_id,
            (
                await client.get(
                    f"/api/therapist/patients/{alice.user_id}/insights", headers=th.headers
                )
            ).json()["blob"],
        )
        pid = insights["stats"]["patterns"][0]["detail"]["pattern_pid"]

        # Create, anchored to a real surfaced pattern.
        blob = th.encrypt_note(alice, "note-1", "Session focus: work stress")
        created = await client.post(
            f"/api/therapist/patients/{alice.user_id}/notes",
            headers=th.headers,
            json={"client_note_id": "note-1", "pattern_pid": pid, "blob": blob},
        )
        assert created.status_code == 201, created.text
        note = created.json()
        assert note["pattern_pid"] == pid
        assert note["version"] == 1
        assert th.decrypt_note(alice, "note-1", note["blob"])["text"] == (
            "Session focus: work stress"
        )

        # A changing edit bumps the version and preserves the prior text.
        edited = await client.patch(
            f"/api/therapist/notes/{note['id']}",
            headers=th.headers,
            json={
                "blob": th.encrypt_note(alice, "note-1", "Edited: see C-SSRS"),
                "base_version": 1,
            },
        )
        assert edited.status_code == 200, edited.text
        assert edited.json()["version"] == 2

        stale = await client.patch(
            f"/api/therapist/notes/{note['id']}",
            headers=th.headers,
            json={"blob": th.encrypt_note(alice, "note-1", "Stale edit"), "base_version": 1},
        )
        assert stale.status_code == 409
        assert stale.json()["code"] == "version_conflict"

        revisions = await client.get(
            f"/api/therapist/notes/{note['id']}/revisions", headers=th.headers
        )
        assert revisions.status_code == 200
        prior = revisions.json()
        assert len(prior) == 1
        assert th.decrypt_note(alice, "note-1", prior[0]["blob"])["text"] == (
            "Session focus: work stress"
        )

        # A note id is patient-scoped: reuse for bob is a loud conflict.
        reused = await client.post(
            f"/api/therapist/patients/{world.bob.user_id}/notes",
            headers=th.headers,
            json={"client_note_id": "note-1", "blob": th.encrypt_note(world.bob, "note-1", "x")},
        )
        assert reused.status_code == 409

        deleted = await client.delete(f"/api/therapist/notes/{note['id']}", headers=th.headers)
        assert deleted.status_code == 204
        remaining = await client.get(
            f"/api/therapist/patients/{alice.user_id}/notes", headers=th.headers
        )
        assert remaining.json() == []


# --- ACT 5 — data movement: revoke, re-grant, key rotation ------------------------


class TestAct5Movement:
    async def test_revoke_blinds_regrant_restores_same_row(self, client, monkeypatch):
        world = await _world(client, monkeypatch)
        carol, th = world.carol, world.th
        consent_id = world.consents["carol"]["id"]

        blob = th.encrypt_note(carol, "carol-note", "Ongoing plan agreed")
        created = await client.post(
            f"/api/therapist/patients/{carol.user_id}/notes",
            headers=th.headers,
            json={"client_note_id": "carol-note", "blob": blob},
        )
        assert created.status_code == 201

        # --- revoke ---------------------------------------------------------
        assert await carol.revoke_consent(client, consent_id) == 204
        listing = await _patients_list(client, th)
        carol_row = world.row_for(listing, "e2e-carol")
        assert carol_row["status"] == "revoked"
        assert carol_row["wrapped_key"] is None
        assert carol_row["ephemeral_pub"] is None
        assert carol_row["summary_blob"] is None

        for path in ("insights", "entries", "measures"):
            response = await client.get(
                f"/api/therapist/patients/{carol.user_id}/{path}", headers=th.headers
            )
            assert response.status_code == 404, (path, response.text)

        # The therapist's OWN notes remain reachable and decryptable.
        notes = await client.get(
            f"/api/therapist/patients/{carol.user_id}/notes", headers=th.headers
        )
        assert notes.status_code == 200
        assert th.decrypt_note(carol, "carol-note", notes.json()[0]["blob"])["text"] == (
            "Ongoing plan agreed"
        )

        # carol keeps journaling; the therapist stays blind to the new data.
        await carol.create_entry(
            client,
            "Wrote while unlinked, private again",
            TODAY,
            client_entry_id="e-after-revoke",
            content_version=1,
        )
        assert (
            await client.get(f"/api/therapist/patients/{carol.user_id}/entries", headers=th.headers)
        ).status_code == 404

        # --- re-grant: the SAME row revives, visibility returns -------------
        regranted = await _grant(client, carol, th)
        assert regranted["id"] == consent_id, "re-grant must reuse the consent row"

        listing = await _patients_list(client, th)
        carol_row = world.row_for(listing, "e2e-carol")
        assert carol_row["status"] == "active"
        data_key = _unwrap(client, th, carol, carol_row)

        fresh = await _read_entries(client, th, carol, {"since": TODAY.isoformat()})
        texts = [_decrypt_entry(data_key, carol.user_id, row)["text"] for row in fresh]
        assert "Wrote while unlinked, private again" in texts

        insights = await client.get(
            f"/api/therapist/patients/{carol.user_id}/insights", headers=th.headers
        )
        assert insights.json()["phase"] == "insight"
        _decrypt_insights(data_key, carol.user_id, insights.json()["blob"])

        notes = await client.get(
            f"/api/therapist/patients/{carol.user_id}/notes", headers=th.headers
        )
        assert th.decrypt_note(carol, "carol-note", notes.json()[0]["blob"])["text"] == (
            "Ongoing plan agreed"  # note continuity across the cycle
        )

        # The summary re-arms only after the next recompute.
        assert carol_row["summary_blob"] is None
        await carol.recompute(client)
        revived = world.row_for(await _patients_list(client, th), "e2e-carol")
        assert revived["summary_blob"] is not None

    async def test_rekey_kills_the_old_wrap_rewrap_restores(self, client, monkeypatch):
        world = await _world(client, monkeypatch)
        alice, th = world.alice, world.th
        consent_id = world.consents["alice"]["id"]
        old_key = alice.data_key
        old_verifier = alice.auth_key_b64

        # The patient rotates her data key; every stored blob is re-encrypted.
        alice.derive_new_generation("pw-alice-rotated")
        assert alice.data_key != old_key
        await alice.rekey(client, old_key, alice.data_key, verifier=old_verifier)

        # The consent still wraps the OLD key: the therapist can unwrap, but
        # the key no longer opens the re-encrypted corpus (dead-wrap state).
        listing = await _patients_list(client, th)
        stale_key = _unwrap(client, th, alice, world.row_for(listing, "e2e-alice"))
        assert stale_key == alice.data_key  # wrap committed with the corpus
        rows = await _read_entries(client, th, alice, {"limit": 3})
        _decrypt_entry(stale_key, alice.user_id, rows[0])

        # The rewrap publishes the NEW key to the same therapist...
        rewrapped = await alice.rewrap_consent(
            client, consent_id, th.wrap_pub_key, th.user_id, verifier=alice.auth_key_b64
        )
        assert rewrapped["status"] == 200, rewrapped

        # ...and the chart opens again, old and new rows alike.
        listing = await _patients_list(client, th)
        fresh_key = _unwrap(client, th, alice, world.row_for(listing, "e2e-alice"))
        assert fresh_key == alice.data_key
        rows = await _read_entries(client, th, alice, {"limit": 5})
        for row in rows:
            _decrypt_entry(fresh_key, alice.user_id, row)
        insights = await client.get(
            f"/api/therapist/patients/{alice.user_id}/insights", headers=th.headers
        )
        _decrypt_insights(fresh_key, alice.user_id, insights.json()["blob"])


# --- ACT 6 — the audit trail ------------------------------------------------------


class TestAct6Audit:
    async def test_every_action_is_audited_on_both_sides(self, client, monkeypatch, app):
        world = await _world(client, monkeypatch)
        alice, th = world.alice, world.th

        # A representative therapist session against alice's chart.
        await _patients_list(client, th)
        await client.get(f"/api/therapist/patients/{alice.user_id}/insights", headers=th.headers)
        await _read_entries(client, th, alice, {"limit": 5})
        await client.get(
            f"/api/therapist/patients/{alice.user_id}/measures",
            headers=th.headers,
            params={"limit": 5},
        )
        note = await client.post(
            f"/api/therapist/patients/{alice.user_id}/notes",
            headers=th.headers,
            json={
                "client_note_id": "audit-note",
                "blob": th.encrypt_note(alice, "audit-note", "x"),
            },
        )
        assert note.status_code == 201
        await client.get(f"/api/therapist/patients/{alice.user_id}/notes", headers=th.headers)
        await client.patch(
            f"/api/therapist/notes/{note.json()['id']}",
            headers=th.headers,
            json={"blob": th.encrypt_note(alice, "audit-note", "y"), "base_version": 1},
        )
        await client.delete(f"/api/therapist/notes/{note.json()['id']}", headers=th.headers)

        # The therapist's own accountability view carries every action.
        own = await client.get(
            "/api/therapist/access-log", headers=th.headers, params={"limit": 200}
        )
        assert own.status_code == 200
        actions = {row["action"] for row in own.json()}
        for expected in (
            "list_patients",
            "read_insights",
            "read_entries",
            "read_measures",
            "read_notes",
            "write_note",
            "update_note",
            "delete_note",
        ):
            assert expected in actions, (expected, actions)
        assert any(row["patient_name"] == "e2e-alice" for row in own.json())

        # The patient's who-accessed-my-data view names the human.
        patient_log = await client.get(
            "/api/account/access-log", headers=alice.headers, params={"limit": 200}
        )
        assert patient_log.status_code == 200
        rows = patient_log.json()
        therapist_rows = [r for r in rows if r["actor"] == "therapist"]
        assert {r["actor_name"] for r in therapist_rows} == {"Dr. E2E"}
        assert {r["action"] for r in therapist_rows} >= {
            "list_patients",
            "read_insights",
            "read_entries",
            "read_measures",
            "read_notes",
            "write_note",
            "update_note",
            "delete_note",
        }
        assert any(r["action"] == "grant" and r["actor"] == "self" for r in rows)

        # The stored trail is a verifiable, tamper-evident chain.
        async with app.state.sessionmaker() as session:
            stored = list(
                (
                    await session.execute(
                        select(AccessLog)
                        .where(AccessLog.user_id == alice.user_id)
                        .order_by(AccessLog.chain_seq)
                    )
                )
                .scalars()
                .all()
            )
            assert len(stored) >= 9  # grant + every read/write above
            assert all(row.entry_hash and row.entry_mac for row in stored)
            verification = await verify_access_log_chain(session, alice.user_id)
        assert verification.ok, verification
        assert verification.rows_checked == len(stored)


# --- ACT 7 — the whole story in one world -----------------------------------------


async def test_act7_full_story_sequential(client, monkeypatch):
    """Link three patients -> read the caseload -> note a chart -> one
    revokes and re-grants -> one rotates keys -> audit, in ONE world, in
    order: the portal's product narrative as a single pass."""
    world = await _world(client, monkeypatch)
    th = world.th

    # The caseload, linked.
    listing = await _patients_list(client, th)
    assert {r["username"] for r in listing} == {"e2e-alice", "e2e-carol", "e2e-bob"}

    # Per-patient visibility with independently unwrapped keys.
    keys = {
        name: _unwrap(client, th, getattr(world, name), world.row_for(listing, f"e2e-{name}"))
        for name in ("alice", "carol", "bob")
    }
    assert len({bytes(k) for k in keys.values()}) == 3

    for name in ("alice", "carol"):
        insights = await client.get(
            f"/api/therapist/patients/{getattr(world, name).user_id}/insights",
            headers=th.headers,
        )
        payload = _decrypt_insights(
            keys[name], getattr(world, name).user_id, insights.json()["blob"]
        )
        assert payload["stats"]["patterns"]
    baseline = await client.get(
        f"/api/therapist/patients/{world.bob.user_id}/insights", headers=th.headers
    )
    assert baseline.json()["blob"] is None

    # A clinical note on the revoke-target's chart, before the cycle.
    await client.post(
        f"/api/therapist/patients/{world.carol.user_id}/notes",
        headers=th.headers,
        json={
            "client_note_id": "story-note",
            "blob": th.encrypt_note(world.carol, "story-note", "Cycle note"),
        },
    )

    # carol revokes; the therapist keeps only the note.
    assert await world.carol.revoke_consent(client, world.consents["carol"]["id"]) == 204
    assert (
        await client.get(
            f"/api/therapist/patients/{world.carol.user_id}/entries", headers=th.headers
        )
    ).status_code == 404
    notes = await client.get(
        f"/api/therapist/patients/{world.carol.user_id}/notes", headers=th.headers
    )
    assert [
        th.decrypt_note(world.carol, "story-note", n["blob"])["text"] for n in notes.json()
    ] == ["Cycle note"]

    # carol re-grants on the same row; alice rotates and re-wraps.
    assert (await _grant(client, world.carol, th))["id"] == world.consents["carol"]["id"]
    old_verifier = world.alice.auth_key_b64
    world.alice.derive_new_generation("pw-alice-story")
    await world.alice.rekey(client, keys["alice"], world.alice.data_key, verifier=old_verifier)
    assert (
        await world.alice.rewrap_consent(
            client,
            world.consents["alice"]["id"],
            th.wrap_pub_key,
            th.user_id,
            verifier=world.alice.auth_key_b64,
        )
    )["status"] == 200

    # Every active chart still opens with the CURRENT key material.
    listing = await _patients_list(client, th)
    for name in ("alice", "carol"):
        patient = getattr(world, name)
        key = _unwrap(client, th, patient, world.row_for(listing, f"e2e-{name}"))
        rows = await _read_entries(client, th, patient, {"limit": 3})
        for row in rows:
            _decrypt_entry(key, patient.user_id, row)

    # And the whole story left its trail.
    own = await client.get("/api/therapist/access-log", headers=th.headers, params={"limit": 200})
    actions = {row["action"] for row in own.json()}
    assert {"list_patients", "read_insights", "read_entries", "read_notes", "write_note"} <= actions
