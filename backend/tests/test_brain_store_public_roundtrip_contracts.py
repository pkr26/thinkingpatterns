"""Public persisted-store roundtrips from actual analysis output and admitted faults."""

import json
from datetime import date, timedelta

import pytest

from app.services import brain
from app.services.patterns import JournalEntry

TODAY = date(2026, 10, 5)


def actual_analysis_store():
    entries = [
        JournalEntry(
            "ordinary notes about a quiet day",
            TODAY - timedelta(days=offset),
            tags=("yoga",),
            sentiment=0.3,
        )
        for offset in range(14)
    ]
    result = brain.update(brain.fresh_state(), entries, TODAY)
    payload = json.loads(brain.dump_state(result.new_state))
    pid = next(
        pid for pid, record in payload["patterns"].items() if record["kind"] == "recurring_phrase"
    )
    return payload, pid


@pytest.mark.parametrize(
    "case",
    [
        "actual_producer",
        "date_caps",
        "archived",
        "invalid_state",
        "candidate_lookalike",
        "foreign_kind",
        "invalid_kind",
        "missing_occurrences",
        "negative_occurrences",
        "long_label",
        "invalid_dates",
    ],
)
def test_public_store_roundtrip_preserves_actual_records_and_normalizes_admitted_faults(case):
    payload, pid = actual_analysis_store()
    record = payload["patterns"][pid]
    expected = dict(record)
    if case == "date_caps":
        dates = [(TODAY - timedelta(days=offset)).isoformat() for offset in range(65)]
        record["qualification_days"] = dates
        record["evidence_dates"] = dates
        expected["qualification_days"] = sorted(dates)[-60:]
        expected["evidence_dates"] = sorted(dates)[-60:]
    elif case == "archived":
        record["state"] = expected["state"] = "archived"
    elif case in {"invalid_state", "candidate_lookalike"}:
        record["state"] = "broken" if case == "invalid_state" else "XXcandidateXX"
        expected["state"] = "candidate"
    elif case == "foreign_kind":
        record["kind"] = expected["kind"] = "foreign-explicit-store-version"
        record["state"] = "confirmed"
        expected["state"] = "archived"
    elif case == "invalid_kind":
        record["kind"] = None
    elif case == "missing_occurrences":
        record.pop("occurrences")
        expected["occurrences"] = 0
    elif case == "negative_occurrences":
        record["occurrences"] = -1
        expected["occurrences"] = 0
    elif case == "long_label":
        record["label"] = "x" * 205
        expected["label"] = "x" * 200
    elif case == "invalid_dates":
        record.update(
            first_seen="not-calendar",
            last_seen=None,
            first_qualified=1,
            last_qualified="",
        )
        expected.update(
            first_seen="1970-01-01",
            last_seen="1970-01-01",
            first_qualified="",
            last_qualified="",
        )
    # The public loader explicitly admits corrupt/old JSON plaintext, and
    # the public dumper revalidates JSON-shaped records on its own boundary.
    loaded = brain.load_state(json.dumps(payload).encode("utf-8"))
    normalized_bytes = brain.dump_state(loaded)
    normalized = json.loads(normalized_bytes)
    if case == "invalid_kind":
        assert pid not in normalized["patterns"]
    else:
        assert normalized["patterns"][pid] == expected
    assert brain.dump_state(brain.load_state(normalized_bytes)) == normalized_bytes
    direct = json.loads(brain.dump_state(payload))
    if case == "invalid_kind":
        assert pid not in direct["patterns"]
    else:
        assert direct["patterns"][pid] == expected
