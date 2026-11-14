"""The public legacy JSON boundary keeps foreign kind records inert."""

import json

import pytest

from app.services import brain
from tests.test_brain_store_public_roundtrip_contracts import actual_analysis_store


@pytest.mark.parametrize("foreign_kind", ["foreign-explicit-store-version", "XXtopicXX"])
def test_foreign_kind_cannot_inherit_an_active_state_from_legacy_json(foreign_kind):
    payload, pid = actual_analysis_store()
    # Explicit corrupt/foreign JSON input, based on a genuine native store.
    # These names are not claims about an actual historical producer.
    payload["patterns"][pid].update(kind=foreign_kind, state="confirmed")
    raw = json.dumps(payload).encode("utf-8")
    normalized = brain.dump_state(brain.load_state(raw))
    record = json.loads(normalized)["patterns"][pid]
    assert record["kind"] == foreign_kind
    assert record["state"] == "archived"
    assert brain.dump_state(brain.load_state(normalized)) == normalized
