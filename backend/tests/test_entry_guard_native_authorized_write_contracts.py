"""Native authorized pre-flush entry signing preserves default-v1 decryption."""

import json
import os
import uuid

from app.models import Entry
from app.security import crypto, entry_guard


def test_native_guard_signs_an_authorized_unflushed_entry_with_the_default_version(settings):
    user_id = uuid.uuid4().hex
    client_id = "native-authorized-default-version"
    key = os.urandom(32)
    plain = json.dumps({"v": 1, "text": "A quiet ordinary note."}).encode()
    blob = crypto.encrypt(key, plain, crypto.entry_aad_v2(user_id, client_id, 1))
    # A genuine native SQLAlchemy Entry before its mapped column defaults
    # execute at flush. The public signer explicitly supplies version1 for
    # this authorized write; no database or private MAC helper is replaced.
    row = Entry(user_id=user_id, client_entry_id=client_id, blob=blob)
    entry_guard.seal_entry_guard(row, settings, v2_bound=True)
    bindings = entry_guard.guarded_entry_aads(row, settings)
    assert len(bindings) == 1
    assert crypto.decrypt(key, row.blob, bindings[0]) == plain
