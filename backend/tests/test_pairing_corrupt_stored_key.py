"""Fail closed at pairing boundaries for an explicitly corrupted stored key.

The fixture writes malformed data directly to SQLite to model an imported or
corrupted record; it does not assert that registration accepts malformed keys.
Calls use the real endpoint functions and the existing isolated sharing fixture.
"""

import base64

import pytest

from app.api import consents, therapist
from app.deps import ApiError
from app.schemas import PairingLookupRequest
from tests.test_full_backend_authentication_mutation import (  # noqa: F401
    OWNER,
    authentication_db,
    collection_db,
    seed_pairing,
    sharing_db,
)


async def _public_call(db, endpoint):
    if endpoint == "lookup":
        return await consents.lookup_pairing(
            PairingLookupRequest(code=db.code), db.request, db.owner, db.session
        )
    return await therapist.pairing_sas(db.request, db.other, db.session, OWNER, db.code)


@pytest.mark.parametrize("endpoint", ["lookup", "sas"])
async def test_pairing_never_issues_verification_for_corrupt_stored_key(sharing_db, endpoint):  # noqa: F811
    db = sharing_db
    await seed_pairing(db)
    valid = await _public_call(db, endpoint)
    assert valid.sas and valid.wrap_key_fingerprint

    # This is a deliberately corrupted/imported stored value, not an API
    # producer. Python's permissive decoder would silently discard this byte.
    db.other.wrap_pub_key = "!" + db.spki
    await db.session.commit()
    assert base64.b64decode(db.other.wrap_pub_key, validate=False) == base64.b64decode(
        db.spki, validate=True
    )
    with pytest.raises(ApiError) as caught:
        await _public_call(db, endpoint)
    assert caught.value.status_code == 404
    assert caught.value.detail == "pairing code not found"
    assert caught.value.code == "not_found"

    # The failed check must not consume the code. Repairing imported state
    # makes the same live pairing available again.
    db.other.wrap_pub_key = db.spki
    await db.session.commit()
    repaired = await _public_call(db, endpoint)
    assert repaired.sas == valid.sas
    assert repaired.wrap_key_fingerprint == valid.wrap_key_fingerprint
