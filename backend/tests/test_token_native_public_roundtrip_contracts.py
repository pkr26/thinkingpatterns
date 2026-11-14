"""Public token roundtrip for supported existing account epochs and both roles."""

import uuid

import pytest

from app.security import tokens


@pytest.mark.parametrize("purpose", ["patient", "therapist"])
def test_public_token_roundtrip_preserves_a_supported_existing_account_epoch(purpose):
    user_id = uuid.uuid4().hex
    secret = "native-token-roundtrip-test-secret"
    issued = 1_790_000_000
    token = tokens.issue_token(user_id, secret, 86_400, now=issued, epoch=1000, purpose=purpose)
    payload = tokens.verify_token(token, secret, now=issued + 1)
    assert payload["uid"] == user_id
    assert payload["purpose"] == purpose
    assert payload["ep"] == 1000
    assert payload["iat"] == issued
    assert payload["exp"] == issued + 86_400
