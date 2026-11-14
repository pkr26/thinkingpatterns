"""The native public ticket interface rotates, consumes and clears capabilities."""

import time

from app.security.export_ticket import ExportTicketStore


def test_native_public_ticket_rotation_consumption_and_clear():
    store = ExportTicketStore()
    authorization = {
        "token_epoch": 1,
        "token_jti": "jti",
        "token_expires": time.time() + 600,
        "secret_fingerprint": "digest",
    }
    first = store.issue(user_id="one", **authorization)
    second = store.issue(user_id="one", **authorization)
    third = store.issue(user_id="one", **authorization)
    assert store.consume(first) is None
    grant = store.consume(second)
    assert grant is not None
    assert (
        grant.user_id,
        grant.token_epoch,
        grant.token_jti,
        grant.token_expires,
        grant.secret_fingerprint,
    ) == ("one", 1, "jti", authorization["token_expires"], "digest")
    assert store.consume(second) is None
    assert store.consume(third).user_id == "one"
    assert store.consume(third) is None
    retained = store.issue(user_id="two", **authorization)
    store.clear()
    assert store.consume(retained) is None
