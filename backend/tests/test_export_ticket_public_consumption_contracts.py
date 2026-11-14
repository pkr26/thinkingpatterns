"""Issuing another user's native download capability preserves earlier grants."""

import time

from app.security.export_ticket import ExportTicketStore


def test_native_export_tickets_for_distinct_users_remain_publicly_consumable():
    store = ExportTicketStore()
    arguments = {
        "token_epoch": 1,
        "token_jti": None,
        "token_expires": time.time() + 300,
        "secret_fingerprint": "reference",
    }
    tickets = [store.issue(user_id=f"native-owner-{i}", **arguments) for i in range(4)]
    for index, ticket in enumerate(tickets):
        grant = store.consume(ticket)
        assert grant is not None
        assert grant.user_id == f"native-owner-{index}"
        assert store.consume(ticket) is None
