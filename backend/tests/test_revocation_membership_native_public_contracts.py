"""The exported revocation cache preserves its configured membership contract."""

from app.cache import TokenRevocationStore


def test_explicit_revocation_capacity_preserves_the_latest_unexpired_token():
    store = TokenRevocationStore(max_entries=1)
    store.revoke("earlier", expires_at_epoch=110.0, now=100.0)
    store.revoke("later", expires_at_epoch=120.0, now=100.0)
    assert not store.is_revoked("earlier", now=100.0)
    assert store.is_revoked("later", now=100.0)
