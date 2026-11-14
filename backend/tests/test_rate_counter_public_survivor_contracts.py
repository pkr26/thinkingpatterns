"""Public count behavior at the real in-process counter capacity limits."""

import pytest

from app.cache import SlidingWindowCounter


@pytest.mark.parametrize("identities", [50_000, 50_001])
def test_default_identity_capacity_preserves_the_documented_eviction_batch(identities):
    counter = SlidingWindowCounter()
    for identity in range(identities):
        counter.hit(f"identity:{identity}", 1000, now=0)

    if identities == 50_000:
        assert counter.check("identity:0", 1000, now=0).count == 1
    else:
        assert counter.check("identity:0", 1000, now=0).count == 0
        assert counter.check("identity:4900", 1000, now=0).count == 0
        assert counter.check("identity:5001", 1000, now=0).count == 1


@pytest.mark.parametrize("timestamps", [128, 129])
def test_default_timestamp_compression_preserves_public_expiry_counts(timestamps):
    counter = SlidingWindowCounter()
    for instant in range(timestamps):
        counter.hit("busy", 1000, now=instant)

    assert counter.check("busy", 1000, now=1000).count == 127
    assert counter.check("busy", 1000, now=1001).count == (126 if timestamps == 128 else 127)


def test_expired_rich_identity_does_not_displace_a_live_identity_during_eviction():
    counter = SlidingWindowCounter()
    counter.hit("expired", 100, now=0)
    counter.hit("expired", 100, now=0)
    for identity in range(50_000):
        counter.hit(f"active:{identity}", 1000, now=100)

    assert counter.check("active:5000", 1000, now=100).count == 1
    assert counter.check("expired", 100, now=100).count == 0
