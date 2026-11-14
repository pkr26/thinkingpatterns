"""A released counter preserves native hit counts across timestamp compression."""

from app import cache


def test_native_public_counter_preserves_live_hits_and_expires_the_full_window():
    counter = cache.SlidingWindowCounter()
    for index in range(256):
        assert counter.hit("patient", 1000, now=float(index)).count == index + 1
    assert counter.check("patient", 1000, now=256).count == 256
    assert counter.check("patient", 1000, now=1256).count == 0
