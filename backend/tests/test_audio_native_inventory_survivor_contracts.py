"""A native deletion during reconciliation must preserve other live audio."""

import asyncio
import threading
from pathlib import Path

import pytest

from app.services.audio_store import AudioStoreError, LocalAudioStore


@pytest.mark.asyncio
@pytest.mark.parametrize("handoff", ("before_is_file", "after_is_file"))
async def test_restarted_inventory_keeps_live_objects_when_one_file_disappears(
    tmp_path, monkeypatch, handoff
):
    owner = "a" * 32
    blobs = {
        f"audio/{owner}/{number:032x}.enc": f"encrypted audio {number}".encode()
        for number in range(1, 4)
    }
    initial = LocalAudioStore(str(tmp_path))
    for key, blob in blobs.items():
        await initial.put(key, blob)
    store = LocalAudioStore(str(tmp_path))
    paths = {tmp_path / key: key for key in blobs}
    first_file_seen = threading.Event()
    unlink_finished = threading.Event()
    chosen = []
    native_results = []
    unlinked = []
    native_is_file = Path.is_file
    native_unlink = Path.unlink

    def observe_real_file(path, *args, **kwargs):
        if path in paths and not first_file_seen.is_set():
            # Both windows occur after native glob gathered the batch. In
            # the second window, keep the real True observed before unlink;
            # the implementation's next native stat then sees the deletion.
            if handoff == "after_is_file":
                result = native_is_file(path, *args, **kwargs)
                assert result is True
            chosen.append(paths[path])
            first_file_seen.set()
            if not unlink_finished.wait(timeout=10):
                raise AssertionError("the owned deletion did not unlink its object")
            if handoff == "before_is_file":
                result = native_is_file(path, *args, **kwargs)
            native_results.append(result)
            return result
        return native_is_file(path, *args, **kwargs)

    def observe_real_unlink(path, *args, **kwargs):
        result = native_unlink(path, *args, **kwargs)
        if chosen and path == tmp_path / chosen[0]:
            # delete() next takes the inventory manifest lock. Reconciliation
            # currently holds it, so signal the physical unlink separately.
            unlinked.append(chosen[0])
            unlink_finished.set()
        return result

    async def delete_observed_object():
        seen = await asyncio.to_thread(first_file_seen.wait, 10)
        assert seen, "the restarted inventory never inspected an owned object"
        await store.delete(chosen[0])

    monkeypatch.setattr(Path, "is_file", observe_real_file)
    monkeypatch.setattr(Path, "unlink", observe_real_unlink)
    inventory = asyncio.create_task(store.inventory_page(after_key=None, limit=10))
    deletion = asyncio.create_task(delete_observed_object())
    try:
        objects, cursor = await asyncio.wait_for(asyncio.shield(inventory), timeout=15)
        await asyncio.wait_for(asyncio.shield(deletion), timeout=15)
    finally:
        # Both actors are owned and joined even on an assertion or timeout.
        # Releasing these events also lets a waiting native thread retire.
        first_file_seen.set()
        unlink_finished.set()
        await asyncio.wait_for(
            asyncio.gather(inventory, deletion, return_exceptions=True), timeout=15
        )

    assert len(chosen) == 1
    assert native_results == [handoff == "after_is_file"]
    assert unlinked == chosen
    removed = chosen[0]
    live_keys = sorted(set(blobs) - {removed})
    for key in live_keys:
        assert await store.get(key) == blobs[key]
    with pytest.raises(AudioStoreError, match="object missing"):
        await store.get(removed)
    assert cursor is None
    assert [key for key, _modified in objects] == live_keys
