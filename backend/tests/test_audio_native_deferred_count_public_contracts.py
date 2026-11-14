"""Native owned filesystem refusal reports exactly one deferred audio object."""

import logging
import os
import time
import uuid

import pytest

from app.security import crypto
from app.services.audio_store import (
    AudioStoreError,
    LocalAudioStore,
    new_storage_key,
    reconcile_audio_inventory,
)


@pytest.mark.asyncio
async def test_native_owned_audio_delete_refusal_reports_one_deferred_object(
    app, settings, tmp_path, caplog
):
    assert os.geteuid() != 0, "This native permission profile requires an ordinary process owner"
    store = LocalAudioStore(str(tmp_path / "owned-audio-store"))
    key = new_storage_key(uuid.uuid4().hex)
    blob = crypto.encrypt(os.urandom(32), b"native opaque audio", b"native-audio-fixture")
    await store.put(key, blob)
    path = store.root / key
    cutoff_age = (settings.audio_lifecycle_ceiling_days or settings.audio_retention_days + 1) + 2
    old = time.time() - cutoff_age * 86_400
    os.utime(path, (old, old))
    # Only this fixture's own directory is made non-writable. Inventory can
    # read it, while unlink uses the actual native filesystem refusal.
    path.parent.chmod(0o500)
    try:
        with pytest.raises(AudioStoreError):
            await store.delete(key)
        assert path.is_file()
        caplog.set_level(logging.WARNING, logger="mindpattern.audio_store")
        async with app.state.sessionmaker() as session:
            assert await reconcile_audio_inventory(session, store, settings) == 0
        warnings = [
            record
            for record in caplog.records
            if record.name == "mindpattern.audio_store"
            and record.msg.startswith("audio lifecycle reconciliation deferred")
        ]
        assert len(warnings) == 1
        assert warnings[0].args == (1, "AudioStoreError")
        assert key not in warnings[0].getMessage()
        assert path.read_bytes() == blob
    finally:
        path.parent.chmod(0o700)
