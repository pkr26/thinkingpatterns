"""Server-generated object keys survive native store restart and inventory."""

import asyncio
import uuid

from app.security import crypto
from app.services import audio_store


def test_native_generated_object_is_recoverable_in_inventory_after_restart(tmp_path):
    async def exercise():
        owner = uuid.uuid4().hex
        key = audio_store.new_storage_key(owner)
        plaintext = b"a kept recording"
        data_key = bytes(range(32))
        aad = crypto.build_aad("audio", owner, "entry", "1")
        ciphertext = crypto.encrypt(data_key, plaintext, aad)
        store = audio_store.LocalAudioStore(str(tmp_path))
        await store.put(key, ciphertext)
        assert crypto.decrypt(data_key, await store.get(key), aad) == plaintext

        restarted = audio_store.LocalAudioStore(str(tmp_path))
        inventory, next_after = await restarted.inventory_page(after_key=None, limit=10)
        assert [object_key for object_key, _ in inventory] == [key]
        assert next_after is None
        await restarted.delete(key)
        assert await restarted.inventory_page(after_key=None, limit=10) == ([], None)

    asyncio.run(exercise())
