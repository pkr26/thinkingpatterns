"""A canceled rekey must not disrupt a live account writer or retain its keys."""

import asyncio
import uuid
from datetime import datetime, timezone

import pytest

from app.api import account, entries, insights
from tests.helpers import ClientEmulator


@pytest.mark.asyncio
async def test_cancel_rekey_while_entry_holds_lifecycle_fence(client, app, monkeypatch):
    owner = ClientEmulator("rekey-cancel-fence", "rekey-cancel-fence-password")
    await owner.register(client)
    replacement = ClientEmulator(owner.username, "rekey-cancel-fence-new-password")
    replacement.user_id = owner.user_id
    old_token = await owner.open_processing_session(client)
    new_token = await owner.open_processing_session_for(client, replacement.data_key)

    verifier_checked = asyncio.Event()
    continue_rekey = asyncio.Event()
    entry_holds_fence = asyncio.Event()
    continue_entry = asyncio.Event()
    original_verify = account._require_verifier
    original_entry_user = entries._fresh_active_entry_user
    original_pop = app.state.key_store.pop
    popped = []

    async def pause_after_verifier(*args, **kwargs):
        result = await original_verify(*args, **kwargs)
        verifier_checked.set()
        await continue_rekey.wait()
        return result

    async def pause_entry_inside_fence(*args, **kwargs):
        entry_holds_fence.set()
        await continue_entry.wait()
        return await original_entry_user(*args, **kwargs)

    def record_consumed_key(*args, **kwargs):
        key = original_pop(*args, **kwargs)
        popped.append(key)
        return key

    monkeypatch.setattr(account, "_require_verifier", pause_after_verifier)
    monkeypatch.setattr(entries, "_fresh_active_entry_user", pause_entry_inside_fence)
    monkeypatch.setattr(app.state.key_store, "pop", record_consumed_key)

    headers = {
        **owner.headers,
        "X-Account-Verifier": owner.auth_key_b64,
        "X-Processing-Token": old_token,
        "X-New-Processing-Token": new_token,
    }
    body = {
        "operation_id": str(uuid.uuid4()),
        "new_salt": replacement.salt_b64,
        "new_verifier": replacement.auth_key_b64,
    }
    today = datetime.now(timezone.utc).date()
    entry_body = {
        "client_entry_id": "cancel-fence-entry",
        "entry_date": today.isoformat(),
        "blob": owner.encrypt_entry("the entry still commits", today, "cancel-fence-entry"),
    }
    rekey = asyncio.create_task(client.post("/api/processing/rekey", headers=headers, json=body))
    entry = None
    try:
        await asyncio.wait_for(verifier_checked.wait(), timeout=10)
        entry = asyncio.create_task(
            client.post("/api/entries", headers=owner.headers, json=entry_body)
        )
        await asyncio.wait_for(entry_holds_fence.wait(), timeout=10)
        continue_rekey.set()

        lock_key = f"llm-lifecycle:{owner.user_id}"
        for _ in range(1000):
            lock = insights.lifecycle_locks._locks.get(lock_key)
            if len(popped) == 2 and lock is not None and lock.refs >= 2:
                break
            await asyncio.sleep(0.01)
        else:
            pytest.fail("rekey did not reach the second lifecycle wait")

        rekey.cancel()
        with pytest.raises(asyncio.CancelledError):
            await rekey
        assert all(key == bytearray(len(key)) for key in popped)
        assert not entry.done()

        continue_entry.set()
        response = await asyncio.wait_for(entry, timeout=10)
        assert response.status_code == 201, response.text
    finally:
        continue_rekey.set()
        continue_entry.set()
        for task in (rekey, entry):
            if task is not None and not task.done():
                task.cancel()
        await asyncio.gather(
            *(task for task in (rekey, entry) if task is not None), return_exceptions=True
        )
