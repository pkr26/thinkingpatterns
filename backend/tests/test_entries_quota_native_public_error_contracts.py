"""Entry quota errors retain their public status and codes at valid settings."""

from dataclasses import replace
from datetime import date

from tests.helpers import ClientEmulator


def valid_minimum_quota(app, settings):
    configured = replace(settings, max_entries_per_user=1, max_user_blob_bytes=1024)
    app.state.settings = configured


async def test_native_entry_count_quota_has_its_public_error_envelope(client, app, settings):
    valid_minimum_quota(app, settings)
    owner = ClientEmulator("native-count-quota", "native-count-password")
    await owner.register(client)
    today = date.today()
    await owner.create_entry(client, "one", today, client_entry_id="first")
    refused = await client.post(
        "/api/entries",
        headers=owner.headers,
        json={
            "client_entry_id": "second",
            "blob": owner.encrypt_entry("two", today, "second"),
            "entry_date": today.isoformat(),
        },
    )
    assert refused.status_code == 413
    assert refused.json() == {
        "detail": "storage quota reached (1 entries)",
        "code": "quota_exceeded",
    }


async def test_native_minimum_byte_quota_has_its_public_error_envelope(client, app, settings):
    valid_minimum_quota(app, settings)
    owner = ClientEmulator("native-bytes-quota", "native-bytes-password")
    await owner.register(client)
    today = date.today()
    ciphertext = owner.encrypt_entry("a native encrypted entry " * 100, today, "large")
    refused = await client.post(
        "/api/entries",
        headers=owner.headers,
        json={"client_entry_id": "large", "blob": ciphertext, "entry_date": today.isoformat()},
    )
    assert refused.status_code == 413
    assert refused.json() == {
        "detail": "storage quota reached (total size)",
        "code": "blob_quota_exceeded",
    }


async def test_native_replacement_byte_quota_preserves_the_existing_record(client, app, settings):
    valid_minimum_quota(app, settings)
    owner = ClientEmulator("native-replace-quota", "native-replace-password")
    await owner.register(client)
    today = date.today()
    created = await owner.create_entry(client, "retained", today, client_entry_id="entry")
    ciphertext = owner.encrypt_entry("a native encrypted replacement " * 100, today, "entry")
    refused = await client.put(
        "/api/entries/entry",
        headers=owner.headers,
        json={"blob": ciphertext, "entry_date": today.isoformat()},
    )
    assert refused.status_code == 413
    assert refused.json() == {
        "detail": "storage quota reached (total size)",
        "code": "blob_quota_exceeded",
    }
    assert (await owner.get_entry(client, "entry"))["blob"] == created["blob"]
