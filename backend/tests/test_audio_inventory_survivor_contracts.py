"""Compatibility with persisted local-audio inventory data across a restart."""

import sqlite3

import pytest

from app.services.audio_store import AudioStoreError, LocalAudioStore


@pytest.mark.asyncio
async def test_deleting_restarted_audio_removes_its_persisted_inventory_identity(tmp_path):
    # A fixture in the released on-disk format, independent of whichever index
    # name the implementation currently chooses. Such files survive upgrades
    # and process restarts alongside the account's encrypted audio objects.
    owner = "a" * 32
    key = f"audio/{owner}/{'b' * 32}.enc"
    audio = tmp_path / key
    audio.parent.mkdir(parents=True)
    audio.write_bytes(b"opaque historical encrypted audio")
    with sqlite3.connect(tmp_path / ".mindpattern-audio-inventory.sqlite3") as connection:
        connection.executescript(
            "CREATE TABLE manifest_meta (singleton INTEGER PRIMARY KEY "
            "CHECK (singleton = 1), generation INTEGER NOT NULL);"
            "INSERT INTO manifest_meta VALUES (1, 0);"
            "CREATE TABLE manifest_objects (object_key TEXT PRIMARY KEY, "
            "modified_ns INTEGER NOT NULL, seen_generation INTEGER NOT NULL);"
        )
        connection.execute(
            "INSERT INTO manifest_objects VALUES (?, ?, 0)",
            (key, audio.stat().st_mtime_ns),
        )

    store = LocalAudioStore(str(tmp_path))
    assert await store.get(key) == b"opaque historical encrypted audio"
    objects, cursor = await store.inventory_page(after_key=None, limit=10)
    assert [item[0] for item in objects] == [key] and cursor is None
    await store.delete(key)
    with pytest.raises(AudioStoreError, match="object missing"):
        await store.get(key)
    assert not audio.parent.exists()
    assert await store.inventory_page(after_key=None, limit=10) == ([], None)

    # Erasure must remove live inventory records that still identify the
    # retired account, including data already present before this restart.
    inventories = 0
    for candidate in tmp_path.iterdir():
        if not candidate.is_file() or candidate.read_bytes()[:16] != b"SQLite format 3\0":
            continue
        with sqlite3.connect(candidate) as connection:
            names = {row[0] for row in connection.execute("SELECT name FROM sqlite_master")}
            if "manifest_objects" not in names:
                continue
            inventories += 1
            assert connection.execute(
                "SELECT COUNT(*) FROM manifest_objects WHERE object_key = ?", (key,)
            ).fetchone() == (0,)
    assert inventories >= 1
