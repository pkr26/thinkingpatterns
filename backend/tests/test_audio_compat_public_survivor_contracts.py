"""Native compatibility sweep continuation across a foreign storage target."""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.models import AudioAttachment, Base, User
from app.services import audio_store


@pytest.mark.asyncio
@pytest.mark.parametrize("foreign", ["backend", "locator"])
async def test_compatibility_sweep_deletes_later_owned_object_after_foreign_target(
    monkeypatch, tmp_path, foreign
):
    engine = create_async_engine("sqlite+aiosqlite://")
    store = audio_store.LocalAudioStore(str(tmp_path / "objects"))
    now = datetime(2026, 10, 5, tzinfo=timezone.utc)
    monkeypatch.setattr(audio_store, "utcnow", lambda: now)
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with async_sessionmaker(engine, expire_on_commit=False)() as session:
            owner = "aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa"
            session.add(
                User(
                    id=owner,
                    username=owner,
                    salt="salt",
                    verifier=b"v",
                    scrypt_salt=b"s",
                )
            )
            await session.commit()
            for index, name in enumerate(["foreign", "owned"]):
                key = f"audio/{name}.enc"
                await store.put(key, b"opaque client ciphertext" * 2)
                session.add(
                    AudioAttachment(
                        id=(
                            "11111111111141118111111111111111"
                            if index == 0
                            else "22222222222242228222222222222222"
                        ),
                        user_id=owner,
                        client_entry_id=name,
                        backend="s3" if name == "foreign" and foreign == "backend" else "local",
                        storage_locator=(
                            "another-storage-target"
                            if name == "foreign"
                            else audio_store.storage_locator(store)
                        ),
                        storage_key=key,
                        size_bytes=48,
                        mime_type="audio/webm",
                        duration_seconds=1,
                        created_at=now - timedelta(days=1),
                        expires_at=now - timedelta(seconds=2 - index),
                    )
                )
            await session.commit()
            # These are valid native identity-factory inputs. They remove
            # incidental UUID/query-plan ordering from this SQLite fixture;
            # no SQL result, sweep decision or storage output is supplied.
            identities = iter(
                ["00000000000040008000000000000000", "ffffffffffff4fffbfffffffffffffff"]
            )
            monkeypatch.setattr(audio_store, "new_id", lambda: next(identities))
            assert await audio_store.sweep_expired_audio(session, store) == 2
            assert await store.get("audio/foreign.enc") == b"opaque client ciphertext" * 2
            with pytest.raises(audio_store.AudioStoreError):
                await store.get("audio/owned.enc")
    finally:
        await engine.dispose()
