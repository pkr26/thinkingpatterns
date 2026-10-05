"""Actual opaque storage, provider requests and crash-repaired inventory."""

from __future__ import annotations

import asyncio
import importlib
import io
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 10, 5, tzinfo=timezone.utc)


def _user(models):
    return models.User(
        id="patient",
        username="patient",
        salt="salt",
        verifier=b"v",
        scrypt_salt=b"s",
        created_at=NOW,
    )


def _storage(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "backend"))
    monkeypatch.setenv("MINDPATTERN_ENV", "development")
    return importlib.import_module("app.services.audio_store")


def _settings(root="", **changes):
    values = {
        "audio_bucket": "",
        "audio_bucket_region": "",
        "audio_s3_endpoint": "",
        "audio_local_dir": str(root),
        "environment": "production",
        "audio_aws_access_key_id": "",
        "audio_aws_secret_access_key": "",
        "audio_retention_days": 30,
        "audio_lifecycle_ceiling_days": 31,
    }
    values.update(changes)
    return SimpleNamespace(**values)


def test_storage_selection_configuration_identity_and_authenticated_locator(
    monkeypatch, tmp_path
):
    module = _storage(monkeypatch)
    monkeypatch.chdir(tmp_path)
    module._audio_store_cache.clear()
    assert module.get_audio_store(_settings()) is None
    dev = module.get_audio_store(_settings(environment="development"))
    assert (
        isinstance(dev, module.LocalAudioStore)
        and dev.root == (tmp_path / "data/audio").resolve()
    )
    local = _settings(tmp_path / "objects")
    first = module.get_audio_store_cached(local)
    assert module.get_audio_store_cached(local) is first
    assert json.loads(module.storage_locator(first)) == {
        "backend": "local",
        "root": str(first.root),
    }
    cloud = _settings(
        audio_bucket=" bucket ",
        audio_bucket_region=" us-west-2 ",
        audio_s3_endpoint=" https://s3.invalid/ ",
        audio_aws_access_key_id="access",
        audio_aws_secret_access_key="secret",
    )
    store = module.get_audio_store_cached(cloud)
    assert isinstance(store, module.S3AudioStore)
    assert (store.bucket, store.region, store.endpoint) == (
        "bucket",
        "us-west-2",
        "https://s3.invalid/",
    )
    assert (store._access_key_id, store._secret_access_key) == ("access", "secret")
    assert (
        module.get_audio_store_cached(cloud) is store
        and len(module._audio_store_cache) == 1
    )
    expected = {
        "backend": "s3",
        "bucket": "bucket",
        "region": "us-west-2",
        "endpoint": "https://s3.invalid/",
    }
    assert json.loads(module.storage_locator(store)) == expected
    assert module.storage_locator(object()) is None
    for field in (
        "audio_bucket",
        "audio_bucket_region",
        "audio_s3_endpoint",
        "audio_aws_access_key_id",
        "audio_aws_secret_access_key",
    ):
        changed = SimpleNamespace(**vars(cloud))
        setattr(changed, field, getattr(changed, field) + "changed")
        assert module.get_audio_store_cached(changed) is not store
    for row, diagnostic in (
        (SimpleNamespace(backend="other"), "original audio backend is unavailable"),
        (
            SimpleNamespace(backend="s3", storage_locator="other"),
            "original audio storage target is unavailable",
        ),
    ):
        with pytest.raises(module.AudioStoreError) as observed:
            module.store_for_object(cloud, row)
        assert str(observed.value) == diagnostic
    assert (
        module.store_for_object(
            cloud, SimpleNamespace(backend="s3", storage_locator=None)
        ).backend
        == "s3"
    )


@pytest.mark.parametrize("endpoint", ["", " https://s3.invalid "])
def test_s3_transport_has_native_budgets_credentials_and_one_cached_client(
    monkeypatch, endpoint
):
    module = _storage(monkeypatch)
    import boto3

    calls = []
    client = object()
    monkeypatch.setattr(
        boto3, "client", lambda **kwargs: calls.append(kwargs) or client
    )
    store = module.S3AudioStore("bucket", "region", "access", "secret", endpoint)
    assert store._s3() is client and store._s3() is client and len(calls) == 1
    request = calls[0]
    assert request["service_name"] == "s3" and request["region_name"] == "region"
    assert (
        request["aws_access_key_id"] == "access"
        and request["aws_secret_access_key"] == "secret"
    )
    config = request["config"]
    assert config.connect_timeout == 5 and config.read_timeout == 10
    assert config.retries == {"max_attempts": 1, "mode": "standard"}
    if endpoint:
        assert request["endpoint_url"] == "https://s3.invalid"
        assert config.s3 == {"addressing_style": "path"}
    else:
        assert "endpoint_url" not in request


def test_s3_default_credentials_are_sdk_owned_and_exact_full_page_is_terminal(
    monkeypatch,
):
    module = _storage(monkeypatch)
    import boto3

    calls = []

    class Client:
        def list_objects_v2(self, **kwargs):
            return {
                "Contents": [
                    {"Key": "audio/a.enc", "LastModified": datetime.now(timezone.utc)}
                ],
                "IsTruncated": False,
            }

    monkeypatch.setattr(
        boto3, "client", lambda **kwargs: calls.append(kwargs) or Client()
    )
    for credentials in (
        {},
        {"access_key_id": "partial"},
        {"secret_access_key": "partial"},
    ):
        store = module.S3AudioStore("bucket", **credentials)
        objects, cursor = asyncio.run(store.inventory_page(after_key=None, limit=1))
        assert len(objects) == 1 and cursor is None
        assert "region_name" not in calls[-1]
        assert "endpoint_url" not in calls[-1]
        assert (
            "aws_access_key_id" not in calls[-1]
            and "aws_secret_access_key" not in calls[-1]
        )


def test_local_bounded_read_connection_and_prefetch_budgets_are_native(
    monkeypatch, tmp_path
):
    module = _storage(monkeypatch)
    store = module.LocalAudioStore(str(tmp_path))
    assert store.backend == "local"
    connect = module.sqlite3.connect
    connections, statements, read_sizes = [], [], []

    class Connection:
        def __init__(self, raw):
            self.raw = raw

        def __enter__(self):
            self.raw.__enter__()
            return self

        def __exit__(self, *args):
            return self.raw.__exit__(*args)

        def __getattr__(self, name):
            return getattr(self.raw, name)

        def execute(self, statement, parameters=()):
            statements.append((statement, parameters))
            return self.raw.execute(statement, parameters)

    def open_index(*args, **kwargs):
        connections.append(kwargs)
        return Connection(connect(*args, **kwargs))

    monkeypatch.setattr(module.sqlite3, "connect", open_index)
    asyncio.run(store.put("audio/a.enc", b"opaque"))
    asyncio.run(store.put("audio/b.enc", b"other"))
    assert len([sql for sql, _ in statements if sql == "PRAGMA quick_check"]) == 1
    assert all(call["timeout"] == 5 for call in connections)
    for limit, after, wanted in [
        (1, None, ["audio/a.enc"]),
        (1, "audio/a.enc", ["audio/b.enc"]),
    ]:
        page, cursor = asyncio.run(store.inventory_page(limit=limit, after_key=after))
        assert [row[0] for row in page] == wanted
        assert cursor == ("audio/a.enc" if after is None else None)
        queries = [
            parameters
            for sql, parameters in statements
            if "ORDER BY object_key" in sql and "LIMIT" in sql
        ]
        assert queries[-1][-1] == 2
    real_open = Path.open

    class ReadFile:
        def __init__(self, raw):
            self.raw = raw

        def __enter__(self):
            self.raw.__enter__()
            return self

        def __exit__(self, *args):
            return self.raw.__exit__(*args)

        def read(self, size=-1):
            read_sizes.append(size)
            return self.raw.read(size)

    def open_object(path, *args, **kwargs):
        raw = real_open(path, *args, **kwargs)
        return ReadFile(raw) if path.suffix == ".enc" and args == ("rb",) else raw

    monkeypatch.setattr(Path, "open", open_object)
    assert asyncio.run(store.get("audio/a.enc", max_bytes=6)) == b"opaque"
    assert read_sizes == [7]
    with pytest.raises(ValueError, match="^inventory page limit must be positive$"):
        asyncio.run(store.inventory_page(after_key=None, limit=0))
    new_ns = (store.root / "audio/a.enc").stat().st_mtime_ns + 1_000_000
    os.utime(store.root / "audio/a.enc", ns=(new_ns, new_ns))
    asyncio.run(store.inventory_page(after_key="audio/0.enc", limit=1))
    with connect(store._manifest_path) as connection:
        assert (
            connection.execute(
                "SELECT modified_ns FROM manifest_objects WHERE object_key = ?",
                ("audio/a.enc",),
            ).fetchone()[0]
            == new_ns
        )


def test_local_native_manifest_batches_skip_directories_and_remove_crash_stale_rows(
    monkeypatch, tmp_path
):
    module = _storage(monkeypatch)
    store = module.LocalAudioStore(str(tmp_path))
    audio = store.root / "audio"
    audio.mkdir()
    for n in range(501):
        (audio / f"{n:04d}.enc").write_bytes(b"opaque")
    (audio / "zzz-directory.enc").mkdir()
    # Filesystem enumeration order is provider-dependent. Exercise a
    # legitimate deterministic order with all 501 files preceding a directory.
    actual_glob = Path.glob

    def ordered_glob(path, pattern):
        results = actual_glob(path, pattern)
        return (
            iter(sorted(results))
            if path == store.root and pattern == "audio/**/*.enc"
            else results
        )

    monkeypatch.setattr(Path, "glob", ordered_glob)
    connect = module.sqlite3.connect
    batch_lengths = []

    class Connection:
        def __init__(self, raw):
            self.raw = raw

        def __enter__(self):
            self.raw.__enter__()
            return self

        def __exit__(self, *args):
            return self.raw.__exit__(*args)

        def __getattr__(self, name):
            return getattr(self.raw, name)

        def executemany(self, statement, parameters):
            rows = list(parameters)
            batch_lengths.append(len(rows))
            return self.raw.executemany(statement, rows)

    monkeypatch.setattr(
        module.sqlite3,
        "connect",
        lambda *args, **kwargs: Connection(connect(*args, **kwargs)),
    )
    page, cursor = asyncio.run(store.inventory_page(after_key=None, limit=500))
    assert len(page) == 500 and cursor == "audio/0499.enc"
    assert (
        max(batch_lengths) <= 500
        and sum(batch_lengths) == 501
        and len(batch_lengths) == 2
    )
    with connect(store._manifest_path) as connection:
        assert (
            connection.execute("SELECT count(*) FROM manifest_objects").fetchone()[0]
            == 501
        )
    # A crash between unlink and manifest update must disappear from the next cycle.
    (audio / "0000.enc").unlink()
    page, cursor = asyncio.run(store.inventory_page(after_key=None, limit=500))
    assert len(page) == 500 and cursor is None
    with connect(store._manifest_path) as connection:
        assert (
            connection.execute("SELECT count(*) FROM manifest_objects").fetchone()[0]
            == 500
        )


def test_local_corruption_discards_all_owned_sidecars_and_os_failures_are_named(
    monkeypatch, tmp_path
):
    module = _storage(monkeypatch)
    store = module.LocalAudioStore(str(tmp_path))
    for suffix in ("", "-journal", "-wal", "-shm"):
        Path(str(store._manifest_path) + suffix).write_bytes(b"corrupt cache")
    store._reset_manifest_unlocked()
    assert all(
        not Path(str(store._manifest_path) + suffix).exists()
        for suffix in ("", "-journal", "-wal", "-shm")
    )
    sentinel = tmp_path / "outside"
    sentinel.write_bytes(b"private")
    Path(str(store._manifest_path) + "-wal").symlink_to(sentinel)
    with pytest.raises(
        module.AudioStoreError, match="^local audio inventory index is unsafe$"
    ):
        store._reset_manifest_unlocked()
    assert sentinel.read_bytes() == b"private"
    Path(str(store._manifest_path) + "-wal").unlink()
    actual_replace = module.os.replace

    def fail_replace(source, target):
        raise PermissionError("private OS details")

    monkeypatch.setattr(module.os, "replace", fail_replace)
    with pytest.raises(module.AudioStoreError, match="^local audio put failed$"):
        asyncio.run(store.put("audio/a.enc", b"opaque"))
    assert list((tmp_path / "audio").glob("*")) == []
    monkeypatch.setattr(module.os, "replace", actual_replace)
    asyncio.run(store.put("audio/a.enc", b"opaque"))
    actual_unlink = Path.unlink

    def fail_unlink(path, *args, **kwargs):
        if path.suffix == ".enc":
            raise PermissionError("private OS details")
        return actual_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_unlink)
    with pytest.raises(module.AudioStoreError, match="^local audio delete failed$"):
        asyncio.run(store.delete("audio/a.enc"))


def test_successful_native_deletion_page_skips_lost_claims_and_filters_requested_ids(
    monkeypatch, tmp_path
):
    module = _storage(monkeypatch)
    models = importlib.import_module("app.models")
    from sqlalchemy import func, select, update
    from sqlalchemy.sql.dml import Update

    monkeypatch.setattr(module, "utcnow", lambda: NOW)
    settings = _settings(tmp_path)
    deleted = []
    actual_delete = module.LocalAudioStore.delete

    async def record_delete(store, key):
        deleted.append(key)
        return await actual_delete(store, key)

    monkeypatch.setattr(module.LocalAudioStore, "delete", record_delete)

    async def exercise(session, sessions):
        session.add_all(
            [
                models.AudioDeletion(
                    id=f"{n:02d}",
                    owner_id="patient",
                    backend="local",
                    storage_key=f"audio/patient/{n}.enc",
                    not_before=NOW,
                    created_at=NOW - timedelta(days=1),
                )
                for n in range(51)
            ]
        )
        await session.commit()
        execute = session.execute
        claimed = False

        async def concurrent_claim(statement, *args, **kwargs):
            nonlocal claimed
            if (
                isinstance(statement, Update)
                and statement.table.name == "audio_deletions"
                and not claimed
            ):
                claimed = True
                async with sessions() as other:
                    await other.execute(
                        update(models.AudioDeletion)
                        .where(models.AudioDeletion.id == "00")
                        .values(not_before=NOW + timedelta(seconds=600))
                    )
                    await other.commit()
            return await execute(statement, *args, **kwargs)

        monkeypatch.setattr(session, "execute", concurrent_claim)
        assert await module.drain_audio_deletions(session, settings) == 49
        assert len(deleted) == 49 and "audio/patient/0.enc" not in deleted
        assert await session.scalar(select(func.count(models.AudioDeletion.id))) == 2
        assert (
            await module.drain_audio_deletions(
                session, settings, identifiers=["absent"]
            )
            == 0
        )
        assert (
            await module.drain_audio_deletions(session, settings, identifiers=["50"])
            == 1
        )
        assert await session.get(models.AudioDeletion, "00") is not None

    asyncio.run(_database(models, exercise))


def test_attachment_enqueue_tracks_owned_pending_work_and_revision_exhaustion_is_exact(
    monkeypatch, tmp_path
):
    module = _storage(monkeypatch)
    models = importlib.import_module("app.models")
    from app.deps import ApiError

    monkeypatch.setattr(module, "utcnow", lambda: NOW)
    store = module.LocalAudioStore(str(tmp_path))

    async def exercise(session, sessions):
        user = _user(models)
        user.entries_revision = 2**63 - 1
        session.add(user)
        row = SimpleNamespace(
            user_id=user.id,
            backend="local",
            storage_key="audio/patient/key.enc",
            storage_locator="captured-private-original-location",
        )
        later = NOW + timedelta(seconds=17)
        first = module.enqueue_audio_delete(session, row, store=store, not_before=later)
        row.storage_locator = None
        second = module.enqueue_audio_delete(session, row, store=store)
        assert session.info["mindpattern_audio_deletions_pending"] == [first, second]
        await session.commit()
        saved = await session.get(models.AudioDeletion, first)
        assert (
            saved.owner_id == user.id
            and saved.storage_locator == "captured-private-original-location"
        )
        assert saved.not_before == later
        saved = await session.get(models.AudioDeletion, second)
        assert (
            saved.owner_id == user.id
            and saved.storage_locator == module.storage_locator(store)
        )
        assert saved.not_before == NOW
        with pytest.raises(ApiError) as failure:
            await module.advance_audio_revision(session, user.id)
        assert (
            failure.value.status_code,
            failure.value.detail,
            failure.value.code,
        ) == (503, "unable to advance attachment revision", "service_unavailable")
        assert user.entries_revision == 2**63 - 1
        user.entries_revision = 2**63 - 2
        await session.commit()
        await module.advance_audio_revision(session, user.id)
        await session.commit()
        await session.refresh(user)
        assert user.entries_revision == 2**63 - 1

    asyncio.run(_database(models, exercise))


@pytest.mark.parametrize("explicit_ceiling,retention", [(0, 30), (31, 10)])
def test_lifecycle_ceiling_applies_independently_of_future_declared_expiry(
    monkeypatch, explicit_ceiling, retention
):
    module = _storage(monkeypatch)
    models = importlib.import_module("app.models")
    monkeypatch.setattr(module, "utcnow", lambda: NOW)
    settings = _settings(
        audio_lifecycle_ceiling_days=explicit_ceiling, audio_retention_days=retention
    )
    deleted = []

    class Store:
        backend = "adapter"

        async def delete(self, key):
            deleted.append(key)

    store = Store()
    monkeypatch.setattr(module, "store_for_object", lambda settings, row: store)

    async def exercise(session, sessions):
        user = _user(models)
        session.add(user)
        for name, created in [
            ("old", NOW - timedelta(days=31)),
            ("recent", NOW - timedelta(days=31) + timedelta(microseconds=1)),
        ]:
            session.add(
                models.AudioAttachment(
                    id=name,
                    user_id=user.id,
                    client_entry_id=name,
                    backend="adapter",
                    storage_key=name,
                    size_bytes=32,
                    mime_type="audio/webm",
                    duration_seconds=1,
                    created_at=created,
                    expires_at=NOW + timedelta(days=100),
                )
            )
        await session.commit()
        assert await module.sweep_expired_audio(session, store, settings) == 1
        assert (
            deleted == ["old"]
            and await session.get(models.AudioAttachment, "recent") is not None
        )
        await session.refresh(user)
        assert user.entries_revision == 1

    asyncio.run(_database(models, exercise))


def test_expiry_selection_does_not_spend_native_500_page_on_ineligible_recordings(
    monkeypatch,
):
    module = _storage(monkeypatch)
    models = importlib.import_module("app.models")
    monkeypatch.setattr(module, "utcnow", lambda: NOW)
    settings = _settings()

    class Store:
        backend = "adapter"

        async def delete(self, key):
            assert key == "old"

    store = Store()
    monkeypatch.setattr(module, "store_for_object", lambda settings, row: store)

    async def exercise(session, sessions):
        session.add(_user(models))
        for n in range(500):
            session.add(
                models.AudioAttachment(
                    id=f"recent-{n}",
                    user_id="patient",
                    client_entry_id=f"recent-{n}",
                    backend="adapter",
                    storage_key=f"recent-{n}",
                    size_bytes=32,
                    mime_type="audio/webm",
                    duration_seconds=1,
                    created_at=NOW - timedelta(days=1),
                    expires_at=NOW + timedelta(days=1),
                )
            )
        session.add(
            models.AudioAttachment(
                id="old",
                user_id="patient",
                client_entry_id="old",
                backend="adapter",
                storage_key="old",
                size_bytes=32,
                mime_type="audio/webm",
                duration_seconds=1,
                created_at=NOW - timedelta(days=31),
                expires_at=NOW + timedelta(days=2),
            )
        )
        await session.commit()
        assert await module.sweep_expired_audio(session, store, settings) == 1
        assert (
            await session.get(models.AudioAttachment, "old", populate_existing=True)
            is None
        )

    asyncio.run(_database(models, exercise))


def test_manifest_uses_the_last_representable_sqlite_generation(monkeypatch, tmp_path):
    module = _storage(monkeypatch)
    store = module.LocalAudioStore(str(tmp_path))
    asyncio.run(store.put("audio/a.enc", b"opaque"))
    with sqlite3.connect(store._manifest_path) as connection:
        connection.execute(
            "UPDATE manifest_meta SET generation=? WHERE singleton=1", (2**63 - 2,)
        )
        connection.execute(
            "UPDATE manifest_objects SET seen_generation=?", (2**63 - 2,)
        )
    page, cursor = asyncio.run(store.inventory_page(after_key=None, limit=1))
    assert [key for key, _ in page] == ["audio/a.enc"] and cursor is None


def test_inventory_delegation_errors_expose_only_the_named_public_store_refusal(
    monkeypatch, tmp_path
):
    module = _storage(monkeypatch)
    store = module.LocalAudioStore(str(tmp_path))
    connect = sqlite3.connect

    def fail(*args, **kwargs):
        raise sqlite3.DatabaseError("private cache contents")

    monkeypatch.setattr(module.sqlite3, "connect", fail)
    with pytest.raises(module.AudioStoreError, match="^local audio inventory failed$"):
        asyncio.run(store.inventory_page(after_key=None, limit=1))
    monkeypatch.setattr(module.sqlite3, "connect", connect)


def test_s3_put_get_delete_and_failures_use_real_threaded_request_contract(monkeypatch):
    module = _storage(monkeypatch)
    calls, bodies = [], []

    class Body(io.BytesIO):
        def read(self, size=-1):
            calls.append(("read", size))
            return super().read(size)

    class Client:
        def put_object(self, **kwargs):
            calls.append(("put", kwargs))

        def get_object(self, **kwargs):
            calls.append(("get", kwargs))
            body = Body(b"opaque")
            bodies.append(body)
            return {"Body": body}

        def delete_object(self, **kwargs):
            calls.append(("delete", kwargs))

    store = module.S3AudioStore("bucket")
    store._client = Client()
    asyncio.run(store.put("audio/owner/item.enc", b"opaque"))
    assert calls.pop() == (
        "put",
        {
            "Bucket": "bucket",
            "Key": "audio/owner/item.enc",
            "Body": b"opaque",
            "ServerSideEncryption": "AES256",
        },
    )
    assert asyncio.run(store.get("key", max_bytes=6)) == b"opaque"
    assert calls[-1] == ("read", 7) and bodies[-1].closed
    assert asyncio.run(store.get("key")) == b"opaque"
    assert calls[-1] == ("read", (1 << 40) + 1) and bodies[-1].closed
    with pytest.raises(
        module.AudioStoreError, match="^object-store get failed$"
    ) as observed:
        asyncio.run(store.get("key", max_bytes=5))
    assert (
        str(observed.value.__cause__) == "object exceeds the fetch size limit"
        and bodies[-1].closed
    )
    asyncio.run(store.delete("key"))
    assert calls[-1] == ("delete", {"Bucket": "bucket", "Key": "key"})
    for operation, diagnostic in (
        ("put", "object-store put failed"),
        ("get", "object-store get failed"),
        ("delete", "object-store delete failed"),
    ):

        def fail(**kwargs):
            raise OSError("provider secret must stay private")

        monkeypatch.setattr(store._client, operation + "_object", fail)
        with pytest.raises(module.AudioStoreError) as observed:
            asyncio.run(
                getattr(store, operation)("key", b"x")
                if operation == "put"
                else getattr(store, operation)("key")
            )
        assert str(observed.value) == diagnostic


def test_s3_inventory_bounds_sorts_continuation_and_requires_timestamps(monkeypatch):
    module = _storage(monkeypatch)
    stamp = datetime(2026, 10, 5, tzinfo=timezone.utc)
    replies = [
        {
            "Contents": [
                {"Key": key, "LastModified": stamp}
                for key in ("audio/c", "audio/a", "audio/b")
            ],
            "IsTruncated": False,
        }
    ]
    requests = []

    def listing(**kwargs):
        requests.append(kwargs)
        return replies[0]

    store = module.S3AudioStore("bucket")
    store._client = SimpleNamespace(list_objects_v2=listing)
    assert asyncio.run(store.inventory_page(after_key="audio/0", limit=2)) == (
        [("audio/a", stamp), ("audio/b", stamp)],
        "audio/b",
    )
    assert requests[-1] == {
        "Bucket": "bucket",
        "Prefix": "audio/",
        "MaxKeys": 2,
        "StartAfter": "audio/0",
    }
    replies[0] = {
        "Contents": [{"Key": "audio/a", "LastModified": stamp}],
        "IsTruncated": False,
    }
    assert asyncio.run(store.inventory_page(after_key=None, limit=2)) == (
        [("audio/a", stamp)],
        None,
    )
    assert "StartAfter" not in requests[-1]
    replies[0]["IsTruncated"] = True
    assert asyncio.run(store.inventory_page(after_key=None, limit=2))[1] == "audio/a"
    for reply in ({}, {"Contents": [], "IsTruncated": True}):
        replies[0] = reply
        assert asyncio.run(store.inventory_page(after_key=None, limit=2)) == ([], None)
    replies[0] = {"Contents": [{"Key": "audio/a", "LastModified": "garbage"}]}
    with pytest.raises(
        module.AudioStoreError, match="^object-store inventory failed$"
    ) as observed:
        asyncio.run(store.inventory_page(after_key=None, limit=1))
    assert (
        str(observed.value.__cause__)
        == "inventory object has no modification timestamp"
    )
    for limit in (0, -1):
        with pytest.raises(ValueError, match="^inventory page limit must be positive$"):
            asyncio.run(store.inventory_page(after_key=None, limit=limit))


def test_local_opaque_files_fetch_bounds_erasure_and_traversal(monkeypatch, tmp_path):
    module = _storage(monkeypatch)
    store = module.LocalAudioStore(str(tmp_path / "objects"))
    key = "audio/user/item.enc"
    asyncio.run(store.put(key, b"opaque"))
    path = store.root / key
    assert path.read_bytes() == b"opaque"
    assert asyncio.run(store.get(key)) == b"opaque"
    assert asyncio.run(store.get(key, max_bytes=6)) == b"opaque"
    with pytest.raises(
        module.AudioStoreError, match="^local audio get failed$"
    ) as observed:
        asyncio.run(store.get(key, max_bytes=5))
    assert str(observed.value.__cause__) == "object exceeds the fetch size limit"
    for escaped in ("../outside", str(tmp_path / "outside"), "."):
        with pytest.raises(
            module.AudioStoreError, match="^storage key escapes the local root$"
        ):
            asyncio.run(store.get(escaped))
    assert not list(store.root.rglob("*.tmp"))
    asyncio.run(store.delete(key))
    asyncio.run(store.delete(key))
    assert not path.exists() and not path.parent.exists()
    with pytest.raises(module.AudioStoreError, match="^object missing$"):
        asyncio.run(store.get(key))


def test_local_inventory_repairs_corruption_restart_orphans_and_changed_files(
    monkeypatch, tmp_path
):
    module = _storage(monkeypatch)
    store = module.LocalAudioStore(str(tmp_path))
    stamp_ns = 1_759_680_000_123_456_789
    for key in ("audio/user/c.enc", "audio/user/a.enc", "audio/user/b.enc"):
        asyncio.run(store.put(key, b"ciphertext"))
        os.utime(tmp_path / key, ns=(stamp_ns, stamp_ns))
    page, after = asyncio.run(store.inventory_page(after_key=None, limit=2))
    expected_time = datetime.fromtimestamp(stamp_ns / 1_000_000_000, timezone.utc)
    assert page == [
        ("audio/user/a.enc", expected_time),
        ("audio/user/b.enc", expected_time),
    ]
    assert after == "audio/user/b.enc"
    assert asyncio.run(store.inventory_page(after_key=after, limit=2)) == (
        [("audio/user/c.enc", expected_time)],
        None,
    )
    with sqlite3.connect(store._manifest_path) as connection:
        assert connection.execute(
            "SELECT count(*) FROM manifest_objects"
        ).fetchone() == (3,)
    assert store._manifest_path.stat().st_mode & 0o777 == 0o600
    # A process restart must discover an unindexed opaque object and repair a
    # corrupt derived index while preserving the actual recordings.
    (tmp_path / "audio/user/orphan.enc").write_bytes(b"orphan ciphertext")
    store._manifest_path.write_bytes(b"corrupt derived index")
    restarted = module.LocalAudioStore(str(tmp_path))
    page, after = asyncio.run(
        restarted.inventory_page(after_key="audio/user/b.enc", limit=2)
    )
    assert [key for key, _ in page] == [
        "audio/user/c.enc",
        "audio/user/orphan.enc",
    ] and after is None
    assert asyncio.run(restarted.get("audio/user/orphan.enc")) == b"orphan ciphertext"
    # Continuations inspect actual files rather than trusting cached mtimes.
    os.utime(
        tmp_path / "audio/user/c.enc",
        ns=(stamp_ns + 2_000_000_000, stamp_ns + 2_000_000_000),
    )
    page, _ = asyncio.run(
        restarted.inventory_page(after_key="audio/user/b.enc", limit=1)
    )
    assert page[0][1] == expected_time.replace(second=expected_time.second + 2)
    (tmp_path / "audio/user/c.enc").unlink()
    page, after = asyncio.run(
        restarted.inventory_page(after_key="audio/user/b.enc", limit=1)
    )
    assert page == [] and after == "audio/user/c.enc"
    with sqlite3.connect(restarted._manifest_path) as connection:
        assert connection.execute(
            "SELECT count(*) FROM manifest_objects WHERE object_key=?",
            ("audio/user/c.enc",),
        ).fetchone() == (0,)


def test_local_index_symlinks_are_refused_without_touching_outside_data(
    monkeypatch, tmp_path
):
    module = _storage(monkeypatch)
    store = module.LocalAudioStore(str(tmp_path / "objects"))
    external = tmp_path / "outside"
    external.write_bytes(b"outside data")
    store._manifest_path.symlink_to(external)
    with pytest.raises(
        module.AudioStoreError, match="^local audio inventory index is unsafe$"
    ):
        asyncio.run(store.inventory_page(after_key=None, limit=1))
    assert external.read_bytes() == b"outside data"


def test_server_generated_storage_keys_and_attachment_expiry_are_portable(monkeypatch):
    module = _storage(monkeypatch)
    stamp = datetime(2026, 10, 5, tzinfo=timezone.utc)
    monkeypatch.setattr(module.uuid, "uuid4", lambda: SimpleNamespace(hex="f" * 32))
    assert module.new_storage_key("owner") == "audio/owner/" + "f" * 32 + ".enc"
    monkeypatch.setattr(module, "utcnow", lambda: stamp)
    assert module.attachment_expiry(_settings(audio_retention_days=1)) == datetime(
        2026, 10, 6, tzinfo=timezone.utc
    )


async def _database(models, exercise):
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        async with engine.begin() as connection:
            await connection.run_sync(models.Base.metadata.create_all)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        async with maker() as session:
            await exercise(session, maker)
    finally:
        await engine.dispose()


def test_deletion_drain_commits_native_lease_and_retries_with_exact_backoff(
    monkeypatch, caplog
):
    module = _storage(monkeypatch)
    models = importlib.import_module("app.models")
    clock = [datetime(2026, 10, 5, tzinfo=timezone.utc)]
    monkeypatch.setattr(module, "utcnow", lambda: clock[0])
    observed, errors = [], []

    async def exercise(session, maker):
        class Store:
            backend = "adapter"

            async def delete(self, key):
                assert session.in_transaction() is False
                async with maker() as reader:
                    lease = await reader.get(models.AudioDeletion, "pending")
                    assert lease.not_before == clock[0] + timedelta(seconds=300)
                observed.append(key)
                raise module.AudioStoreError("private provider content")

        monkeypatch.setattr(module, "get_audio_store_cached", lambda settings: Store())
        session.add(
            models.AudioDeletion(
                id="pending",
                owner_id="owner",
                backend="adapter",
                storage_key="opaque-key",
                not_before=clock[0],
                created_at=clock[0],
            )
        )
        await session.commit()
        for attempt, delay in [
            (1, 60),
            (2, 120),
            (3, 240),
            (4, 480),
            (5, 960),
            (6, 1920),
            (7, 3600),
            (8, 3600),
        ]:
            assert (
                await module.drain_audio_deletions(
                    session,
                    _settings(),
                    identifiers=["pending"],
                    failure_observer=lambda: errors.append(True),
                )
                == 0
            )
            row = await session.get(
                models.AudioDeletion, "pending", populate_existing=True
            )
            assert row.attempts == attempt and row.not_before == clock[0] + timedelta(
                seconds=delay
            )
            clock[0] = row.not_before
            await session.commit()
        assert observed == ["opaque-key"] * 8 and errors == [True] * 8

    asyncio.run(_database(models, exercise))
    records = [r for r in caplog.records if r.name == "mindpattern.audio_store"]
    assert len(records) == 8 and all(r.levelname == "WARNING" for r in records)
    assert all(
        r.getMessage() == "audio deletion deferred after object-store failure"
        for r in records
    )


def test_expiry_sweep_deletes_only_native_500_records_then_advances_revision(
    monkeypatch,
):
    module = _storage(monkeypatch)
    models = importlib.import_module("app.models")
    now = datetime(2026, 10, 5, tzinfo=timezone.utc)
    monkeypatch.setattr(module, "utcnow", lambda: now)
    from sqlalchemy import func, select

    async def exercise(session, maker):
        deleted = []

        class Store:
            backend = "adapter"

            async def delete(self, key):
                deleted.append(key)

        user = models.User(
            id="owner",
            username="owner",
            salt="s",
            verifier=bytes(32),
            scrypt_salt=bytes(16),
        )
        session.add(user)
        for n in range(501):
            session.add(
                models.AudioAttachment(
                    id=f"audio-{n}",
                    user_id="owner",
                    client_entry_id=f"client-{n}",
                    backend="adapter",
                    storage_key=f"opaque-{n}",
                    size_bytes=30,
                    mime_type="audio/mp4",
                    duration_seconds=1,
                    expires_at=now,
                    created_at=now,
                )
            )
        session.add(
            models.AudioAttachment(
                id="future",
                user_id="owner",
                client_entry_id="future",
                backend="adapter",
                storage_key="future-key",
                size_bytes=30,
                mime_type="audio/mp4",
                duration_seconds=1,
                expires_at=now + timedelta(seconds=1),
                created_at=now,
            )
        )
        await session.commit()
        assert await module.sweep_expired_audio(session, Store()) == 500
        assert len(deleted) == 500 and "future-key" not in deleted
        assert await session.scalar(select(func.count(models.AudioAttachment.id))) == 2
        assert (
            await session.get(models.User, "owner", populate_existing=True)
        ).entries_revision == 500
        assert await module.sweep_expired_audio(session, Store()) == 1
        assert (
            await session.get(models.User, "owner", populate_existing=True)
        ).entries_revision == 501
        assert await session.get(models.AudioAttachment, "future") is not None

    asyncio.run(_database(models, exercise))


def test_inventory_resumes_durable_cursor_protects_live_objects_and_forces_old_tombstones(
    monkeypatch, caplog
):
    module = _storage(monkeypatch)
    models = importlib.import_module("app.models")
    now = datetime(2026, 10, 5, tzinfo=timezone.utc)
    monkeypatch.setattr(module, "utcnow", lambda: now)
    import hashlib

    async def exercise(session, maker):
        deleted, progress = [], []
        old = now - timedelta(days=31)

        class Store:
            backend = "adapter"

            async def inventory_page(self, *, after_key, limit):
                assert after_key == "previous-key" and limit == 500
                return [
                    ("live", old),
                    ("old-orphan", old),
                    ("forced", now),
                    ("failed", old),
                ] + [(f"future-{n}", now) for n in range(496)], "continued-key"

            async def delete(self, key):
                deleted.append(key)
                if key == "failed":
                    raise module.AudioStoreError("untrusted private exception")

        store_id = hashlib.sha256(b"adapter\0").hexdigest()
        session.add(
            models.AudioInventoryCursor(
                store_id=store_id, after_key="previous-key", updated_at=now
            )
        )
        session.add(
            models.User(
                id="owner",
                username="owner",
                salt="s",
                verifier=bytes(32),
                scrypt_salt=bytes(16),
            )
        )
        session.add(
            models.AudioAttachment(
                id="live-attachment",
                user_id="owner",
                client_entry_id="live",
                backend="adapter",
                storage_key="live",
                size_bytes=30,
                mime_type="audio/mp4",
                duration_seconds=1,
                expires_at=now + timedelta(days=5),
                created_at=old,
            )
        )
        for identifier, created in [("old", old), ("new", now)]:
            session.add(
                models.AudioDeletion(
                    id=identifier,
                    owner_id="owner",
                    backend="adapter",
                    storage_key="forced",
                    not_before=now + timedelta(days=1),
                    created_at=created,
                )
            )
        await session.commit()
        assert (
            await module.reconcile_audio_inventory(
                session,
                Store(),
                _settings(),
                progress_observer=lambda **values: progress.append(values),
            )
            == 2
        )
        assert deleted == ["old-orphan", "forced", "failed"]
        assert progress == [{"scanned": 500, "backlog": True, "cycle_completed": False}]
        assert (
            await session.get(models.AudioInventoryCursor, store_id)
        ).after_key == "continued-key"
        assert (
            await session.get(models.AudioDeletion, "old", populate_existing=True)
            is None
        )
        assert (
            await session.get(models.AudioDeletion, "new", populate_existing=True)
            is None
        )

    asyncio.run(_database(models, exercise))
    record = next(r for r in caplog.records if r.name == "mindpattern.audio_store")
    assert record.levelname == "WARNING"
    assert record.getMessage() == (
        "audio lifecycle reconciliation deferred 1 object(s); "
        "storage error class(es): AudioStoreError"
    )


def test_empty_inventory_and_unsupported_adapter_publish_exact_progress_and_backlog(
    monkeypatch,
):
    module = _storage(monkeypatch)
    models = importlib.import_module("app.models")
    now = datetime(2026, 10, 5, tzinfo=timezone.utc)
    monkeypatch.setattr(module, "utcnow", lambda: now)

    async def exercise(session, maker):
        progress = []
        observer = lambda **values: progress.append(values)
        assert (
            await module.reconcile_audio_inventory(
                session, object(), _settings(), progress_observer=observer
            )
            == 0
        )
        assert progress.pop() == {
            "scanned": 0,
            "backlog": False,
            "cycle_completed": True,
        }

        class Store:
            backend = "adapter"

            async def inventory_page(self, *, after_key, limit):
                return [], "next"

        assert (
            await module.reconcile_audio_inventory(
                session, Store(), _settings(), progress_observer=observer
            )
            == 0
        )
        assert progress.pop() == {
            "scanned": 0,
            "backlog": True,
            "cycle_completed": False,
        }
        assert await module.audio_deletion_backlog(session) == (0, 0.0)
        session.add(
            models.AudioDeletion(
                id="old",
                owner_id=None,
                backend="adapter",
                storage_key="old",
                created_at=now - timedelta(seconds=12),
                not_before=now,
            )
        )
        session.add(
            models.AudioDeletion(
                id="new",
                owner_id="owner",
                backend="adapter",
                storage_key="new",
                created_at=now,
                not_before=now,
            )
        )
        await session.commit()
        assert await module.audio_deletion_backlog(session) == (2, 12.0)

    asyncio.run(_database(models, exercise))


def test_persisted_unicode_storage_locator_remains_compatible(monkeypatch, tmp_path):
    module = _storage(monkeypatch)
    settings = _settings(tmp_path / "recórdings")
    store = module.get_audio_store_cached(settings)
    # This is the canonical wire locator persisted by existing deployments.
    persisted = json.dumps(
        {"backend": "local", "root": str(store.root)},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    assert (
        module.store_for_object(
            settings, SimpleNamespace(backend="local", storage_locator=persisted)
        )
        is store
    )


def test_existing_empty_cursor_advances_and_future_backlog_age_is_zero(monkeypatch):
    module = _storage(monkeypatch)
    models = importlib.import_module("app.models")
    monkeypatch.setattr(module, "utcnow", lambda: NOW)
    import hashlib

    async def exercise(session, maker):
        class Store:
            backend = "adapter"

            async def inventory_page(self, *, after_key, limit):
                assert after_key == "old"
                return [], "new"

        identifier = hashlib.sha256(b"adapter\0").hexdigest()
        session.add(
            models.AudioInventoryCursor(
                store_id=identifier, after_key="old", updated_at=NOW
            )
        )
        session.add(
            models.AudioDeletion(
                id="future",
                owner_id=None,
                backend="adapter",
                storage_key="future",
                created_at=NOW + timedelta(seconds=1),
                not_before=NOW + timedelta(seconds=1),
            )
        )
        await session.commit()
        assert (
            await module.reconcile_audio_inventory(session, Store(), _settings()) == 0
        )
        assert (
            await session.get(
                models.AudioInventoryCursor, identifier, populate_existing=True
            )
        ).after_key == "new"
        assert await module.audio_deletion_backlog(session) == (1, 0.0)

    asyncio.run(_database(models, exercise))


@pytest.mark.parametrize("ceiling,retention", [(0, 30), (31, 10)])
def test_local_inventory_protects_authenticated_live_locator_and_counts_each_failure(
    monkeypatch, tmp_path, caplog, ceiling, retention
):
    module = _storage(monkeypatch)
    models = importlib.import_module("app.models")
    monkeypatch.setattr(module, "utcnow", lambda: NOW)
    settings = _settings(
        tmp_path, audio_lifecycle_ceiling_days=ceiling, audio_retention_days=retention
    )
    store = module.LocalAudioStore(str(tmp_path))
    locator = module.storage_locator(store)
    old = NOW - timedelta(days=31)
    for key, stamp in [
        ("audio/a-failed.enc", old),
        ("audio/b-failed.enc", old),
        ("audio/c-orphan.enc", old),
        ("audio/d-live.enc", old),
        ("audio/e-recent.enc", old + timedelta(microseconds=1)),
    ]:
        asyncio.run(store.put(key, b"opaque"))
        ns = int(stamp.timestamp() * 1_000_000_000)
        os.utime(store.root / key, ns=(ns, ns))
    unlink = Path.unlink

    def fail_selected(path, *args, **kwargs):
        if path.name in {"a-failed.enc", "b-failed.enc"}:
            raise OSError("private failure")
        return unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_selected)

    async def exercise(session, maker):
        session.add(_user(models))
        session.add(
            models.AudioAttachment(
                id="live",
                user_id="patient",
                client_entry_id="live",
                backend="local",
                storage_key="audio/d-live.enc",
                storage_locator=locator,
                size_bytes=30,
                mime_type="audio/webm",
                duration_seconds=1,
                created_at=old,
                expires_at=NOW + timedelta(days=1),
            )
        )
        await session.commit()
        assert await module.reconcile_audio_inventory(session, store, settings) == 1
        assert (store.root / "audio/d-live.enc").exists()
        assert (store.root / "audio/e-recent.enc").exists()
        assert not (store.root / "audio/c-orphan.enc").exists()

    asyncio.run(_database(models, exercise))
    record = next(
        record for record in caplog.records if record.name == "mindpattern.audio_store"
    )
    assert record.getMessage() == (
        "audio lifecycle reconciliation deferred 2 object(s); "
        "storage error class(es): AudioStoreError"
    )


def test_compatibility_sweep_skips_wrong_targets_and_failure_then_deletes_later_match(
    monkeypatch, tmp_path
):
    module = _storage(monkeypatch)
    models = importlib.import_module("app.models")
    monkeypatch.setattr(module, "utcnow", lambda: NOW)
    store = module.LocalAudioStore(str(tmp_path))
    locator = module.storage_locator(store)
    cases = [
        ("a-backend", "other", None),
        ("b-target", "local", "wrong-target"),
        ("c-failed", "local", locator),
        ("d-good", "local", locator),
    ]
    for key, _, _ in cases:
        asyncio.run(store.put("audio/" + key + ".enc", b"opaque"))
    unlink = Path.unlink

    def fail_one(path, *args, **kwargs):
        if path.name == "c-failed.enc":
            raise OSError("private failure")
        return unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_one)

    async def exercise(session, maker):
        session.add(_user(models))
        for n, (key, backend, target) in enumerate(cases):
            session.add(
                models.AudioAttachment(
                    id=key,
                    user_id="patient",
                    client_entry_id=key,
                    backend=backend,
                    storage_key="audio/" + key + ".enc",
                    storage_locator=target,
                    size_bytes=30,
                    mime_type="audio/webm",
                    duration_seconds=1,
                    created_at=NOW,
                    expires_at=NOW - timedelta(seconds=4 - n),
                )
            )
        await session.commit()
        assert await module.sweep_expired_audio(session, store) == 4
        assert await session.get(models.AudioDeletion, "none") is None
        for key, _, _ in cases[:-1]:
            assert (store.root / ("audio/" + key + ".enc")).exists()
        assert not (store.root / "audio/d-good.enc").exists()
        from sqlalchemy import func, select

        assert await session.scalar(select(func.count(models.AudioDeletion.id))) == 3

    asyncio.run(_database(models, exercise))


def test_sweep_waits_for_shared_owner_lifecycle_and_refreshes_renewed_attachment(
    monkeypatch,
):
    module = _storage(monkeypatch)
    models = importlib.import_module("app.models")
    monkeypatch.setattr(module, "utcnow", lambda: NOW)
    from contextlib import asynccontextmanager

    async def exercise(session, maker):
        session.add(_user(models))
        session.add(
            models.AudioAttachment(
                id="renewed",
                user_id="patient",
                client_entry_id="renewed",
                backend="adapter",
                storage_key="renewed",
                size_bytes=30,
                mime_type="audio/webm",
                duration_seconds=1,
                created_at=NOW - timedelta(days=32),
                expires_at=NOW,
            )
        )
        await session.commit()
        # Keep a stale identity-map object while the durable row is renewed.
        stale = await session.get(models.AudioAttachment, "renewed")
        await session.commit()
        original_hold = module.lifecycle_locks.hold
        waiting = asyncio.Event()

        @asynccontextmanager
        async def observed_hold(key):
            waiting.set()
            async with original_hold(key):
                yield

        monkeypatch.setattr(module.lifecycle_locks, "hold", observed_hold)
        async with original_hold("llm-lifecycle:patient"):
            task = asyncio.create_task(
                module.sweep_expired_audio(session, None, _settings())
            )
            try:
                await asyncio.wait_for(waiting.wait(), 1)
                await asyncio.sleep(0)
                assert not task.done(), (
                    "retention must wait for the same account lifecycle fence"
                )
                async with maker() as writer:
                    row = await writer.get(models.AudioAttachment, "renewed")
                    row.created_at = NOW
                    row.expires_at = NOW + timedelta(days=1)
                    await writer.commit()
            except BaseException:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                raise
        assert await asyncio.wait_for(task, 2) == 0
        assert stale is await session.get(models.AudioAttachment, "renewed")
        assert stale.created_at == NOW and stale.expires_at == NOW + timedelta(days=1)

    asyncio.run(_database(models, exercise))


def test_persisted_s3_locator_preserves_canonical_object_field_order(monkeypatch):
    module = _storage(monkeypatch)
    settings = _settings(
        audio_bucket="bucket",
        audio_bucket_region="region",
        audio_s3_endpoint="https://s3.invalid",
    )
    persisted = '{"backend":"s3","bucket":"bucket","endpoint":"https://s3.invalid","region":"region"}'
    assert (
        module.store_for_object(
            settings, SimpleNamespace(backend="s3", storage_locator=persisted)
        ).backend
        == "s3"
    )


def test_failed_integrity_verdict_rebuilds_only_the_derived_manifest(
    monkeypatch, tmp_path
):
    module = _storage(monkeypatch)
    store = module.LocalAudioStore(str(tmp_path))
    asyncio.run(store.put("audio/a.enc", b"opaque"))
    store._manifest_initialized = False
    connect = module.sqlite3.connect
    checks = []

    class Connection:
        def __init__(self, raw):
            self.raw = raw

        def __getattr__(self, name):
            return getattr(self.raw, name)

        def __enter__(self):
            self.raw.__enter__()
            return self

        def __exit__(self, *args):
            return self.raw.__exit__(*args)

        def execute(self, statement, parameters=()):
            if statement == "PRAGMA quick_check":
                checks.append(True)
                if len(checks) == 1:
                    return SimpleNamespace(fetchone=lambda: ("database corruption",))
            return self.raw.execute(statement, parameters)

    monkeypatch.setattr(
        module.sqlite3,
        "connect",
        lambda *args, **kwargs: Connection(connect(*args, **kwargs)),
    )
    page, after = asyncio.run(store.inventory_page(after_key=None, limit=1))
    assert [key for key, _ in page] == ["audio/a.enc"] and after is None
    assert len(checks) == 2 and (store.root / "audio/a.enc").read_bytes() == b"opaque"


def test_reconciliation_continues_after_a_file_vanishes_during_stat(
    monkeypatch, tmp_path
):
    module = _storage(monkeypatch)
    store = module.LocalAudioStore(str(tmp_path))
    audio = store.root / "audio"
    audio.mkdir()
    (audio / "a.enc").write_bytes(b"vanishing")
    (audio / "b.enc").write_bytes(b"opaque")
    stat = Path.stat
    glob = Path.glob

    def ordered(path, pattern):
        return iter(sorted(glob(path, pattern)))

    # Directory entries can cache is_file metadata. The file disappears
    # after that metadata was obtained and before the modification-time read.
    is_file = Path.is_file

    def existed(path, *args, **kwargs):
        return True if path == audio / "a.enc" else is_file(path, *args, **kwargs)

    def vanished(path, *args, **kwargs):
        if path == audio / "a.enc":
            raise FileNotFoundError(path)
        return stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "glob", ordered)
    monkeypatch.setattr(Path, "is_file", existed)
    monkeypatch.setattr(Path, "stat", vanished)
    page, after = asyncio.run(store.inventory_page(after_key=None, limit=1))
    assert [key for key, _ in page] == ["audio/b.enc"] and after is None


def test_compatibility_sweep_continues_after_matching_provider_failure(
    monkeypatch, tmp_path
):
    module = _storage(monkeypatch)
    models = importlib.import_module("app.models")
    monkeypatch.setattr(module, "utcnow", lambda: NOW)
    store = module.LocalAudioStore(str(tmp_path))
    locator = module.storage_locator(store)
    for key in ("a-failed", "b-good"):
        asyncio.run(store.put("audio/" + key + ".enc", b"opaque"))
    unlink = Path.unlink

    def fail_one(path, *args, **kwargs):
        if path.name == "a-failed.enc":
            raise OSError("provider fault")
        return unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_one)
    # Tombstone ids are server-generated. Fix their legitimate order to
    # exercise one failure followed by a deletable matching target.
    identifiers = iter(("a", "b"))
    monkeypatch.setattr(module, "new_id", lambda: next(identifiers))

    async def exercise(session, maker):
        session.add(_user(models))
        for n, key in enumerate(("a-failed", "b-good")):
            session.add(
                models.AudioAttachment(
                    id=key,
                    user_id="patient",
                    client_entry_id=key,
                    backend="local",
                    storage_key="audio/" + key + ".enc",
                    storage_locator=locator,
                    size_bytes=30,
                    mime_type="audio/webm",
                    duration_seconds=1,
                    created_at=NOW,
                    expires_at=NOW - timedelta(seconds=2 - n),
                )
            )
        await session.commit()
        assert await module.sweep_expired_audio(session, store) == 2
        assert (store.root / "audio/a-failed.enc").exists()
        assert not (store.root / "audio/b-good.enc").exists()
        assert (
            await session.get(models.AudioDeletion, "a", populate_existing=True)
            is not None
        )
        assert (
            await session.get(models.AudioDeletion, "b", populate_existing=True) is None
        )

    asyncio.run(_database(models, exercise))


def test_live_storage_configuration_race_recovers_one_pooled_provider(
    monkeypatch, tmp_path
):
    module = _storage(monkeypatch)
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    from app.config import Settings

    settings = Settings(environment="development", audio_local_dir=str(tmp_path))
    module._audio_store_cache.clear()
    initialized, proceed = Event(), Event()
    initialize = module.LocalAudioStore.__init__

    def paused_initialize(store, root):
        initialize(store, root)
        initialized.set()
        assert proceed.wait(2), (
            "configuration writer must finish before construction resumes"
        )

    monkeypatch.setattr(module.LocalAudioStore, "__init__", paused_initialize)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(module.get_audio_store_cached, settings)
        try:
            assert initialized.wait(2)
            settings.audio_bucket = "bucket"
        finally:
            proceed.set()
        assert isinstance(future.result(timeout=2), module.LocalAudioStore)
    cloud = module.get_audio_store_cached(settings)
    assert isinstance(cloud, module.S3AudioStore)
    assert module.get_audio_store_cached(settings) is cloud
