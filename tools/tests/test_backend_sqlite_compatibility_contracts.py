"""Execute backend binary-size queries on a real pre-3.43 SQLite engine."""

from __future__ import annotations

import importlib
import os
import subprocess
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    ("module", "helper", "model_name"),
    [
        ("account", "_export_blob_length", "Entry"),
        ("account", "_export_blob_length", "Insight"),
        ("account", "_export_blob_length", "Measure"),
        ("entries", "_blob_length", "Entry"),
        ("measures", "_measure_blob_length", "Measure"),
        ("therapist", "_note_blob_length", "TherapistNote"),
        ("therapist", "_revision_blob_length", "TherapistNoteRevision"),
    ],
)
def test_native_binary_size_queries_support_older_sqlite(
    monkeypatch, tmp_path, module, helper, model_name
):
    executable = os.environ.get("MINDPATTERN_MUTATION_LEGACY_SQLITE")
    if not executable:
        pytest.skip("set MINDPATTERN_MUTATION_LEGACY_SQLITE to a real SQLite3.42 CLI")
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / "backend"))
    monkeypatch.setenv("MINDPATTERN_ENV", "development")
    from app import models
    from app.security import crypto
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import Session

    api = importlib.import_module("app.api." + module)
    model = getattr(models, model_name)
    # Use actual encrypted binary envelopes, including NUL and UTF8
    # plaintext. Every ciphertext satisfies the native producer minimum.
    key = bytes(range(32))
    blobs = [crypto.encrypt(key, value) for value in (b"", b"\0" * 32, "€é".encode())]
    engine = create_engine("sqlite://")
    try:
        with Session(engine) as session:
            function = getattr(api, helper)
            expression = (
                function(session, model.blob)
                if module == "account"
                else function(session)
            )
            query = str(
                select(model.id, expression)
                .order_by(model.id)
                .compile(dialect=engine.dialect, compile_kwargs={"literal_binds": True})
            )
    finally:
        engine.dispose()
    table = model.__tablename__
    statements = [
        "SELECT sqlite_version();",
        f'CREATE TABLE "{table}" (id TEXT PRIMARY KEY, blob BLOB NOT NULL);',
    ]
    for n, blob in enumerate(blobs):
        statements.append(f"INSERT INTO \"{table}\" VALUES ('{n}',X'{blob.hex()}');")
    statements.append(query + ";")
    result = subprocess.run(
        [executable, "-batch", "-bail", str(tmp_path / "compatibility.sqlite")],
        input="\n".join(statements),
        text=True,
        capture_output=True,
        timeout=5,
        check=False,
    )
    # This is a real database-query assertion: no source text or SQL
    # function-name assertion determines the verdict.
    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    version = tuple(map(int, lines[0].split(".")))
    assert (3, 35, 0) <= version < (3, 43, 0), (
        "provide the declared older-engine profile"
    )
    assert lines[1:] == [f"{n}|{len(blob)}" for n, blob in enumerate(blobs)]
