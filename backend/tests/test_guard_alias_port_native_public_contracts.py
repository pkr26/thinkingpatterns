"""Native public process guards preserve supported aliases and port identity."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from app import singleprocess


@pytest.mark.parametrize(
    "held_url,child_url,expected",
    [
        (
            "postgresql+asyncpg://probe:probe@[::1]:55488/mutation_guard_test",
            "postgresql+asyncpg://probe:probe@127.0.0.1:55488/mutation_guard_test",
            "same deployment refused",
        ),
        (
            "postgresql+asyncpg://probe:probe@127.0.0.1:55488/mutation_guard_test",
            "postgresql+asyncpg://probe:probe@127.0.0.1:55489/mutation_guard_test",
            "independent deployment entered",
        ),
    ],
    ids=["ipv6-loopback-alias", "different-explicit-ports"],
)
def test_native_guards_apply_the_supported_alias_and_port_identity(
    tmp_path, monkeypatch, held_url, child_url, expected
):
    monkeypatch.setenv("MINDPATTERN_LOCK_DIR", str(tmp_path / "owned-native-locks"))
    backend = Path(singleprocess.__file__).resolve().parents[1]
    env = dict(os.environ, PYTHONPATH=str(backend), PYTHONDONTWRITEBYTECODE="1")
    child_code = (
        "from app.singleprocess import MultipleWorkersError, single_process_guard\n"
        "try:\n"
        "    with single_process_guard('native-alias-port', " + repr(child_url) + "):\n"
        "        print('independent deployment entered')\n"
        "except MultipleWorkersError:\n"
        "    print('same deployment refused')\n"
    )
    # These URLs only name native lock identities; no network connection,
    # DNS lookup, database service, or real deployment lock is used.
    with singleprocess.single_process_guard("native-alias-port", held_url):
        child = subprocess.run(
            [sys.executable, "-B", "-c", child_code],
            cwd=backend,
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    assert child.returncode == 0, child.stderr
    assert child.stdout.strip() == expected
