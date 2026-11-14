"""Different DNS deployment identities keep independent native process guards."""

import os
import subprocess
import sys
from pathlib import Path

from app import singleprocess


def test_unrelated_dns_deployment_does_not_exclude_loopback_process(tmp_path, monkeypatch):
    monkeypatch.setenv("MINDPATTERN_LOCK_DIR", str(tmp_path / "owned-native-locks"))
    backend = Path(singleprocess.__file__).resolve().parents[1]
    env = dict(os.environ, PYTHONPATH=str(backend), PYTHONDONTWRITEBYTECODE="1")
    loopback = "postgresql+asyncpg://probe:probe@127.0.0.1/mutation_guard_test"
    remote_dns = "postgresql+asyncpg://probe:probe@XX127.0.0.1XX/mutation_guard_test"
    child_code = (
        "from app.singleprocess import single_process_guard\n"
        "with single_process_guard('independent-dns-deployment', " + repr(loopback) + "):\n"
        "    print('independent deployment entered')\n"
    )
    # Only native lock files are used. Neither URL is resolved or connected.
    with singleprocess.single_process_guard("independent-dns-deployment", remote_dns):
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
    assert child.stdout.strip() == "independent deployment entered"
