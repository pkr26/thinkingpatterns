"""Prove public-value exceptions keep adjacent secrets visible in every scan mode.

Use the CI-pinned Gitleaks 8.30.1 binary or its digest-pinned Docker image.
Fixtures are synthetic and confined to a disposable repository. Docker reads
an in-memory archive, scans its own temporary filesystem, and returns redacted
JSON on stdout; host/VM bind-mount cache behavior cannot corrupt the proof.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import subprocess
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = "8.30.1"
PUBLIC = 'app.api.therapist": "a3b747d3c02e9468"'
PUBLIC_FILES = {
    "source/pins.py": PUBLIC,
    "docs/OPERATOR_PACK.md": "| policy | therapist linkage, speech/translation processing |",
    "mobile/ios/Podfile.lock": "  React-cxxstableapi: 1e0ad8a5ecb7f2f5440c012798cf20bec6341c1f",
}


def verify(*, binary: str = "gitleaks", docker_image: str | None = None) -> list[dict]:
    command = ["docker", "run", "--rm", docker_image] if docker_image else [binary]
    version = subprocess.run(
        [*command, "version"], check=True, capture_output=True, text=True, timeout=60
    ).stdout.strip()
    if version.removeprefix("v") != VERSION:
        raise RuntimeError(f"expected Gitleaks {VERSION}, got {version!r}")

    with tempfile.TemporaryDirectory(prefix="secret-exception-control-") as scratch:
        folder = Path(scratch) / "repo"
        folder.mkdir()

        def git(*args):
            subprocess.run(
                ["git", *args], cwd=folder, check=True, capture_output=True, timeout=30
            )

        git("init", "-q")
        git("config", "user.email", "synthetic@example.invalid")
        git("config", "user.name", "Synthetic scanner control")
        git("commit", "--allow-empty", "-qm", "empty fixture repository")
        results = []
        token = (
            "ghp_"
            + hashlib.sha256(b"synthetic scanner negative control").hexdigest()[:36]
        )

        def scan(mode: str, expected: set[tuple[str, str]], label: str):
            flags = ["protect" if mode == "staged" else "detect"]
            if mode == "no-git":
                flags.append("--no-git")
            elif mode == "staged":
                flags.append("--staged")
            common = ["--redact", "--exit-code", "7", "--report-format", "json"]
            if docker_image:
                # The archive includes staged/index/history content and the exact
                # checkout policy. No writable mount or report lives in source.
                archive = io.BytesIO()

                def container_owner(member):
                    member.uid = member.gid = 0
                    member.uname = member.gname = "root"
                    return member

                with tarfile.open(fileobj=archive, mode="w") as bundle:
                    bundle.add(folder, arcname="repo", filter=container_owner)
                    bundle.add(
                        ROOT / ".gitleaks.toml",
                        arcname="config.toml",
                        filter=container_owner,
                    )
                process = subprocess.run(
                    [
                        "docker",
                        "run",
                        "--rm",
                        "-i",
                        "--entrypoint",
                        "/bin/sh",
                        docker_image,
                        "-c",
                        'mkdir /probe && tar -xf - -C /probe || exit 125; gitleaks "$@"; result=$?; test -f /probe/report.json || exit 125; cat /probe/report.json; exit "$result"',
                        "scan",
                        *flags,
                        "--source",
                        "/probe/repo",
                        "--config",
                        "/probe/config.toml",
                        *common,
                        "--report-path",
                        "/probe/report.json",
                    ],
                    check=False,
                    input=archive.getvalue(),
                    capture_output=True,
                    timeout=120,
                )
                stdout, stderr = process.stdout.decode(), process.stderr.decode()
                report = stdout
            else:
                output = Path(scratch) / f"report-{len(results)}.json"
                process = subprocess.run(
                    [
                        binary,
                        *flags,
                        "--source",
                        str(folder),
                        "--config",
                        str(ROOT / ".gitleaks.toml"),
                        *common,
                        "--report-path",
                        str(output),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                stdout, stderr = process.stdout, process.stderr
                if not output.is_file():
                    raise RuntimeError(
                        f"{mode}/{label}: scanner produced no report ({process.returncode})"
                    )
                report = output.read_text()
            if token in stdout or token in stderr or token in report:
                raise RuntimeError("scanner failed to redact the synthetic credential")
            if process.returncode != (7 if expected else 0):
                raise RuntimeError(
                    f"{mode}/{label}: unexpected scanner exit {process.returncode}: {stderr[-1000:]}"
                )
            rows = json.loads(report)  # empty/missing/malformed reports fail closed
            if not isinstance(rows, list):
                raise TypeError("scanner report is not a findings list")
            found = []
            known_paths = set(PUBLIC_FILES) | {"source/changed.py"}
            for row in rows:
                scanned_path = row["File"].replace("\\", "/")
                paths = [
                    name
                    for name in known_paths
                    if scanned_path == name or scanned_path.endswith("/" + name)
                ]
                if len(paths) != 1:
                    raise RuntimeError(f"unexpected finding location: {scanned_path}")
                found.append((paths[0], row["RuleID"]))
            if set(found) != expected or len(found) != len(expected):
                raise RuntimeError(
                    f"{mode}/{label}: findings {found!r}, expected {sorted(expected)!r}"
                )
            results.append(
                {
                    "scanner_version": version,
                    "mode": mode,
                    "fixture": label,
                    "exit": process.returncode,
                    "findings": len(rows),
                    "locations_and_rules": sorted(found),
                }
            )

        for name, content in PUBLIC_FILES.items():
            path = folder / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content + "\n")
        git("add", ".")
        scan("staged", set(), "exact public values")
        git("commit", "-qm", "public values only")
        for mode in ("history", "no-git"):
            scan(mode, set(), "exact public values")

        for name, content in PUBLIC_FILES.items():
            (folder / name).write_text(content + '\ncredential = "' + token + '"\n')
        git("add", ".")
        secrets = {(name, "github-pat") for name in PUBLIC_FILES}
        for mode in ("staged", "no-git"):
            scan(mode, secrets, "adjacent synthetic credential")
        git("commit", "-qm", "synthetic credential control")
        scan("history", secrets, "adjacent synthetic credential")

        # Another same-shaped public assignment must not inherit the exception.
        changed = PUBLIC.replace("a3b747d3c02e9468", "d4978c39b205e6fa")
        (folder / "source/changed.py").write_text(changed + "\n")
        git("add", "source/changed.py")
        unlisted = {("source/changed.py", "generic-api-key")}
        scan("staged", unlisted, "different unlisted digest")
        scan("no-git", secrets | unlisted, "different unlisted digest")
        git("commit", "-qm", "unlisted digest control")
        scan("history", secrets | unlisted, "different unlisted digest")
        return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="gitleaks")
    parser.add_argument("--docker-image")
    args = parser.parse_args()
    print(
        json.dumps(verify(binary=args.binary, docker_image=args.docker_image), indent=2)
    )


if __name__ == "__main__":
    main()
