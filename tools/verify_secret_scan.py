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
import re
import subprocess
import tarfile
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = "8.30.1"
PUBLIC = 'app.api.therapist": "a3b747d3c02e9468"'
PUBLIC_FILES = {
    "source/pins.py": PUBLIC,
    "docs/OPERATOR_PACK.md": "| policy | therapist linkage, speech/translation processing |",
    "mobile/ios/Podfile.lock": "  React-cxxstableapi: 1e0ad8a5ecb7f2f5440c012798cf20bec6341c1f",
}
CATALOG_KEYS = (
    "insights.hideMutedA11y",
    "insights.muteA11y",
    "insights.unmuteA11y",
    "insights.whySeeingA11y",
    "measures.gad7.item1",
    "measures.gad7.item2",
    "measures.gad7.item3",
    "measures.gad7.item4",
    "measures.gad7.item5",
    "measures.gad7.item6",
    "measures.item9Body",
    "measures.phq2.item1",
    "measures.phq2.item2",
    "measures.phq9.item1",
    "measures.phq9.item2",
    "measures.phq9.item3",
    "measures.phq9.item4",
    "measures.phq9.item5",
    "measures.phq9.item6",
    "measures.phq9.item7",
    "measures.phq9.item8",
    "measures.phq9.item9",
    "measures.questionA11y",
    "measures.trendA11y",
    "privacy.s1Body",
    "privacy.s2Body",
    "privacy.s3Body",
    "privacy.s4Body",
    "privacy.s5Body",
    "privacy.webS1",
    "privacy.webS2",
    "privacy.webS3",
    "privacy.webS4",
    "privacy.webS5",
    "question.notMeA11y",
    "question.resonatedA11y",
)


def public_fixture_files() -> dict[str, str]:
    """Copy the reviewed public assignments into the scanner fixture."""
    vector_path = "backend/tests/fixtures/portal_reference_security_vectors.json"
    account_path = "web/tests/accountAdoption.public.regression.test.tsx"
    native_path = "web/tests/loginNativeCompletion.test.tsx"
    portal_path = "portal/tests/accountSecurityPresentation.test.tsx"
    share_path = "web/tests/sharePublicProtocol.test.tsx"
    catalog_path = "web/tests/fixtures/catalog-output.json"
    vector = json.loads((ROOT / vector_path).read_text())
    account_source = (ROOT / account_path).read_text()
    password = re.search(r'\bPASSWORD\s*=\s*"([^"\n]+)"', account_source)
    if password is None:
        raise RuntimeError("reviewed account-adoption password assignment is missing")
    native_password = re.search(
        r'\bPASSWORD\s*=\s*"([^"\n]+)"', (ROOT / native_path).read_text()
    )
    if native_password is None or native_password.group(1) != password.group(1):
        raise RuntimeError("reviewed local login fixture passwords no longer match")
    fingerprint = "0123456789abcdef"[::-1]
    portal_source = (ROOT / portal_path).read_text()
    share_source = (ROOT / share_path).read_text()
    if f'wrap_key_fingerprint:"{fingerprint}"' not in portal_source:
        raise RuntimeError("reviewed mocked fingerprint assignment changed")
    if f'THERAPIST = "{fingerprint * 2}"' not in share_source:
        raise RuntimeError("reviewed synthetic therapist identifier changed")
    catalog = json.loads((ROOT / catalog_path).read_text())
    if set(CATALOG_KEYS) - {row["key"] for row in catalog["rows"]}:
        raise RuntimeError("reviewed public catalog identifiers changed")
    return {
        **PUBLIC_FILES,
        vector_path: json.dumps(
            {
                "portalDerivedKeys": {
                    "noteKeyHex": vector["portalDerivedKeys"]["noteKeyHex"]
                },
                "keyPair": {"wrapKeyBlobB64": vector["keyPair"]["wrapKeyBlobB64"]},
            },
            indent=2,
        ),
        account_path: f"const PASSWORD = {json.dumps(password.group(1))};",
        native_path: f"const PASSWORD={json.dumps(native_password.group(1))};",
        portal_path: f'wrap_key_fingerprint:"{fingerprint}"',
        share_path: f'const THERAPIST = "{fingerprint * 2}";',
        catalog_path: json.dumps(
            {"rows": [{"key": key} for key in CATALOG_KEYS]}, indent=2
        ),
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
        public_files = public_fixture_files()
        token = (
            "ghp_"
            + hashlib.sha256(b"synthetic scanner negative control").hexdigest()[:36]
        )
        api_key = hashlib.sha256(
            b"synthetic scanner negative API key control"
        ).hexdigest()
        copied_vector = "source/copied-portal-vectors.json"
        copied_account = "source/copied-account-adoption.ts"
        copied_native = "source/copied-native-login.ts"
        copied_portal = "source/copied-portal-fingerprint.ts"
        copied_share = "source/copied-share-identifier.ts"
        copied_catalog = "source/copied-catalog.json"
        known_paths = set(public_files) | {
            "source/changed.py",
            copied_vector,
            copied_account,
            copied_native,
            copied_portal,
            copied_share,
            copied_catalog,
        }

        def scan(
            mode: str,
            expected: set[tuple[str, str]] | Counter[tuple[str, str]],
            label: str,
        ):
            expected = Counter(expected)
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
            if any(
                value in output
                for value in (token, api_key)
                for output in (stdout, stderr, report)
            ):
                raise RuntimeError("scanner failed to redact the synthetic credential")
            if process.returncode != (7 if expected else 0):
                raise RuntimeError(
                    f"{mode}/{label}: unexpected scanner exit {process.returncode}: {stderr[-1000:]}"
                )
            rows = json.loads(report)  # empty/missing/malformed reports fail closed
            if not isinstance(rows, list):
                raise TypeError("scanner report is not a findings list")
            found = []
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
            if Counter(found) != expected:
                raise RuntimeError(
                    f"{mode}/{label}: findings {found!r}, expected {sorted(expected.elements())!r}"
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

        for name, content in public_files.items():
            path = folder / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content + "\n")
        git("add", ".")
        scan("staged", set(), "exact public values")
        git("commit", "-qm", "public values only")
        for mode in ("history", "no-git"):
            scan(mode, set(), "exact public values")

        for name, content in public_files.items():
            (folder / name).write_text(
                content + f'\ncredential = "{token}"\napi_key = "{api_key}"\n'
            )
        git("add", ".")
        secrets = Counter(
            (name, rule)
            for name in public_files
            for rule in ("github-pat", "generic-api-key")
        )
        for mode in ("staged", "no-git"):
            scan(mode, secrets, "adjacent synthetic credential")
        git("commit", "-qm", "synthetic credential control")
        scan("history", secrets, "adjacent synthetic credential")

        # Neither a different value at an approved path nor the approved value
        # at a different path may inherit a rule/path/value conjunction.
        for name, content in public_files.items():
            (folder / name).write_text(content + "\n")
        vector_path = "backend/tests/fixtures/portal_reference_security_vectors.json"
        account_path = "web/tests/accountAdoption.public.regression.test.tsx"
        native_path = "web/tests/loginNativeCompletion.test.tsx"
        portal_path = "portal/tests/accountSecurityPresentation.test.tsx"
        share_path = "web/tests/sharePublicProtocol.test.tsx"
        catalog_path = "web/tests/fixtures/catalog-output.json"
        changed_vector = json.loads(public_files[vector_path])
        note_key = changed_vector["portalDerivedKeys"]["noteKeyHex"]
        changed_vector["portalDerivedKeys"]["noteKeyHex"] = (
            "1" if note_key[0] == "0" else "0"
        ) + note_key[1:]
        wrapped_key = changed_vector["keyPair"]["wrapKeyBlobB64"]
        changed_vector["keyPair"]["wrapKeyBlobB64"] = (
            "B" if wrapped_key[0] == "A" else "A"
        ) + wrapped_key[1:]
        (folder / vector_path).write_text(json.dumps(changed_vector, indent=2) + "\n")
        changed_account = public_files[account_path].replace(
            'PASSWORD = "', 'PASSWORD = "z', 1
        )
        (folder / account_path).write_text(changed_account + "\n")
        changed_native = public_files[native_path].replace(
            'PASSWORD="', 'PASSWORD="z', 1
        )
        (folder / native_path).write_text(changed_native + "\n")
        (folder / copied_vector).write_text(public_files[vector_path] + "\n")
        (folder / copied_account).write_text(public_files[account_path] + "\n")
        (folder / copied_native).write_text(public_files[native_path] + "\n")
        for original, copied, old, new in (
            (portal_path, copied_portal, 'fingerprint:"f', 'fingerprint:"0'),
            (share_path, copied_share, 'THERAPIST = "f', 'THERAPIST = "0'),
        ):
            content = public_files[original]
            if old not in content:
                raise RuntimeError("reviewed identifier alteration control is missing")
            (folder / original).write_text(content.replace(old, new, 1) + "\n")
            (folder / copied).write_text(content + "\n")
        # Avoid the scanner's built-in natural-language stopwords in this
        # unlisted-value control; every altered identifier must remain a finding.
        changed_catalog = {"rows": [{"key": key + ".q7Z9"} for key in CATALOG_KEYS]}
        (folder / catalog_path).write_text(json.dumps(changed_catalog, indent=2) + "\n")
        (folder / copied_catalog).write_text(public_files[catalog_path] + "\n")
        changed = PUBLIC.replace("a3b747d3c02e9468", "d4978c39b205e6fa")
        (folder / "source/changed.py").write_text(changed + "\n")
        git("add", ".")
        unlisted = Counter(
            (name, "generic-api-key")
            for name in (
                "source/changed.py",
                vector_path,
                vector_path,
                account_path,
                native_path,
                copied_vector,
                copied_vector,
                copied_account,
                copied_native,
                portal_path,
                copied_portal,
                share_path,
                copied_share,
            )
        )
        unlisted[(catalog_path, "generic-api-key")] = len(CATALOG_KEYS)
        unlisted[(copied_catalog, "generic-api-key")] = len(CATALOG_KEYS)
        scan("staged", unlisted, "unlisted values and copied public assignments")
        scan("no-git", unlisted, "unlisted values and copied public assignments")
        git("commit", "-qm", "unlisted value and path controls")
        scan(
            "history",
            secrets + unlisted,
            "unlisted values and copied public assignments",
        )
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
