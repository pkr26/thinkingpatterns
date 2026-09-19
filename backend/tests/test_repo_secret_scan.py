"""Tracked-file secret scan (2026-09-19 remediation).

The audit's finding: a prior e2e campaign committed its results artifact
WITH the live session tokens the run had minted — including a
therapist-role bearer (expired by the time anyone looked, but the pattern
re-arms on the next ``campaign.py`` run + commit). ``reports/`` has since
left the tree; this test keeps the CLASS of leak out: no git-tracked file
may contain a three-part base64url string whose header OR payload decodes
to a claim set with ``exp``/``iat`` (the service's own token format), nor
a GitHub PAT shape. History rewrite is a separate, destructive decision
this test deliberately does not touch.
"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
from pathlib import Path

os.environ.setdefault("MINDPATTERN_ENV", "development")

REPO_ROOT = Path(__file__).resolve().parents[2]

# A three-part base64url run (JWT shape; "." is not in the base64url
# alphabet, so the segments are unambiguous). Claim decoding is the real
# discriminator — this shape alone also matches innocuous dotted tokens.
_B64URL_TRIPLE = re.compile(rb"([A-Za-z0-9_-]{8,})\.([A-Za-z0-9_-]{8,})\.([A-Za-z0-9_-]{8,})")
# GitHub personal access tokens (classic and fine-grained).
_GITHUB_PAT = re.compile(rb"(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9]{20,}")

# Large binary-ish tracked artifacts (lockfile digests etc.) — cheap skip;
# none of them can legitimately carry a credential, and scanning them all
# byte-by-byte is waste.
_SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".tar"}


def _segment_has_token_claims(segment: bytes) -> bool:
    try:
        padded = segment + b"=" * (-len(segment) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, json.JSONDecodeError):
        return False
    return isinstance(claims, dict) and "exp" in claims and "iat" in claims


def _scan_bytes(blob: bytes) -> list[str]:
    """Credential-shaped findings in one file's bytes."""
    found: list[str] = []
    for match in _B64URL_TRIPLE.finditer(blob):
        if _segment_has_token_claims(match.group(1)) or _segment_has_token_claims(match.group(2)):
            found.append("JWT-shaped token with exp/iat claims")
            break
    if _GITHUB_PAT.search(blob):
        found.append("GitHub PAT shape")
    return found


def _tracked_files() -> list[Path]:
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=REPO_ROOT,
            capture_output=True,
            check=True,
            timeout=60,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        # Not a git checkout (e.g. an exported tree): nothing tracked to
        # scan, the guard is a no-op rather than a false failure.
        return []
    return [REPO_ROOT / name for name in out.decode("utf-8", "ignore").split("\0") if name]


def test_no_session_tokens_in_tracked_files():
    offenders: list[str] = []
    for path in _tracked_files():
        if path.suffix.lower() in _SKIP_SUFFIXES or not path.is_file():
            continue
        for finding in _scan_bytes(path.read_bytes()):
            offenders.append(f"{path.relative_to(REPO_ROOT)}: {finding}")
    assert not offenders, (
        "tracked files carry credential-shaped strings — redact them before "
        "committing (tokens minted by test/campaign runs are live for their "
        f"TTL): {offenders}"
    )


def test_scan_detects_the_original_leak_shape():
    """The guard must catch exactly what the audit found: a JSON results
    artifact embedding a freshly minted token (ep/exp/iat claims)."""
    claims = base64.urlsafe_b64encode(
        json.dumps({"ep": 1, "exp": 1999999999, "iat": 1999999990, "uid": "x" * 32}).encode()
    ).rstrip(b"=")
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=")
    leaked = b'{"evidence": "201 {\'token\': \'%s.%s.%s\'}"}' % (header, claims, b"S" * 43)
    assert _scan_bytes(leaked) == ["JWT-shaped token with exp/iat claims"]

    # And the shapes that must NOT fire: dotted version strings and
    # lockfile-style digests.
    assert _scan_bytes(b"locked v1.2.3 through 7.8.9 today") == []
    assert _scan_bytes(b"sha512-QmFzZTY0YmFzZTY0YmFzZTY0.XhK2.P9zQ") == []
    assert _scan_bytes(b"see ghp_ notes without a real suffix") == []
    assert _scan_bytes(b"github_pat_11" + b"A" * 30) == ["GitHub PAT shape"]
