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


def _working_tree_source_files() -> list[Path]:
    """Tracked and untracked, non-ignored source files in the checkout."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=REPO_ROOT,
            capture_output=True,
            check=True,
            timeout=60,
        ).stdout
    except (OSError, subprocess.SubprocessError):
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
    leaked = b"{\"evidence\": \"201 {'token': '%s.%s.%s'}\"}" % (header, claims, b"S" * 43)
    assert _scan_bytes(leaked) == ["JWT-shaped token with exp/iat claims"]

    # And the shapes that must NOT fire: dotted version strings and
    # lockfile-style digests.
    assert _scan_bytes(b"locked v1.2.3 through 7.8.9 today") == []
    assert _scan_bytes(b"sha512-QmFzZTY0YmFzZTY0YmFzZTY0.XhK2.P9zQ") == []
    assert _scan_bytes(b"see ghp_ notes without a real suffix") == []
    assert _scan_bytes(b"github_pat_11" + b"A" * 30) == ["GitHub PAT shape"]


def test_gitleaks_false_positive_exceptions_stay_at_reviewed_locations():
    """Exact-match exceptions must not quietly become general exemptions.

    The strings necessarily also occur in the policy and its planted-secret
    CI probe. Any new occurrence is a review event rather than an implicit
    extension of the allowlist.
    """
    approved = {
        b"therapist linkage, speech/translation": {
            Path(".gitleaks.toml"),
            Path("tools/verify_secret_scan.py"),
            Path("backend/tests/test_repo_secret_scan.py"),
            Path("docs/OPERATOR_PACK.md"),
        },
        b"React-cxxstableapi: 1e0ad8a5ecb7f2f5440c012798cf20bec6341c1f": {
            Path(".gitleaks.toml"),
            Path("tools/verify_secret_scan.py"),
            Path("backend/tests/test_repo_secret_scan.py"),
            Path("mobile/ios/Podfile.lock"),
        },
    }
    approved[b"a3b747d3c02e9468"] = {
        Path(".gitleaks.toml"),
        Path("backend/tests/test_repo_secret_scan.py"),
        Path("tools/verify_secret_scan.py"),
    }
    # Exact SHA-256 of the current therapist source, emitted by the portable
    # evidence publisher; this is public provenance rather than a credential.
    approved[b"4f2e6ec68674c2cfffb15ece89c5977cd6111725240e6ecf994721950c72342c"] = {
        Path(".gitleaks.toml"),
        Path("backend/tests/test_repo_secret_scan.py"),
        Path(
            "reports/mutation-2026-10-05/certificates/current-lock-scheduling-review-causal-review.json"
        ),
        Path(
            "reports/mutation-2026-10-05/certificates/historical-nested-sharing-lock-proof-provenance.json"
        ),
        Path("reports/mutation-2026-10-05/manifest.json"),
        Path("reports/mutation-2026-10-05/summary.json"),
    }
    # Public, deterministic offline vectors reviewed with the exact-match
    # scanner policy. Each key is the value itself so an unauthorized copy
    # is rejected even when its assignment or surrounding prose changes.
    # The producers and fixed public inputs are documented in .gitleaks.toml.
    policy_and_guard = {
        Path(".gitleaks.toml"),
        Path("backend/tests/test_repo_secret_scan.py"),
    }
    vector_locations = {
        b"S51594wKma1bAMYvsz+TZOtBMNNA7lVsuSyfxwJ1Qoo=": {
            Path("redteam/automatic_backend_contracts/crypto_vectors_small.json"),
        },
        b"Q4ioovzM6rPmUxtNSG3omid64x75jvjx1ljPTKpV21Y=": {
            Path("redteam/automatic_backend_contracts/crypto_vectors_small.json"),
        },
        b"Ion8UHquCO320Z0jbpJVBt9NK8I+MwY5wlkxiVd0bxk=": {
            Path("redteam/automatic_backend_contracts/crypto_vectors_small.json"),
        },
        b"AKNEn+eC00cmMscReFZwN/ZvQi7NfZyZU2ltL1tzHXo=": {
            Path("redteam/automatic_backend_contracts/crypto_vectors_small.json"),
        },
        b"gHzzdqkhvSOWFCyimTPcD6qlIOMYRgTKQK3ANEvqOqg=": {
            Path("redteam/automatic_backend_contracts/crypto_vectors_small.json"),
        },
        b"20Oahr5wd9gryOYg1uJFMbwW1bf/EETPCIppchL/NFo=": {
            Path("redteam/automatic_backend_contracts/crypto_vectors_small.json"),
        },
        b"YF1Gb964QHwCFOa5ux1rUnH2DnGbzDBc7L88OHzoqNM=": {
            Path("redteam/automatic_backend_contracts/crypto_vectors_small.json"),
        },
        b"sCBtHwK9z0CE4xyQ7zD61rbAKydYIpRHlPrTTD7zwUA=": {
            Path("redteam/automatic_backend_contracts/crypto_vectors_small.json"),
        },
        b"LnlNrdzQpWjWXEQiQzBOgn9glArlEoY58bae4A4cAhc=": {
            Path("redteam/automatic_backend_contracts/crypto_vectors_small.json"),
        },
        b"QlJdCGZYXUSDu5811B7DsJihYBMsReiAsI+TuWgzuao=": {
            Path("redteam/automatic_backend_contracts/crypto_vectors_small.json"),
        },
        b"glPgs5CUtfncOWXNm2aMLkwzy/peNcn4FZnJLAR8pIE=": {
            Path("redteam/automatic_backend_contracts/crypto_vectors_small.json"),
        },
        b"ggE8tZhjNVn/aJ4MnLa9X23a+s/eRuo2QcIMbU/eijI=": {
            Path("redteam/automatic_backend_contracts/crypto_vectors_small.json"),
        },
        b"NXC/7KCKT0KAOtjrJQQKaePsKsFKOqsNorJH6H4T1EQ=": {
            Path("redteam/automatic_backend_contracts/crypto_vectors_small.json"),
        },
        b"HjxGTtCcfC758otf3toRJcjwLv0QfqmS1Srkvrf15d8=": {
            Path("redteam/automatic_backend_contracts/crypto_vectors_small.json"),
        },
        b"At2ri082RlUhQJ9Ml6eGtYBiK2V71Aob1YMzR16lWgU=": {
            Path("redteam/automatic_backend_contracts/crypto_vectors_small.json"),
        },
        b"dgN4nuHlkRIg3yBHbUaNKuuM5oGouHDY7TTTViRI+4c=": {
            Path("redteam/automatic_backend_contracts/crypto_vectors_small.json"),
        },
        b"1GDk4Uao5o/Bv10xPndiZ6Y0JV11+9Grq8LaA31k/Rs=": {
            Path("redteam/automatic_backend_contracts/crypto_vectors_small.json"),
        },
        b"sc1B91Hvj+67Z21On43a8+ER9ty2KyCya9Ph3b9AOW4=": {
            Path("redteam/automatic_backend_contracts/crypto_vectors_small.json"),
        },
        b"nNB9ItmBepwzUcOhZaF+y27+sMuqx/I4Q0LZjYIgUSc=": {
            Path("redteam/automatic_backend_contracts/crypto_vectors_small.json"),
        },
        b"gPmfikJQwYXX7nEnmcdykuTVHCQ+NDD2OkVtf3tlTL4=": {
            Path("redteam/automatic_backend_contracts/crypto_vectors_small.json"),
        },
        b"yMnKy8zNzs/Q0dLT1NXW19jZ2tvc3d7f4OHi4+Tl5uc=": {
            Path("redteam/automatic_backend_contracts/crypto_vectors_small.json"),
            Path("shared/vectors.json"),
        },
        b"p4PA+VukfyRnYRL6lqmSG8TnqNgrGU1O37BxlgyM8lg=": {
            Path("redteam/automatic_backend_contracts/runtime_outputs.json"),
        },
        b"QgqO+sMHoLmcI4CxTFj2KFOzJj0ewRS6fhPh7lG1Dug=": {
            Path("redteam/automatic_backend_contracts/runtime_outputs.json"),
        },
        b"ASZtTjPHv7iZEdVW3+wI4H6AEHqbYJlFlKS3HsLSTHY=": {
            Path("redteam/automatic_backend_contracts/runtime_outputs.json"),
        },
    }
    approved.update(
        {needle: locations | policy_and_guard for needle, locations in vector_locations.items()}
    )
    found = {needle: set() for needle in approved}
    source_files = _working_tree_source_files()
    if not source_files:
        return
    for path in source_files:
        if not path.is_file():
            continue
        try:
            blob = path.read_bytes()
        except OSError:
            continue
        relative = path.relative_to(REPO_ROOT)
        for needle in approved:
            # Anchored scanner regexes escape punctuation such as '+'.
            # Review both exact spellings without widening approved locations.
            regex_spelling = re.escape(needle).replace(rb"\ ", b" ")
            if needle in blob or regex_spelling in blob:
                found[needle].add(relative)
    assert found == approved
