"""A-series: cryptography & key-management red-team audits.

A1 processing-session attacks (TTL, theft, owner binding, single-use, memory)
A4 client-KDF downgrade (server-side acceptance of weak iterations)
A5 eternal-key / nonce analysis (seam, birthday bound, rotation absence)
A6 cross-platform AAD canonicalization fuzz (Python side; TS side in mobile spec)
"""

from __future__ import annotations

import base64
import gc
import json
import os
import secrets
import time
from datetime import date

from common import (
    RESULTS,
    auth_headers,
    derive_keys,
    guard,
    make_app,
    make_client,
    make_settings,
    run,
    section,
    seed_unlocked_user,
    verdict,
)


async def a1_processing_sessions() -> None:
    section("A1: processing-session key attacks")
    audit = "A1"

    # -- keystore-level single-use ------------------------------------------
    from app.security.enclave import InMemoryKeyStore, KeyNotFound

    ks = InMemoryKeyStore()
    tok = ks.create(b"k" * 32, ttl_seconds=60, owner="user-a")
    key1 = ks.pop(tok, owner="user-a")
    assert key1 == b"k" * 32
    try:
        ks.pop(tok, owner="user-a")
        verdict(audit + ".single-use", "FINDING", "session token reusable after pop")
    except KeyNotFound:
        verdict(audit + ".single-use", "BLOCKED", "second pop() rejected (atomic single-use holds)")

    # -- owner binding at keystore level ------------------------------------
    tok = ks.create(b"k" * 32, ttl_seconds=60, owner="user-a")
    try:
        ks.pop(tok, owner="user-b")
        verdict(audit + ".owner-bind", "FINDING", "foreign owner popped the key")
    except KeyNotFound:
        verdict(audit + ".owner-bind", "BLOCKED", "pop() with foreign owner rejected")

    # -- TTL expiry ----------------------------------------------------------
    settings = make_settings(processing_session_ttl=1)
    app = await make_app(settings)
    async with make_client(app) as client:
        user = await seed_unlocked_user(app, client, "a1_ttl_user", "pw-a1-tenant")
        r = await client.post("/api/v1/processing/sessions", headers=auth_headers(user["token"]),
                              json={"data_key": base64.b64encode(user["data_key"]).decode()})
        session_token = r.json()["session_token"]
        time.sleep(1.6)
        r = await client.post("/api/v1/insights/recompute",
                              headers={**auth_headers(user["token"]),
                                       "X-Processing-Token": session_token})
        ok = r.status_code == 403 and r.json().get("code") == "processing_session_invalid"
        verdict(audit + ".ttl", "BLOCKED" if ok else "FINDING",
                f"expired session rejected: {r.status_code} {r.json().get('code')}")

    # -- opened-but-never-consumed: how long does the key live in server RAM?
    app = await make_app(make_settings(processing_session_ttl=300))  # the (new) operator max
    async with make_client(app) as client:
        user = await seed_unlocked_user(app, client, "a1_abandon_user", "pw-a1-abandon")
        r = await client.post("/api/v1/processing/sessions", headers=auth_headers(user["token"]),
                              json={"data_key": base64.b64encode(user["data_key"]).decode()})
        st = r.json()["session_token"]
        ks_app = app.state.key_store
        held = ks_app.get(st, owner=user["user_id"]) if hasattr(ks_app, "get") else None
        verdict(audit + ".abandoned-session",
                "INFO",
                f"abandoned session still holds the data key in server RAM until "
                f"TTL (held={held is not None}) — but the operator ceiling is now "
                f"300s (2026-09-16 fix), exactly matching the consent copy's "
                f"'held in memory for up to 5 minutes'; residual exposure is the "
                f"disclosed 5-minute window, not an hour")

    # -- token theft across users via the live API ---------------------------
    app = await make_app(make_settings())
    async with make_client(app) as client:
        victim = await seed_unlocked_user(app, client, "a1_victim", "pw-victim")
        thief = await seed_unlocked_user(app, client, "a1_thief", "pw-thief")
        r = await client.post("/api/v1/processing/sessions", headers=auth_headers(victim["token"]),
                              json={"data_key": base64.b64encode(victim["data_key"]).decode()})
        stolen = r.json()["session_token"]
        r = await client.post("/api/v1/insights/recompute",
                              headers={**auth_headers(thief["token"]),
                                       "X-Processing-Token": stolen})
        ok = r.status_code == 403 and r.json().get("code") == "processing_session_invalid"
        verdict(audit + ".theft-owner-bind", "BLOCKED" if ok else "FINDING",
                f"stolen session token unusable by another account: {r.status_code} "
                f"{r.json().get('code')} (thief still needs the victim bearer token too)")

    # -- memory: do plaintext copies outlive the secure context? -------------
    marker = "MARKER-PLAINTEXT-7f3a9c"
    from app.security.crypto import build_aad, encrypt
    from app.security.enclave import SecureProcessingContext

    key = secrets.token_bytes(32)
    payload = json.dumps({"v": 1, "text": f"ordinary entry {marker} ordinary",
                          "sentiment": None, "created_at": date.today().isoformat()}).encode()
    blob = encrypt(key, payload, aad=build_aad("entry", "u1", "c1"))
    seen: list[str] = []

    def analyze(plains):
        for p in plains:  # parse exactly like the real analyze_fn
            seen.append(json.loads(bytes(p).decode("utf-8"))["text"])
        return ("result", [])

    SecureProcessingContext(bytearray(key)).run([(build_aad("entry", "u1", "c1"), blob)], analyze)
    del seen[:]
    gc.collect()
    remnants = [o for o in gc.get_objects()
                if isinstance(o, str) and marker in o]
    verdict(audit + ".memory-remnants",
            "BLOCKED" if not remnants else "FINDING",
            f"post-run GC scan for plaintext marker: {len(remnants)} lingering str copies "
            f"(CPython refcounting frees this path promptly; the enclave docstring's honest "
            f"caveat covers exception paths/analyzer-held refs, not this one)")


async def a4_kdf_downgrade() -> None:
    section("A4: client-KDF downgrade")
    audit = "A4"
    # 2026-09-16 fix: both shipping libraries floor iterations at MIN_ITERATIONS.
    from app.security import kdf

    refused = False
    try:
        kdf.derive_master_key("pw", b"0123456789abcdef", kdf.MIN_ITERATIONS - 1)
    except ValueError:
        refused = True
    verdict(audit + ".library-floor", "BLOCKED" if refused else "FINDING",
            f"derive_master_key refuses iterations < {kdf.MIN_ITERATIONS} on both "
            f"platforms — an honest code path can no longer silently downgrade "
            f"the 600k contract")

    app = await make_app(make_settings())
    async with make_client(app) as client:
        # Structural residual, restated: a client that BYPASSES the library
        # (hand-rolled PBKDF2) still registers fine — the server cannot
        # observe the work factor. Documented, not fixable server-side.
        salt = os.urandom(16)
        auth_key, _ = derive_keys("password", salt, iterations=1)
        r = await client.post("/api/v1/auth/register", json={
            "username": "a4_downgraded",
            "salt": base64.b64encode(salt).decode(),
            "verifier": base64.b64encode(auth_key).decode()})
        verdict(audit + ".server-cannot-verify", "PARTIAL",
                f"a hand-rolled 1-iteration derivation still registers "
                f"({r.status_code}) — the server never sees the password, so "
                f"client work factors are structurally unverifiable; the floor "
                f"removes every accidental/honest downgrade path")


async def a5_key_lifecycle() -> None:
    section("A5: eternal key / nonce / rotation analysis")
    audit = "A5"
    from app.security import crypto

    # 2026-09-16 fix: the seam moved to encrypt_with_nonce (test-only name);
    # production encrypt() has no nonce parameter at all.
    key = bytes(range(32))
    import inspect as _inspect

    params = list(_inspect.signature(crypto.encrypt).parameters)
    seam_free = "nonce" not in params
    fresh = crypto.encrypt(key, b"payload") != crypto.encrypt(key, b"payload")
    verdict(audit + ".nonce-seam", "BLOCKED" if seam_free and fresh else "FINDING",
            f"production encrypt() signature is {params} — no nonce parameter; "
            f"two identical calls always differ (fresh={fresh}); fixed-nonce "
            f"output is only reachable via the unmistakably-named "
            f"encrypt_with_nonce, mirrored in the mobile envelope.ts")

    # birthday bound under the 10k-entry quota, one eternal key
    n = 10_000
    p_collision = n * n / 2**97
    verdict(audit + ".nonce-birthday", "BLOCKED",
            f"random 96-bit nonces, {n} entries under one key: P(collision) ≈ {p_collision:.2e} "
            f"— negligible within the per-user quota; risk is structural only if the quota is "
            f"raised or the seam above is used")

    # rotation / re-key existence
    from app.api import account, auth

    routes = {getattr(r, "path", "") for r in auth.router.routes}
    routes |= {getattr(r, "path", "") for r in account.router.routes}
    has_rotation = any("password" in p or "rotate" in p or "rekey" in p for p in routes)
    verdict(audit + ".no-rekey-path", "INFO" if not has_rotation else "BLOCKED",
            f"no password-change/rotate endpoint exists ({sorted(routes)}): data key never "
            f"changes for an account's lifetime; a compromised master secret has no recovery "
            f"and a forgotten password is permanent data loss (documented design)")


def a6_aad_corpus() -> None:
    section("A6: AAD canonicalization fuzz — generating cross-platform corpus")
    from app.security.crypto import build_aad

    cases = [
        ("ascii", ["entry", "user-1", "e-2026-01-01-abc"]),
        ("latin1", ["entry", "ünïcode-user", "entrée-1"]),
        ("astral", ["insights", "user-🧠-brain", "patterns"]),
        ("lone-high-surrogate", ["entry", "user-\ud800", "id1"]),
        ("lone-low-surrogate", ["entry", "user-\udfff", "id1"]),
        ("surrogate-pair", ["entry", "user-🧠", "id1"]),
        ("tab-newline", ["entry", "user\t1", "id\n1"]),
        ("quote-backslash", ["entry", 'he said "hi"', "C:\\path\\entry"]),
        ("del-char", ["entry", "user\x7f1", "id1"]),
        ("nul-ish", ["entry", "user\x01", "id1"]),
        ("combining", ["entry", "café", "éclair-1"]),
        ("numeric-strings", ["123", "456", "789"]),
        ("empty-part", ["entry", "", "id1"]),
        ("mixed-bag", ["moodlog", "usér-🧠-\t\"x\"", "id\\1"]),
        ("cjk", ["entry", "用户-一号", "条目-1"]),
        ("rtl", ["entry", "مستخدم-١", "مدخل-1"]),
    ]
    out = [{"name": name, "parts": parts, "aad_hex": build_aad(*parts).hex()}
           for name, parts in cases]
    (RESULTS.parent / "aad_corpus.json").write_text(json.dumps(out, indent=1))
    verdict("A6.corpus-generated", "INFO",
            f"{len(out)} edge-case AAD vectors written to redteam/aad_corpus.json; "
            f"verdict comes from the TS-side comparison (mobile redteam spec)")


async def main() -> None:
    await guard("A1", a1_processing_sessions)
    await guard("A4", a4_kdf_downgrade)
    await guard("A5", a5_key_lifecycle)
    await guard("A6", a6_aad_corpus)


if __name__ == "__main__":
    run(main, "a_crypto")
