"""B-series: authentication & session red-team audits.

B1 auth_key replay (password-equivalence), destructive-op verifier replay,
token forgery/type-confusion, epoch revocation coverage
B2 rate-limit evasion: XFF rightmost trust, IPv6 /64, key-eviction flood,
fixed-window boundary burst, victim-lockout
B3 enumeration: registration oracle, salt decoys, login timing, username recycling
"""

from __future__ import annotations

import base64
import statistics
import time

from common import (
    auth_headers,
    guard,
    make_app,
    make_client,
    make_settings,
    register_user,
    run,
    section,
    verdict,
)


async def b1_verifier_and_tokens() -> None:
    section("B1: auth_key replay, verifier replay, token forgery")
    # llm_url MUST be set (a dev-loopback URL is enough — the consent
    # endpoint only fingerprints the policy, it never calls the endpoint):
    # without it llm-consent 409s `llm_unavailable` on EVERY attempt and
    # the verifier-enables-llm-egress egress check below is structurally
    # dead: it would read BLOCKED off a 409 without ever observing whether
    # the stolen verifier passed re-authentication (2026-09-19 audit, H-15).
    app = await make_app(make_settings(llm_url="http://127.0.0.1:9/v1"))
    async with make_client(app) as client:
        user = await register_user(client, "b1_user", "pw-b1", iterations=1000)
        captured_verifier = base64.b64encode(user["auth_key"]).decode()

        # The verifier IS the login credential — replay after logout
        r = await client.post("/api/v1/auth/logout", headers=auth_headers(user["token"]))
        assert r.status_code == 204, r.text
        dead = await client.get("/api/v1/entries", headers=auth_headers(user["token"]))
        r = await client.post("/api/v1/auth/login", json={
            "username": "b1_user", "verifier": captured_verifier})
        verdict("B1.verifier-replay",
                "FINDING" if r.status_code == 200 else "BLOCKED",
                f"old bearer after logout={dead.status_code} (epoch revocation works), but the "
                f"captured verifier logs straight back in ({r.status_code}): the auth_key is a "
                f"password-equivalent bearer credential with no rotation/revocation path — "
                f"one interception = persistent account access")

        # Stolen verifier enables the LLM egress consent (destructive op)
        fresh = r.json()["token"]
        r = await client.put("/api/v1/account/llm-consent",
                             headers=auth_headers(fresh),
                             json={"enabled": True, "verifier": captured_verifier})
        verdict("B1.verifier-enables-llm-egress",
                "FINDING" if r.status_code == 200 else "BLOCKED",
                f"captured verifier flipped llm-consent ON ({r.status_code}) — a stolen "
                f"credential chain reaches the plaintext-egress switch, the most sensitive "
                f"setting in the system")

        # 2026-09-18 round-2 oracle campaign (N8): the checks above never
        # send a WRONG verifier, so a mutant that stops verifying replays
        # entirely still read "BLOCKED" here. Re-authentication must reject
        # a wrong password-equivalent on every destructive surface.
        wrong_verifier = base64.b64encode(b"\x00" * 32).decode()
        wrong_codes = {}
        r = await client.put("/api/v1/account/llm-consent",
                             headers=auth_headers(fresh),
                             json={"enabled": True, "verifier": wrong_verifier})
        wrong_codes["llm-consent"] = r.status_code
        r = await client.delete("/api/v1/account",
                                headers={**auth_headers(fresh),
                                         "X-Account-Verifier": wrong_verifier})
        wrong_codes["account-delete"] = r.status_code
        verdict("B1.wrong-verifier-rejected",
                "BLOCKED" if set(wrong_codes.values()) == {403} else "FINDING",
                f"a WRONG verifier on destructive ops -> {wrong_codes} (must be flat 403; "
                f"anything else means re-authentication stopped comparing the proof)")

        # Hostile token shapes at the API boundary: all must be flat 401, no 500
        hostile = [
            "", "Bearer", "Bearer x", "Bearer a.b", "Bearer ..", "Bearer %00.%00",
            "Bearer " + "A" * 100000, "Bearer ..%2e", "Bearer null.null",
            "Bearer eyJ1aWQ", "Bearer .sig", "Bearer body.",
        ]
        codes = set()
        for h in hostile:
            r = await client.get("/api/v1/entries", headers={"Authorization": h} if h else {})
            codes.add(r.status_code)
        verdict("B1.hostile-tokens", "BLOCKED" if codes <= {401, 422} else "FINDING",
                f"10 hostile token shapes -> {sorted(codes)} (no crash, flat denials)")

        # Signed-token payload type confusion (requires the secret: leaked-secret scenario)
        from app.security import tokens as tok

        def forged(exp):
            import base64 as b64
            import hashlib
            import hmac
            import json as js
            payload = {"uid": user["user_id"], "iat": int(time.time()), "exp": exp, "ep": 1}
            body = b64.urlsafe_b64encode(js.dumps(payload, separators=(",", ":"),
                                                  sort_keys=True).encode()).rstrip(b"=").decode()
            sig = b64.urlsafe_b64encode(hmac.new(b"redteam-audit-secret-32-chars-min!!",
                                                 body.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
            return f"{body}.{sig}"

        outcomes = {}
        for name, exp in [("string", "99999999999"), ("negative", -1),
                          ("huge", 10**19), ("nan-str", "NaN")]:
            try:
                tok.verify_token(forged(exp), "redteam-audit-secret-32-chars-min!!")
                outcomes[name] = "accepted"
            except tok.TokenError:
                outcomes[name] = "TokenError"
            except Exception as e:  # noqa: BLE001
                outcomes[name] = f"UNCAUGHT {type(e).__name__}"
        leak = [k for k, v in outcomes.items() if v.startswith("UNCAUGHT")]
        accepted = sorted(k for k, v in outcomes.items() if v == "accepted")
        # The summary must agree with the recorded outcomes: "huge"
        # (a well-signed far-future exp) is legitimately ACCEPTED, so the
        # blanket "all rejected as TokenError" text used to contradict the
        # probe's own data (2026-09-19 audit, L-45).
        if leak:
            detail = (f"verify_token outcomes with a leaked secret: {outcomes} — "
                      f"{'/'.join(leak)} raise uncaught exceptions "
                      f"(would surface as 500, robustness only)")
        elif accepted:
            detail = (f"verify_token outcomes with a leaked secret: {outcomes} — "
                      f"no uncaught exceptions; accepted shape(s): {', '.join(accepted)} "
                      f"(a well-signed token with a merely far-future exp — forging "
                      f"still requires the secret); the rest rejected as TokenError")
        else:
            detail = f"verify_token outcomes with a leaked secret: {outcomes} — all rejected as TokenError"
        verdict("B1.token-type-confusion",
                "FINDING" if leak else "BLOCKED",
                detail)

        # Epoch coverage across both mounts
        r = await client.get("/api/entries", headers=auth_headers(user["token"]))
        verdict("B1.epoch-both-mounts", "BLOCKED" if r.status_code == 401 else "FINDING",
                f"pre-logout token on legacy mount /api: {r.status_code}")


async def b2_rate_limits() -> None:
    section("B2: rate-limit evasion")
    from app.cache import FixedWindowCounter, client_key_from_scope

    # IPv6 /64 aggregation holds (raw ASGI scope — the same input the
    # middleware passes, immune to Request-wrapper signature changes)
    keys = {client_key_from_scope({"client": (f"2001:db8::{i:x}", 1234)}) for i in range(50)}
    verdict("B2.ipv6-aggregation", "BLOCKED" if len(keys) == 1 else "FINDING",
            f"50 rotated IPv6 addresses inside one /64 collapse to {len(keys)} bucket(s)")

    # XFF rightmost-trust: direct-to-origin attack when proxy headers are trusted
    app = await make_app(make_settings(trust_proxy_headers=True, auth_rate_limit=5))
    async with make_client(app) as client:
        allowed = 0
        for i in range(20):
            r = await client.post("/api/v1/auth/salt", json={"username": f"nobody-{i}"},
                                  headers={"X-Forwarded-For": f"198.51.100.{i % 256}"})
            if r.status_code != 429:
                allowed += 1
        verdict("B2.xff-direct-origin", "FINDING" if allowed > 10 else "BLOCKED",
                f"with TRUST_PROXY_HEADERS=1 and direct origin access, {allowed}/20 requests "
                f"passed a 5/min limit using one spoofed XFF entry per request (deployment-"
                f"conditional: safe only behind a proxy that always appends its observation)")

    # Key-eviction flood against the 10k tracked-key cap
    counter = FixedWindowCounter()
    for _ in range(10):
        counter.hit("auth-salt:1.2.3.4", 60)  # victim at the limit (count=10)
    for i in range(11_000):  # attacker floods 11k buckets with count 11 (>= victim's)
        k = f"auth-salt:203.0.113.{i}"
        for _ in range(11):
            counter.hit(k, 60)
    after = counter.hit("auth-salt:1.2.3.4", 60)
    verdict("B2.eviction-flood",
            "PARTIAL",
            f"after 121k attacker hits across 11k keys, victim bucket count={after.count} "
            f"(reset={'yes' if after.count <= 2 else 'no'}): eviction is possible but costs "
            f"~121k requests to reset ONE near-limit bucket — smallest-count/oldest bias makes "
            f"flooding strictly worse for the attacker than waiting out the window")

    # Fixed-window boundary burst (counter level)
    c = FixedWindowCounter()
    first_burst = [c.hit("k", 1, now=100.0).count for _ in range(10)]
    second = [c.hit("k", 1, now=101.05).count for _ in range(10)]
    verdict("B2.fixed-window-boundary", "PARTIAL",
            f"window=1s, limit=10: 10 hits at t=100.0 (counts {first_burst[-1]}), 10 more at "
            f"t=101.05 reset to {second[0]} — {first_burst[-1] + len(second)} hits inside "
            f"~1.05s vs nominal 10/s: classic fixed-window doubling, bounded by capacity "
            f"limiters on the expensive endpoints")

    # Anonymous victim lockout: failed-only per-username counting
    app = await make_app(make_settings(auth_rate_limit=1000))
    async with make_client(app) as client:
        victim = await register_user(client, "b2_victim", "pw-v", iterations=1000)
        wrong = base64.b64encode(b"\x01" * 32).decode()
        for _ in range(30):  # attacker sprays failures at the victim's name
            await client.post("/api/v1/auth/login",
                              json={"username": "b2_victim", "verifier": wrong})
        r = await client.post("/api/v1/auth/login", json={
            "username": "b2_victim",
            "verifier": base64.b64encode(victim["auth_key"]).decode()})
        verdict("B2.victim-lockout", "BLOCKED" if r.status_code == 200 else "FINDING",
                f"after 30 failed sprays the real user still logs in: {r.status_code} "
                f"(check-then-count-on-failure holds)")


async def b3_enumeration() -> None:
    section("B3: enumeration, decoys, timing, recycling")
    app = await make_app(make_settings(auth_rate_limit=1000))
    async with make_client(app) as client:
        await register_user(client, "b3_known", "pw-b3", iterations=1000)

        # Registration availability oracle (documented as accepted)
        r1 = await client.post("/api/v1/auth/register", json={
            "username": "b3_known", "salt": base64.b64encode(b"\x01" * 16).decode(),
            "verifier": base64.b64encode(b"\x01" * 32).decode()})
        verdict("B3.registration-oracle", "INFO",
                f"re-registering a taken name -> {r1.status_code} "
                f"(documented, unavoidable availability oracle; per-username conflict bucket "
                f"throttles mass harvesting)")

        # Salt decoys: deterministic, distinguishable from real only with the secret
        s1 = (await client.post("/api/v1/auth/salt", json={"username": "b3_known"})).json()["salt"]
        s2 = (await client.post("/api/v1/auth/salt", json={"username": "b3_known"})).json()["salt"]
        d1 = (await client.post("/api/v1/auth/salt", json={"username": "ghost-404"})).json()["salt"]
        d2 = (await client.post("/api/v1/auth/salt", json={"username": "ghost-404"})).json()["salt"]
        stable = s1 == s2 and d1 == d2 and s1 != d1
        verdict("B3.salt-decoys", "BLOCKED" if stable else "FINDING",
                f"real salt stable={s1 == s2}, decoy stable={d1 == d2}, distinct={s1 != d1} "
                f"— existence not leaked through /auth/salt")

        # Login timing: known-user-wrong-key vs unknown-user (both burn scrypt)
        wrong = base64.b64encode(b"\x02" * 32).decode()

        async def time_login(name):
            t0 = time.perf_counter()
            await client.post("/api/v1/auth/login", json={"username": name, "verifier": wrong})
            return (time.perf_counter() - t0) * 1000

        known = [await time_login("b3_known") for _ in range(4)]
        unknown = [await time_login(f"ghost-{i}") for i in range(4)]
        km, um = statistics.median(known), statistics.median(unknown)
        ratio = max(km, um) / max(1e-9, min(km, um))
        verdict("B3.login-timing", "BLOCKED" if ratio < 1.35 else "FINDING",
                f"median login latency known={km:.0f}ms vs unknown={um:.0f}ms "
                f"(ratio {ratio:.2f}, samples {len(known)}v{len(unknown)}) — equal-CPU "
                f"scrypt burn keeps them indistinguishable within noise")

        # Username recycling after deletion
        u = await register_user(client, "b3_recycle", "pw-r", iterations=1000)
        await direct_one(app, u)  # leave some data behind
        r = await client.delete("/api/v1/account", headers={
            **auth_headers(u["token"]),
            "X-Account-Verifier": base64.b64encode(u["auth_key"]).decode()})
        assert r.status_code == 204, r.text
        u2 = await register_user(client, "b3_recycle", "pw-r2", iterations=1000)
        r = await client.get("/api/v1/entries", headers=auth_headers(u2["token"]))
        count = len(r.json())
        verdict("B3.username-recycling", "BLOCKED" if count == 0 else "FINDING",
                f"deleted name re-registered; new account sees {count} old entries "
                f"(no data bleed across account generations)")


async def direct_one(app, user) -> None:
    from datetime import date

    from common import direct_insert_entry

    await direct_insert_entry(app, user["user_id"], user["data_key"],
                              "old owner entry", date.today(), "e-recycle-1")


async def main() -> None:
    await guard("B1", b1_verifier_and_tokens)
    await guard("B2", b2_rate_limits)
    await guard("B3", b3_enumeration)


if __name__ == "__main__":
    run(main, "b_auth")
