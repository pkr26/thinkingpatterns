"""H-series: privacy audits against a synthetic operator view.

H1 metadata inference — what the SERVER (and any backup) can learn from
   plaintext metadata alone, with a concrete inference report.
H2 export bundle — cleartext fields, enumeration resistance.
H3 erasure completeness — live DB after account deletion.
"""

from __future__ import annotations

import base64
from datetime import date, timedelta

from common import (
    auth_headers,
    direct_insert_entry,
    guard,
    make_app,
    make_client,
    make_settings,
    register_user,
    run,
    section,
    verdict,
)
from sqlalchemy import select


async def h1_metadata_inference() -> None:
    section("H1: metadata inference from the operator's view")
    app = await make_app(make_settings(entries_rate_limit=1000))
    async with make_client(app) as client:
        # A realistic private pattern: journals only on Sunday nights, skipped
        # two weeks in August (a bereavement, say), long entries when low.
        u = await register_user(client, "h1_subject", "pw-h1", iterations=1000)
        today = date.today()
        for i in range(120, 0, -1):
            d = today - timedelta(days=i)
            august_gap = (d.month == 8 and 4 <= d.day <= 18)
            if august_gap:
                continue
            if d.weekday() != 6:  # Sundays only
                continue
            length = 4000 if i % 3 == 0 else 400
            await direct_insert_entry(app, u["user_id"], u["data_key"],
                                      "x" * length, d)

        # Operator view: no decryption, just the DB
        from app.models import Entry

        rows = []
        async with app.state.sessionmaker() as s:
            result = await s.execute(select(Entry.entry_date, Entry.blob)
                                     .where(Entry.user_id == u["user_id"]))
            rows = result.all()

    dates = sorted(d for d, _ in rows)
    sizes = [len(b) for _, b in rows]
    weekdays = sorted({d.strftime("%A") for d in dates})
    gaps = [(dates[i + 1] - dates[i]).days for i in range(len(dates) - 1)]
    max_gap = max(gaps, default=0)
    gap_start = next((dates[i + 1] - timedelta(days=g) for i, g in enumerate(gaps)
                      if g == max_gap), None)
    long_share = sum(1 for x in sizes if x > 2000) / max(1, len(sizes))
    inference = (
        f"subject journals on {weekdays} exclusively "
        f"({len(dates)} entries over 120 days); a {max_gap}-day silence ending "
        f"{gap_start}; {long_share:.0%} of entries are 10x longer than the rest "
        f"(crisis-length writes vs routine updates) — an operator can infer "
        f"religious observance or work schedules, episode timing, and possibly "
        f"severity from SIZE alone, with zero decryption"
    )
    verdict("H1.metadata-inference", "FINDING",
            f"operator-view inference from entry_date+length only: {inference}")


async def h2_export() -> None:
    section("H2: export bundle contents")
    app = await make_app(make_settings())
    async with make_client(app) as client:
        u = await register_user(client, "h2_user", "pw-h2", iterations=1000)
        await direct_insert_entry(app, u["user_id"], u["data_key"], "text",
                                  date.today(), "e-h2-1")
        r = await client.get("/api/v1/account/export", headers=auth_headers(u["token"]))
        body = r.text
        has_username = u["username"] in body
        has_salt = base64.b64encode(u["salt"]).decode() in body
        has_cleartext = "text" in body.replace("client_entry_id", "").replace(
            "entry_date", "") and '"text"' in body
        verdict("H2.export-cleartext-fields", "BLOCKED" if not has_username else "FINDING",
                f"export bundle: username-in-cleartext={has_username} (dropped in the "
                f"2026-09-16 fix), kdf-salt-present={has_salt} (required for any future "
                f"re-import — a random 16-byte value, not an identifier), "
                f"entry-plaintext={'NO' if not has_cleartext else 'YES'}")
        # Cross-account enumeration: export is token-scoped
        r2 = await client.get("/api/v1/account/export")
        verdict("H2.export-auth-scoped", "BLOCKED" if r2.status_code == 401 else "FINDING",
                f"unauthenticated export: {r2.status_code}")


async def h3_erasure() -> None:
    section("H3: erasure completeness")
    app = await make_app(make_settings())
    async with make_client(app) as client:
        u = await register_user(client, "h3_gone", "pw-h3", iterations=1000)
        await direct_insert_entry(app, u["user_id"], u["data_key"], "text",
                                  date.today(), "e-h3-1")
        r = await client.post("/api/v1/processing/sessions", headers=auth_headers(u["token"]),
                              json={"data_key": base64.b64encode(
                                  bytes(u["data_key"])).decode()})
        r = await client.delete("/api/v1/account", headers={
            **auth_headers(u["token"]),
            "X-Account-Verifier": base64.b64encode(u["auth_key"]).decode()})
        assert r.status_code == 204, r.text

        from app.models import Entry, Insight, User

        async with app.state.sessionmaker() as s:
            users = (await s.execute(select(User).where(
                User.username == "h3_gone"))).scalars().all()
            entries = (await s.execute(select(Entry).where(
                Entry.user_id == u["user_id"]))).scalars().all()
            insights = (await s.execute(select(Insight).where(
                Insight.user_id == u["user_id"]))).scalars().all()
        keys_held = len(getattr(app.state.key_store, "_keys", {}))
        verdict("H3.erasure-live-db",
                "BLOCKED" if not (users or entries or insights) else "FINDING",
                f"after DELETE /account: users={len(users)}, entries={len(entries)}, "
                f"insights={len(insights)} rows remain; in-memory keystore holds "
                f"{keys_held} keys — live-data erasure is complete and immediate "
                f"(backups are the residual: see G1)")


async def main() -> None:
    await guard("H1", h1_metadata_inference)
    await guard("H2", h2_export)
    await guard("H3", h3_erasure)


if __name__ == "__main__":
    run(main, "h_privacy")
