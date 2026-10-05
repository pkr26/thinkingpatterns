#!/usr/bin/env python3
"""Explicit, offline trust transition after Alembic f4a2d8c6b901.

Stop all API writers and verify the pre-upgrade snapshot before running:
    python bootstrap_entry_guards.py --trusted-bootstrap
Uses the same environment and versioned audit MAC keyring as the API.
Never use this to repair a missing/invalid online guard.
"""

import argparse
import asyncio

from app.config import Settings
from app.db import build_engine, build_sessionmaker
from app.main import _acquire_cross_host_guard, _release_cross_host_guard
from app.security.entry_guard import bootstrap_trusted_entries
from app.singleprocess import single_process_guard


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trusted-bootstrap", action="store_true", required=True)
    parser.parse_args()
    settings = Settings.from_env()
    engine = build_engine(settings.database_url)
    guard = None
    try:
        with single_process_guard(settings.token_secret, settings.database_url):
            guard = await _acquire_cross_host_guard(engine)
            count = await bootstrap_trusted_entries(build_sessionmaker(engine), settings)
            print(f"Trusted entry bootstrap complete: {count} rows; ciphertext unchanged")
    finally:
        await _release_cross_host_guard(guard)
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
