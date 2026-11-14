"""Native returned index remains usable throughout its stable generation."""

from pathlib import Path

import pytest
from sqlalchemy import select

from app.api import _audit
from app.config import Settings
from app.models import AccessLog
from tests.helpers import ClientEmulator


@pytest.fixture
def settings(tmp_path):
    journal = tmp_path / "owned-stable-audit.journal"
    journal.touch(mode=0o600)
    return Settings(
        environment="development",
        database_url="sqlite+aiosqlite://",
        audit_journal_path=str(journal),
    )


@pytest.mark.asyncio
async def test_native_stable_generation_keeps_previously_returned_evidence_usable(client, app):
    owner = ClientEmulator("native-stable-journal", "native-stable-journal-password")
    await owner.register(client)
    async with app.state.sessionmaker() as session:
        head = await session.scalar(
            select(AccessLog)
            .where(AccessLog.user_id == owner.user_id)
            .order_by(AccessLog.chain_seq.desc())
        )
        expected = (head.chain_seq, head.entry_hash, head.entry_mac)
    journal = app.state.settings.audit_journal_path
    first = _audit.reusable_journal_evidence_index(journal)
    first_path = Path(first.path)
    second = None
    try:
        # Same configured path and no intervening journal write. Maintenance
        # may retain its returned index while this stable generation drains.
        second = _audit.reusable_journal_evidence_index(journal)
        kept = first.get(owner.user_id)
        assert (kept.seq, kept.entry_hash, kept.entry_mac) == expected
        current = second.get(owner.user_id)
        assert (current.seq, current.entry_hash, current.entry_mac) == expected
        assert kept.conflict is False and current.conflict is False
    finally:
        _audit.close_reusable_journal_evidence_index()
        first.close()
        if second is not None:
            second.close()
        # A broken generation may recreate its previously unlinked own file
        # on get. Clean only the constructor-returned path owned by this test.
        first_path.unlink(missing_ok=True)
