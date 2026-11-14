"""Native compacted journal bytes and diagnostic output across repeated owners."""

from app.api import _audit


def test_compaction_preserves_latest_native_evidence_across_repeated_owner_lookups(tmp_path):
    journal = tmp_path / "journal"
    stamp = "2026-10-01T00:00:00+00:00"
    first = "0" * 32

    def line(owner, sequence=1):
        return f"{owner} {sequence} {'b' * 64} {'c' * 64} {stamp}\n"

    others = [f"{owner:032x}" for owner in range(1, 1025)]
    journal.write_text(
        line(first) + "".join(line(owner) for owner in others) + line(first, 2) + line(first, 3)
    )
    assert _audit.compact_audit_journal(str(journal), "2026-10-03T00:00:00+00:00") == (
        1025,
        2,
    )
    assert journal.read_text() == "".join(line(owner) for owner in others) + line(first, 3)
    with _audit.build_journal_evidence_index(str(journal)) as reader:
        assert reader.get(first) == _audit.JournalEvidence(3, "b" * 64, "c" * 64, stamp, False)
        assert len(reader.all_evidence()) == 1025
