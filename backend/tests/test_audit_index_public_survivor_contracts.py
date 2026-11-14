"""Returned diagnostic index remains usable for the same journal generation."""

from app.api import _audit


def test_same_journal_key_reconfiguration_keeps_returned_diagnostic_reader_usable(tmp_path):
    owner, stamp = "a" * 32, "2026-10-01T00:00:00+00:00"
    journal = tmp_path / "journal"
    journal.write_text(f"{owner} 1 {'b' * 64} {'c' * 64} {stamp}\n")
    old_keys = dict(_audit._configured_mac_keys)
    old_version = _audit._configured_current_mac_key_version
    old_path = _audit._configured_journal_path
    try:
        _audit.configure_audit_mac_key(b"k" * 32, str(journal))
        reader = _audit.reusable_journal_evidence_index(str(journal))
        _audit.configure_audit_mac_key(b"m" * 32, str(journal))
        # This consumes the returned diagnostic interface, not its object
        # identity, path name, private cache dictionary or source text.
        assert reader.get(owner) == _audit.JournalEvidence(1, "b" * 64, "c" * 64, stamp, False)
        assert reader.owner_ids_after(None, 10) == [owner]
        assert reader.all_evidence() == {owner: reader.get(owner)}
    finally:
        _audit.close_reusable_journal_evidence_index()
        _audit.configure_audit_mac_key(
            None, old_path, key_version=old_version, previous_keys=old_keys
        )
