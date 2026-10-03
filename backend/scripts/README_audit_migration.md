Runtime verification refuses a missing audit MAC. Do not automatically seal a
NULL MAC: it may be a stripped seal rather than a genuine legacy record.

For genuine pre-MAC installations, preserve an immutable database and journal
backup, then run `python scripts/seal_legacy_audit.py snapshot --output review.json`
under the application's existing environment. The command prints the exact
snapshot SHA-256 and refuses broken hashes, links, existing MACs, or journal tail
anchors. The snapshot contains sensitive access metadata and is created 0600.

An accountable operator must independently reconcile every legacy row against
trusted historical backups and operational records. Record identity, evidence
references, investigation results, and the specific reviewed digest in an
attestation file. A matching hash chain alone does not establish legacy truth.
If provenance cannot be established, preserve the evidence and investigate;
do not reseal it just to remove an alarm.

Stop all API, worker, and maintenance writers. Run:

```
python scripts/seal_legacy_audit.py seal --snapshot review.json \
  --sha256 REVIEWED_SHA256 --attestation attestation.txt \
  --receipt migration-receipt.json --maintenance-confirmed
```

The application file/advisory guards and a database write lock fence the
transaction. An unchanged snapshot is required; only missing MACs are filled.
Keep the receipt beside immutable review evidence, verify the resulting chains
with the normal keyed verifier, and restart the application. A receipt prepared
before a failed commit is not proof of completion; normal verification is the
acceptance gate. These new MACs protect the reviewed state going forward, and
cannot retrospectively authenticate historical events.
