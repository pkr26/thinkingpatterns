# Restore the November 14 fresh mutation campaign

The byte-exact evidence is stored in the private repository
<https://github.com/pkr26/thinkingpatterns-mutation-backup-2026-11-14/releases/tag/fresh-2026-11-14>.
Sign in with an account that can access that repository and download **every**
release asset into one directory. A public clone alone contains the safe outcome
ledgers and checksums, not the private raw logs.

Use Python 3.10 or newer; verification and restoration require only the standard
library. Keep enough free space for the compressed assets and approximately
twice the manifest's restored-byte count during restoration. Dependencies are
not bundled and no test or mutation command is executed by this helper.

Prefer running `verify_restore.py` from the cloned public repository. It
automatically anchors the private backup manifest to the committed
`backup-catalog.json` beside the script, in addition to checking the downloaded
checksums. If using the helper downloaded from the private release, pass
`--catalog /path/to/cloned/reports/mutation-campaign-2026-11-14-fresh/backup-catalog.json`.
This detects coordinated changes to the downloaded manifest and checksum file.

```sh
python3 verify_restore.py --assets /path/to/downloaded-assets
python3 verify_restore.py --assets /path/to/downloaded-assets --restore /new/path/fresh
python3 verify_restore.py --assets /path/to/downloaded-assets --check-restored /new/path/fresh
```

The restore destination must be new. The helper never overwrites an existing
directory. It verifies asset SHA-256 values, every deduplicated raw content
object, every restored original file, final backend result/receipt hashes,
canonical backend IDs, and frontend inventories/source bytes. No symlinks or
archive path traversal are accepted.

Historical absolute paths inside evidence JSON remain **unchanged**, preserving
their original hashes. The verifier translates paths in memory from the
manifest's `originalCampaignRoot` to the chosen restore directory. For manual
inspection, replace that prefix only when opening a referenced file; do not edit
hashed originals. Archived live supervisors contain machine-specific paths and
finished-state locks, so do not execute them as a migration/bootstrap command.

The archive excludes redundant runtime copies, installed dependencies, caches,
runtime databases, PID/lock files, local notification/session orchestration,
environment files, private-key files and machine-specific symlinks. Exact
excluded paths and reasons are in the private `excluded-paths.json`. Frozen
source inputs and historical harness overrides remain backed up separately from
the current code branch. Source snapshots can contain older reports as immutable
input bytes; those older reports are not reused in the current campaign totals.

`_migration-validation/` contains the later code-validation logs, tracked
working-tree patch and Git revision identifiers captured for laptop migration.
These are provenance for the code being saved, not additional mutation controls.
`_migration-public-export/` contains the safe public export files as they existed
when the private archive was built.

The unmodified private logs may contain generated synthetic tokens, keys and
journal text. Keep the backup private. The public outcome ledgers omit those
free-form fields; restoring the raw archive does not authorize publishing it.

After cloning the public code on the new laptop, use its normal setup
instructions to install dependencies. This backup is an evidence recovery
bundle, not a portable virtual environment or a claim that unresolved survivors,
timeouts and oracle errors have been fixed.
