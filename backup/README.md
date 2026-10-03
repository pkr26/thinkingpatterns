# Authenticated database backups

The optional `backup` Compose profile writes one `pg_dump -Fc` file per day.
Each `*.dump.enc` is encrypted with AES-256-CBC/PBKDF2 and has a sibling
`*.dump.enc.hmac`. The HMAC uses a domain-separated key derived from
`BACKUP_KEY`; do not decrypt or restore a dump until the tag verifies.
PBKDF2 runs at an explicit 600,000 iterations (`-iter 600000`, pinned well
above openssl's 10k default); every decrypt command must pass the same
count or it will fail rather than guess.

With the backup profile running, verify and inspect a dump in the worker:

```bash
docker compose --profile backups exec backup sh -ceu '
  set -- /backups/mindpattern-*.dump.enc
  set -o pipefail
  mindpattern-backup-mac decrypt "$1" | pg_restore --list
'
```

The decrypt command verifies the HMAC before emitting any plaintext. It
copies ciphertext into an owner-only, automatically deleted disk snapshot,
then authenticates and decrypts those exact bytes even if the original is
changed concurrently. Reserve scratch space equal to the encrypted dump in
the backup directory; for a read-only source, set `BACKUP_SNAPSHOT_DIR` to a
writable directory with sufficient disk space. Plaintext is streamed only.
It uses
one resolver for encryption, authentication and decryption: a nonempty
`BACKUP_KEY` takes precedence; otherwise `BACKUP_KEY_FILE` is read and trimmed.
Use one source per deployment where possible. Keys must be a single line of at
most 256 UTF-8 bytes (the cap avoids OpenSSL passphrase truncation); the
helper rejects embedded newlines/NUL and passes the secret to OpenSSL by file
descriptor, never as a process argument. Use the same pipeline to restore. A missing or
mismatched `.hmac` is a hard stop. The worker uses `encrypt CIPHERTEXT SIDECAR`
to encrypt and authenticate with one resolved key even during secret-file
rotation. Publish the ciphertext and sidecar only after that command succeeds.
Keep retired backup keys securely available until all backups using them
expire; replacing a mounted key does not re-encrypt existing backups.
To exercise a full restore into a
throwaway same-major Postgres container and compare live row counts, run:

```bash
BACKUP_KEY='the same secret used by the backup service' \
  bash backend/scripts/rehearse_restore.sh
```

Older pre-authentication dumps have no sidecar and must be treated as legacy
material: keep them isolated, validate their provenance separately, and
expire them on the existing retention schedule rather than silently accepting
them as equivalent to new backups. Dumps encrypted before 2026-09-19 used
openssl's 10k default iteration count (the header does not record it); decrypt
those without `-iter`, and let retention retire them.
