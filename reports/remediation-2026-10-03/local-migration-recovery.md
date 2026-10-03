# Recovering a retained local migration conflict

This is an operational recovery procedure, not an implemented end-user conflict chooser. A migration conflict deliberately retains newer ciphertext, the staged original/replacement pair and the encrypted checkpoint. Do not clear site data, delete the checkpoint, overwrite the current record with the staged replacement, or repeat the change with a different intended password.

## Preserve the evidence first

1. Stop editing in all tabs and devices for this account. Keep the affected browser profile intact. Record the public account UUID and the exact error; do not include journal text or passwords in a support ticket.
2. Preserve an encrypted server export from a separate trusted browser profile using the authoritative current password. Its immutable canonical username/UUID, salt, scheme and (for v2) wrapped-data-key/KDF fields are necessary for offline recovery. Export is account-scoped; it does not include the affected device's local draft or migration checkpoint.
3. Take a read-only snapshot of the affected profile's `mindpattern` IndexedDB database, `kv` object store. Include only the exact account-owned rows listed below and its queue scopes. Keep the snapshot offline in an owner-controlled encrypted location. Preserve exact strings and keys; do not trim, parse/rewrite or normalize ciphertext.

| Local evidence | Exact account-bound key |
|---|---|
| Encrypted checkpoint with original/replacement records and retained old data key | `mindpattern.localRotation.<UUID>` |
| Candidate salt and encrypted rotation seed | `mindpattern.rotationSalt.<UUID>`, `mindpattern.rotationSeed.<UUID>` |
| Draft, safety plan, mood, feedback, pending measure, pattern mutes, version maps | `mindpattern.draft.active.<UUID>`, `mindpattern.safetyPlan.<UUID>`, `mindpattern.moodlog.<UUID>`, `mindpattern.feedback.<UUID>`, `mindpattern.pendingMeasure.<UUID>`, `mindpattern.patternMutes.v1.<UUID>`, `mindpattern.entryVersions.<UUID>`, `mindpattern.entryV2Bound.<UUID>` |
| Durable account writing-generation proof (or minimal deleted fence) | `mindpattern.writeGeneration.<UUID>` |
| Account-specific erasure marker, if present | `mindpattern.erase.<UUID>` |
| Queue/rejected/quarantine containers | `mindpattern/queue.v1.{items,rejected,quarantine}.<base64url(origin + NUL + UUID)>` |

A database-wide snapshot also includes other accounts' data. Prefer the scoped export. The checkpoint and stored seed are encrypted; never send an unwrapped data key, authentication verifier, password or decrypted journal to an operator. The server export and local snapshot together preserve public recovery bindings and local ciphertext, but an independently authenticated restoration is still required.

## Confirm remote state before touching local records

A prepared checkpoint is not proof that the server changed the credential. The current client requires the server's authenticated account salt to equal the checkpoint's intended `new_salt` before applying staged replacements.

If the original credential still works, open Settings and repeat the exact intended new password. The client reuses the persisted operation ID, salt, credential/envelope and consent-wrap payload; it must not create a second operation or infer success from a timeout. If the new credential works and its authoritative salt matches, remote finalization is confirmed. Keep both passwords available privately until recovery completes; do not put them in the evidence file.

## Resolve the branch without overwriting writing

An engineer must authenticate the current conflicting record under the current data key or the retained old key using its original domain/AAD. The current checkpoint retains the old key encrypted under the candidate new data key. A readable current value can be resealed as the exact same plaintext under the confirmed current key, but replacement must use a single IndexedDB readwrite compare-and-set against the ciphertext that was actually inspected. If it changes again, retain it and retry; never use separate asynchronous get/set calls.

Keep the staged branch as encrypted recovery evidence until the account owner explicitly confirms which content to retain. Missing/deleted, malformed or independently diverged branches require an explicit restore/keep-both decision; they cannot be safely guessed. The current shipped client stops at this conflict rather than implementing an automatic merge or chooser.

Normal current-client mutations of registered encrypted stores and queue mutation paths require their captured account generation after rotation; this durable marker survives checkpoint cleanup and rejects prior callbacks. Confirmed account-specific erasure can delete its own records and retains a minimal content-free deleted fence. Other account scopes remain usable. Older clients writing IndexedDB directly can bypass this seam: retire unsupported clients and close obsolete tabs before recovery. Verified fresh-login adoption changes only the generation marker, never guesses keys or re-encrypts unreadable ciphertext. Retaining ciphertext alone does not establish competing-device recovery without its retained old-key/KDF binding and authenticated current plaintext; that full matrix remains an acceptance gate.

Before concluding recovery, reopen the draft and safety plan, inspect affected queue items, verify fresh-login decryption and retain the encrypted recovery copy until the owner confirms the contents. The normal resume path removes the checkpoint only after every destination has committed durably.
