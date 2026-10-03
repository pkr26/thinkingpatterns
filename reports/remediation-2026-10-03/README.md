# October 3 remediation evidence

This directory records engineering changes after the historical audit at
`9c1ba47508f474afc5f70588dd2771d80c2eece7`. Read the root
[status](../../REMEDIATION_STATUS.md) for final outcomes and release limits.

Client/backend reports map fixes to the original finding IDs. Use the exact
log links in the root status and owner reports as the authoritative checkpoints;
a `final` filename alone does not establish freshness. For example,
`redteam-final-current.log` supersedes the earlier `redteam-final.log`. Earlier
failed probes remain development history, not current passes.
`source-manifest.json` records the final source/evidence hashes and change inventory.

`browser-journeys.py` reproduces real Chrome/WebCrypto/IndexedDB journeys
against **freshly seeded synthetic loopback accounts**. It changes those
accounts' credentials and sharing identity; never use it against user data.
Fresh setup: create a separate development SQLite database, run
`backend/.venv/bin/python e2e_gui/audit_seed.py --api http://127.0.0.1:8918 --db-url sqlite+aiosqlite:///<your-disposable-db>`,
serve the current built clients through Vite's HTTPS preview with the API
proxy, then invoke the script using a Python environment containing Playwright.
The recorded environment used macOS Chrome and a locally generated TLS
certificate; certificate validation was relaxed only for the loopback preview.
The final persistent-generation check is `browser-patient-generation.py`;
`browser-functional-current.py` and `browser-final-readonly.py` exercise the
resulting synthetic credentials on the latest built artifacts.
The web release build still rejects unconfigured public security contact/URL.

`android-progress-ui.xml` and `android-history-final-ui.xml` come from the
owned Android emulator running the linked native crypto engine. Secure-screen
protection makes authenticated screenshots black; UIAutomator verifies the
accessible state without disabling that protection.
`android-draft-restored-ui.xml` and `android-draft-after-ack-restart-ui.xml`
record the earlier clean-disk checkpoint. The final frozen-source check is
`android-draft-structured.py`, with `validation-logs/android-structured-draft-final.log`
and `android-structured-draft-*.xml`: text, mood, energy, sleep and tag survive
restart, acknowledged ciphertext decrypts in History, and a second restart
does not resurrect the draft. This script requires the owned emulator and
synthetic fixture described in its header. Earlier warm-reload/navigation
and interrupted harness attempts remain as failed development history.
The debug-only upstream warning banner was dismissed through its observed
close control; capture protection remained enabled.
Earlier XML/runtime logs
include the crypto-loading failure that prompted `engine.native.ts`.

Backup/upgrade evidence uses owned PostgreSQL databases ending in `_test`,
known synthetic keys, the pinned backup image and real OpenSSL/pg_restore.
It establishes preservation at that checkpoint, not a production RPO/RTO,
remote-object recovery, public deployment or delivered alert guarantee.

Historical simulations, original audit and validation logs remain separate.
Native hardware, full Xcode/iOS archives, human accessibility/usability,
language/clinical assessment, provider accuracy and deployed load remain
unverified unless the root status explicitly records new evidence.
