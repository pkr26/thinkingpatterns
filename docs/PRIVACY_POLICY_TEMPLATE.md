# Privacy policy template — Fathom deployment

> **STATUS: TEMPLATE — LEGAL-REVIEW REQUIRED.** Plain-language text an
> operator can adapt and publish. Every bracket is a decision only the
> deploying organization can make. The technical claims (what is
> encrypted, what the server holds, what deletion does) describe the
> product as shipped and verified 2026-10-04 — do not strengthen them
> without a code change to back the claim.

`OPERATOR-FILL: legal entity, effective date, jurisdictions covered,
contact address/email for privacy requests, supervisory authority if
EU/EEA.`

## What we are

Fathom is designed as a personal journaling and pattern-observation app. You
write journal entries; after 30 active days the app shows you patterns
from your OWN writing (for example, that a topic tends to appear on
Sundays, or that the day after poor sleep your entries read lower). It
makes no diagnosis, treatment recommendation, or individual risk prediction,
and every pattern card shows its evidence. `LEGAL/REGULATORY RELEASE GATE:
qualified counsel must assess the final intended use, named wellbeing
questionnaires, clinician-sharing workflow, jurisdictions, and marketing
before the operator characterizes medical-device, HIPAA/HBNR, or other legal
status. Do not publish a categorical "not a medical device" conclusion from
this template.`

## What you write is encrypted on your device

Your entries, wellbeing questionnaires (PHQ-9, GAD-7 and PHQ-2), pattern
results, and daily questions are encrypted on your device (or in your
browser, for the web app) before they reach our servers, using
AES-256-GCM with a key derived from your password. Our servers store
ciphertext they cannot read without a client-supplied key. Legacy accounts
derive the data key from the password master key. New accounts use a random
32-byte data key wrapped under a password-derived HKDF key-encryption key;
the server stores the opaque wrap, PBKDF2 parameters/salt, and a scrypt
authentication verifier, never the password or unwrapped data key. A
database-only leak therefore yields encrypted content plus the sensitive
metadata listed below, not journal plaintext by itself.

The one deliberate exception: to compute your patterns, the app sends
your key to the server inside a single-use processing session that
lives in memory for at most five minutes and is destroyed the moment
your recompute finishes. During that window the server can read your
entries. This is the trade-off of server-side analysis today; an
on-device analysis path exists and is growing.

**Journal-pattern analysis is deterministic.** The production recompute path
does not send journal text to an LLM. Legacy AI configuration/consent fields
remain for migration compatibility and are not an active processing purpose.
Voice transcription and any separately enabled translation are distinct
provider disclosures described below.

## What we DO hold

Even with encrypted content, we hold some information about every
account. In the spirit of no surprises, here is the complete list:

- your **username** (we never ask for email or phone);
- authentication and recovery metadata: password-derivation parameters and
  salt, a scrypt verifier, wrapped data-key envelope, token/revocation epoch,
  recovery-kit verifier/wrap and setup time, and therapist MFA enrollment/
  backup-code metadata (never your password, unwrapped data key, or live TOTP
  seed in plaintext);
- the version and server timestamp of the minimum-age confirmation made at
  registration (no date of birth), linked to the account;
- **when** you wrote: the calendar date and receipt time of each entry;
- **how much**: the size of each encrypted entry;
- encrypted wellbeing measures (including instrument/date metadata), pattern
  and question ciphertext/metadata, and saved-recording ciphertext plus object
  identifiers, size, duration, creation/expiry, and deletion-retry metadata;
- versioned consent and withdrawal events for voice/external processing and
  sharing, including disclosure/provider-policy fingerprints and whether
  recording access was shared; these action-history records are linked to
  the account and carry event timestamps;
- **therapist linkage**: if you share with a therapist, the fact of the
  sharing relationship, its consent record, and — if your therapist
  anchors a note to a pattern — a coarse topic id (like "temporal:work");
  the note's text is encrypted under YOUR THERAPIST's password and we
  cannot read it;
- an **access/action log** linked to the affected account: actor and patient
  identifiers, actor role, action and timestamp (never journal content; see
  retention below). The log is hash-chained and HMAC-sealed per patient, so
  silent edits are detectable, with production tail evidence outside the
  database.

A database-only leak exposes this metadata and encrypted blobs. It does not by
itself provide the client key needed to open those blobs; plaintext does exist
briefly in application memory during an authorized processing session and at
an external speech/translation provider when the user has consented.

## App-store privacy disclosures

The operator must make store-console answers match this inventory and the
candidate build. In particular, the Apple App Privacy submission must assess
the account-linked access/action history and consent-event history under
**Product Interaction**, and the linked age-attestation version/timestamp and
account-security metadata under **Other Data Types** (or document the precise
current Store Connect taxonomy mapping approved for the release). The Google
Play Data safety form needs the equivalent account-linked app-activity and
other-data disclosures. `OPERATOR-FILL: attach the Store Connect and Play
Console exports/screenshots for this version.` Repository text cannot submit
or verify those external declarations; a mismatch blocks release.

## Therapist sharing

You can let a therapist see your patterns and, one click deeper, the
entries behind them. Sharing wraps your data key to your therapist's
own key; the server relays but cannot read. When you set up sharing,
both of you compare a 6-digit code and a key fingerprint read aloud —
that comparison is what proves the key really belongs to your
therapist. You can revoke at any time (password required); revocation
ends all future access immediately. Honest limit: what a therapist's
browser already downloaded cannot be un-read.

## Children

Registration requires the versioned `minimum_age_confirmed_v1` affirmation in
the clients and API; the server stores only its version and timestamp, not a
birth date. `OPERATOR-FILL + LEGAL-REVIEW: state the actual minimum age and
jurisdictions. If minors may use the service, describe and implement the
guardian-consent procedure—the product provides no parental-consent
machinery.` Do not publish this policy with that decision unresolved.

## How long we keep things

- **Your journal and measures: until you delete them.** There is no
  automatic expiry. Edit or delete any entry; delete your account and
  everything goes.
- **Encrypted backups: up to [`OPERATOR-FILL: BACKUP_RETENTION_DAYS`,
  default 35] days.** Backups taken before a deletion still contain
  your encrypted data until they age out — that window is part of this
  promise.
- **Access log: [`OPERATOR-FILL: MINDPATTERN_ACCESS_LOG_RETENTION_DAYS`,
  default 730] days after account deletion.** When an account is
  deleted, the record of who accessed its data deliberately survives
  (actor, action, date — never content), so that access to a deleted
  account's data remains auditable. `LEGAL-REVIEW: confirm/adjust this
  window for your jurisdictions and disclose it here.`
- **Daily questions: 90 days**, then removed by the scheduled retention sweep
  (recompute also enforces the boundary).
- **Voice recordings you choose to keep:** `OPERATOR-FILL:
  MINDPATTERN_AUDIO_RETENTION_DAYS, default 30` days. The application uses a
  durable deletion queue and inventory reconciliation; the operator must also
  configure an independent object-store/host lifecycle ceiling and disclose
  the deployed value.
- **Speech/translation provider copies (only after consent):** per the named
  provider terms completed below. Journal-pattern LLM dispatch is disabled.
- **Pairing codes: 15 minutes, single use.** Processing keys: memory
  only, destroyed at use or ≤5 minutes.

## Your rights

- **See and export your data:** the patient web app downloads the encrypted
  account export, which can be decrypted offline with the supplied tool.
  Full-account mobile export is not available until a reviewed native
  streaming-to-file path ships; mobile can export individually saved local
  recordings. `OPERATOR-FILL: publish an accessible request/handoff channel
  for mobile-only users and response deadline.`
- **Delete**: delete single entries yourself; account deletion
  (password confirmation) removes the account and its full data set
  from the live database — entries, patterns, questionnaires, sharing
  links — subject only to the backup and access-log windows above.
- **Who accessed your data**: the app shows you the full access trail
  for your account, any time.
- **Contact**: `OPERATOR-FILL: privacy contact + supervisory authority
  + (EU/EEA) your right to lodge a complaint.`

## Security measures (summary)

Device-side key derivation (PBKDF2, 600k iterations); random data keys
in password-wrapped envelopes; server-side verifier hashing (scrypt);
rate limiting; strict transport security; no third-party analytics,
ads, or tracking SDKs; every client ships offline crisis resources one
tap away. The full honest picture, including accepted limitations, is
published in the project's security residuals document:
`OPERATOR-FILL: link to the published SECURITY_RESIDUALS or your
equivalent disclosure page — hiding it would contradict this policy's
own claims.`

## Changes

`OPERATOR-FILL: change-notification procedure (the product has no user
email addresses — use the in-app notice path) and policy version
history.`


## Voice journaling (added 2026-09-29, docs/plans/voice-plan.md)

If you record an entry instead of typing it:

- Your recording is sent to a third-party transcription service
  (`OPERATOR-FILL: STT provider name`) only after you explicitly turn voice journaling
  on, and is deleted from our systems immediately after transcription —
  we never store the recording from that step. The service's retention
  of its own copies is governed by its terms, disclosed at consent
  (`OPERATOR-FILL: provider retention/deletion terms`).
- The transcript is stored like every entry: encrypted on your device
  before it reaches us, in a form we cannot read. If you recorded in
  another language and you have separately enabled pattern insights
  (our analysis provider), the text is translated to English by that
  provider before being re-encrypted — voice journaling alone never
  sends your transcript anywhere else (remediated 2026-09-29: the
  translation dispatch is hard-gated on your current analysis consent).
  The translation then rides inside the same encrypted payload so your
  therapist can read it.
- If you keep a recording, it is encrypted on your device (we store only
  ciphertext) and automatically deleted after
  `OPERATOR-FILL: AUDIO_RETENTION_DAYS` days (default 30, with an independently
  configured object-store lifecycle ceiling). You can delete it sooner at any time;
  deleting the entry deletes its recording.
- Your therapist can hear your recordings only if you separately turn on
  "let my therapist hear my recordings" for that therapist, and every
  playback by a therapist is recorded in your access log.
