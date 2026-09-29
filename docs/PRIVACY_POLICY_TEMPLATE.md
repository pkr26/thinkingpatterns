# Privacy policy template — MindPattern deployment

> **STATUS: TEMPLATE — LEGAL-REVIEW REQUIRED.** Plain-language text an
> operator can adapt and publish. Every bracket is a decision only the
> deploying organization can make. The technical claims (what is
> encrypted, what the server holds, what deletion does) describe the
> product as shipped and verified 2026-09-26 — do not strengthen them
> without a code change to back the claim.

`OPERATOR-FILL: legal entity, effective date, jurisdictions covered,
contact address/email for privacy requests, supervisory authority if
EU/EEA.`

## What we are

MindPattern is a personal journaling and pattern-observation app. You
write journal entries; after 30 active days the app shows you patterns
from your OWN writing (for example, that a topic tends to appear on
Sundays, or that the day after poor sleep your entries read lower). It
is not a medical device: no diagnosis, no treatment advice, no
prediction — and every pattern card shows the evidence behind it.

## What you write is encrypted on your device

Your entries, wellbeing questionnaires (PHQ-9 and similar), pattern
results, and daily questions are encrypted on your device (or in your
browser, for the web app) before they reach our servers, using
AES-256-GCM with a key derived from your password. Our servers store
ciphertext they cannot read. If our database were stolen, the thief
would get encrypted blobs, not your words.

The one deliberate exception: to compute your patterns, the app sends
your key to the server inside a single-use processing session that
lives in memory for at most five minutes and is destroyed the moment
your recompute finishes. During that window the server can read your
entries. This is the trade-off of server-side analysis today; an
on-device analysis path exists and is growing.

[Optional, only if enabled:] **AI analysis (off by default).** You can
optionally consent to have recent journal text sent to a third-party
AI provider [`OPERATOR-FILL: provider name and retention terms, which
must mirror what the consent screen shows`]. Turning it on requires
re-entering your password; turning it off is one tap. The provider's
own retention applies to what it receives.

## What we DO hold

Even with encrypted content, we hold some information about every
account. In the spirit of no surprises, here is the complete list:

- your **username** (we never ask for email or phone);
- **when** you wrote: the calendar date and receipt time of each entry;
- **how much**: the size of each encrypted entry;
- **therapist linkage**: if you share with a therapist, the fact of the
  sharing relationship, its consent record, and — if your therapist
  anchors a note to a pattern — a coarse topic id (like "temporal:work");
  the note's text is encrypted under YOUR THERAPIST's password and we
  cannot read it;
- an **access log**: who accessed which data, when (see retention
  below). Since 2026-09-26 this log is hash-chained per patient, so
  silent edits to it are detectable.

A database leak would reveal when and how much you wrote — never what.

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

`OPERATOR-FILL + REQUIRED CONTROL: the product ships NO age gate —
before public launch, enable the self-declared 18+ registration
confirmation in every client, and state here either (a) the service is
for adults only (18+), or (b) the jurisdictions and guardian-consent
procedure under which minors may use it (the product provides no
parental-consent machinery — see the DPIA §4c).` Do not publish this
policy with this section unresolved.

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
- **Daily questions: 90 days**, then removed during recompute.
- **AI provider copies (if you consented): per the provider's terms**
  (disclosed on the consent screen at the moment you opt in).
- **Pairing codes: 15 minutes, single use.** Processing keys: memory
  only, destroyed at use or ≤5 minutes.

## Your rights

- **See and export your data**: download an encrypted export bundle
  from the app/web app at any time and decrypt it offline with your
  password ([tool link in the app's export screen]).
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


## Voice journaling (added 2026-09-29, VOICE_PLAN.md)

If you record an entry instead of typing it:

- Your recording is sent to a third-party transcription service
  ({STT_PROVIDER_NAME}) only after you explicitly turn voice journaling
  on, and is deleted from our systems immediately after transcription —
  we never store the recording from that step. The service's retention
  of its own copies is governed by its terms, disclosed at consent
  ({STT_DATA_RETENTION}).
- The transcript is stored like every entry: encrypted on your device
  before it reaches us, in a form we cannot read. If you recorded in
  another language, an English translation rides inside the same
  encrypted payload so your therapist can read it.
- If you keep a recording, it is encrypted on your device (we store only
  ciphertext) and automatically deleted after
  {AUDIO_RETENTION_DAYS} days. You can delete it sooner at any time;
  deleting the entry deletes its recording.
- Your therapist can hear your recordings only if you separately turn on
  "let my therapist hear my recordings" for that therapist, and every
  playback by a therapist is recorded in your access log.
