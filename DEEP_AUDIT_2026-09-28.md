# Deep Exhaustive Audit — 2026-09-28

**Scope:** every line of first-party source across all four applications
(backend 32k LOC Python, mobile 20k TS, web 6k TS, portal 2k TS), the shared
cross-platform corpora, the full test suites, the red-team tooling, the CI/CD
and deployment surface, and the documentation — 12 parallel deep-audit passes,
each finding verified against source before fixing, every fix pinned by
regression tests and re-gated.

**Method.** Baselines were captured first (all six gates green at HEAD
`6ff92db`: backend pytest 1619 tests, ruff, mypy, web 647, portal 413,
mobile 1928) so that every defect below is one the existing gates MISS —
the exact class that made issues reappear audit after audit. Findings were
then fixed, red-proven where behavior-defining, and re-verified.

---

## Headline findings (all fixed and regression-pinned)

### CRITICAL

**C1. Production backups have silently never succeeded** (`backup/backup_mac.py`).
The 2026-09-27 remediation moved the backup key to a mounted secret file
(`BACKUP_KEY_FILE`), but the HMAC tool still read only the `BACKUP_KEY` env
var — which compose no longer exports. Every backup run since 2026-09-27:
openssl encrypts the dump, the HMAC step raises, the `&&` chain deletes the
temporaries, and the worker retries every 300 s forever. **Zero backups
published; the failure looks alive.** Fixed with `_secret_env`-style
resolution (env first, file fallback); the rehearsal script's decrypt path
aligned. *The weekly backup-freshness alert would have caught this — which
is why the alert exists — but nothing ran it against a file-key deployment.*

**C2. The LLM narrative sanitizer was bypassed by length** (`llm.py:_clean_narrative`).
Narratives over 240 chars were truncated and returned BEFORE any sanitizer
ran — URLs, phone numbers, spelled contacts, second-person advice,
imperatives, manipulation phrases ("they are tired of you"), digits/dosages,
clinical terms, and the crisis-language suppression were ALL skipped. A
prompt-injected journal only needed to steer the provider's output past 240
chars to land quoted-ideation or isolation content on pattern cards. Fixed:
truncate first, then run the full hostile-input chain.

### HIGH

**H1. The clients' `created_at` brick the analysis engine** (all clients ↔ backend).
Every production client (mobile `EntryScreen`, web `Entry`) writes
`created_at` as a full ISO timestamp — the shape pinned in
`shared/interop_fixtures.json` — but the backend's recompute parser used
`date.fromisoformat`, which rejects any time component. The first entry
saved from either app made every subsequent recompute answer
`400 entry_payload_malformed` once the account left the 30-day baseline
phase: no patterns, no brain state, no daily question, forever. The
backend suite never saw it because its helpers build date-only payloads.
**Red-proven end-to-end before the fix** (identical corpus 400'd at HEAD);
fixed by accepting both wire shapes with the ±1-day tolerance unchanged.

**H2. Portal could not decrypt any current entry** (`portal decryptEntry`).
Since the 2026-09-20 M-2 contract, every patient client seals entries under
the four-part v2 AAD and server-side rekey upgrades every stored row — the
portal tried only the legacy three-part binding, so the therapist
"See the evidence" drill-down rendered "(entry could not be decrypted)"
for every entry written since. The portal's own tests encrypted fixtures
with the v1 AAD, so the suite was green. Fixed with the server's exact
v2-then-v1 candidate ladder.

**H3. Every portal note edit failed** (`portal updateNote`). The backend
made `base_version` mandatory on PATCH (2026-09-26 item 15); the portal
kept sending `{blob}` alone — a 400 on 100% of note edits, with the raw
backend detail surfaced in a clinical banner. Fixed: version echo,
`base_version` on the wire, 409 `version_conflict` handled by refetch.

**H4–H7. Crisis detector: systematic false positives AND false negatives** (both engines).
- The concat evasion channel joined tokens with no boundary information, so
  benign phrases whose words merely END in the same letters fired the
  crisis dialog: "the weekend it all went fine", "sending it all back",
  "spend it all at once", "rocky sunset", "spooky stories", "i love this
  lucky star" — on BOTH the Python and TypeScript engines. Systematic false
  alarms erode trust in the primary safety surface.
- The Spanish tier covered only present-tense first person: "me corté"
  (I cut myself), "me voy a cortar", "quiero terminar con todo" (the
  standard Spanish end-it-all idiom), "me estoy haciendo daño", "me siento
  un estorbo" matched NEITHER tier — and unmatched text can be quoted back
  on pattern cards, the exact harm the interlock exists to prevent.
- The Turkish pattern carried the dotless ı while normalization folds ı→i
  in the text: Python matched by IGNORECASE accident; the mobile engine
  (correct ECMAScript semantics) silently missed the correctly-spelled
  cry for help.
- Small-capital homoglyph styling ("ꜱuicide", "kɪll myself", "kiʟʟ
  myself") evaded both engines.

**Fix (one coherent redesign, mirrored across all three implementations):**
the concat channel now matches a MARKED concatenation (tokens joined with
a `|` sentinel) — phrase starts pinned to token boundaries, internal
boundings optional so every split/spacing evasion still matches, short
patterns contiguous-only. Verified on a 30-case battery: every benign
family silent, every evasion family (splits, leet, no-space, Turkish,
small-caps, Spanish tenses) firing. Spanish past/future/progressive +
idiom + burden families added to both tiers; the Turkish pattern written
post-fold; the four small-capitals added to the homoglyph map (NFKC-verified);
leet "1" maps contextually to "l" in the myself-family ("kill myse1f"
now fires). The shared contract JSON, both embedded TS phrase copies, and
both TS engines were regenerated/synced byte-identically.

**H8. Production compose could not boot** (`docker-compose.yml`). The api
service pointed `MINDPATTERN_AUTH_TOKEN_SECRET_FILE` at a secret it never
mounted; `_secret_env` hard-fails on the unreadable path, so `docker
compose up` crash-loops the api. Fixed by mounting the declared secret.

**H9. The privacy escape hatch couldn't decrypt edited entries**
(`mobile/tools/decrypt_export.mjs`). The export tool used only the legacy
AAD and hardcoded 600k iterations — every entry with `content_version ≥ 2`
(and every non-default-KDF account) reported "wrong password". Fixed with
the AAD ladder + `kdf_params` honoring.

**H10. On-device language detection diverged from the server** (mobile+web
brain). Below a 50-token floor the clients defaulted English while the
server applies the share rule — virtually every journal entry is short, so
Spanish users' on-device mood estimates sign-flipped against the server's
scoring of the same text ("nunca estoy bien": device +0.40, server −0.296).
Both TS engines now mirror the server's rule; pins updated.

**H11. Contradictory crisis-line copy shipped in the web catalogs** (docs).
Dead strings claimed "text HOME to 741741 (US, CA, UK, IE)" — factually
wrong (CA 686868, UK 85258, IE 50808); a future refactor rendering one of
them would direct non-US users to a dead number. Removed (unused,
verified) and pinned by a new guard test so a multi-country claim on a
US-only short code can never silently return.

### MEDIUM (fixed; selection)

- **Phantom audit-journal lines** (`deps.py`): `require_user`'s early commit
  made "committed" sticky, and the silent close-rollback fires no event —
  staged journal lines for rolled-back audit rows flushed anyway, and the
  daily sweep read them as "tail truncation" tamper evidence from ordinary
  4xx traffic. Fixed with a staged-count snapshot at each commit; only the
  committed prefix flushes.
- **TOTP Unicode 500** (`totp.py`): `str.isdigit()` accepts Arabic-Indic
  digits but `hmac.compare_digest` raises TypeError on non-ASCII — a user
  with a non-Latin numeric keypad 500'd the login path (and skipped the
  throttle accounting). `isascii()` gate added; regression-pinned.
- **change-password KDF divergence** (web+mobile parity): a v2 re-wrap
  under default parameters for a non-default-params account produced an
  envelope the next unlock could never reproduce — permanent lockout.
  Web now fetches and reuses the account's current parameters (mobile's
  2026-09-26 fix, finally mirrored).
- **Web edit path ran no crisis detection** (mobile H-6 not mirrored):
  editing yesterday's entry into crisis language got no support dialog.
- **No client-side entry cap** (web): >100k drafts were silently dropped on
  restore; >1.5M chars stranded unreadable in the rejected store. Capped at
  100k on create and edit, empty-edit blocked (mobile parity).
- **`_chosen_pattern_pid` mirrored the EN pool** while the served question
  came from the ES pool — correct today only by positional accident;
  language now threaded through the exact mirror.
- **Rumination scoring ignored the detected language** (brain): Spanish
  corpora scored with muted English weights on the 14 collision words.
- **"solo" poisoned Spanish sentiment**: the adverb "only/just" carried
  −1.8, so "solo fui al supermercado" read as a clearly negative day —
  feeding fabricated mood-correlation claims. Both bare gendered forms
  removed; artifacts regenerated.
- **Red-team guard rot** (why issues kept recurring): `b_auth.py` imported
  a renamed class (five checks dead on HEAD), `g_infra.py` grepped a
  removed literal (false FINDING every run), `a_crypto.py`'s memory probe
  scanned `gc.get_objects()` for strings (structurally cannot fire),
  `e2_brain.py` gated on the wrong signal, `d_llm.py` had an AND-for-OR.
  All repaired to observe what they claim.
- **Monitoring gaps**: the audit-chain tamper counter was exported but
  never alerted or charted; the keystore dashboard panel contradicted its
  own alert threshold; the digest-pin verifier's glob accepted mutable
  defaults. All fixed.
- **loadtest.py** created known-password accounts with deterministic salts
  against any `--url` with no non-loopback guard. Fixed (env/prompt
  password, `--yes-prod` gate).
- **Streak zeroed by timezone-skewed entries** (threshold): a single
  future-dated (UTC+14 grace) entry anchored the walk at "tomorrow" and
  reset a 40-day streak to 0. Future dates excluded from anchor and count.
- **UX safety (mobile)**: availability flash of "Can't reach the server"
  during load; rekeyed-elsewhere notice auto-clearing into a "No entries
  yet" data-loss reading; silent discard of unsaved edits (History edit,
  Safety Plan) on back; English capability reasons interpolated into
  Spanish sentences. All fixed with locale parity.
- **`_ALLOWED_KINDS` vs findings sent**: the enrichment round-trip POSTed
  the consented journal plaintext for kinds the sanitizer structurally
  drops — dispatched nothing, still reported `analyzer: "llm"`. Filtered
  pre-dispatch; the analyzer name now requires an actual round-trip.

### LOW / INFO (fixed unless noted)

Enclave `create()` now enforces its documented owner requirement; the TOTP
wrap/URI/AAD nits; KDF dead length-cap enforced; envelope AAD ordering rule
documented; CORS `X-Pairing-Code`; `_FILE` resolution for the last two
env-only secrets; metrics-token floor; verifier-gated endpoints' error
shapes aligned (404/401 split); `ACCESS_LOG_RETENTION` argument made
required; `WRAPPED_DATA_KEY_SIZE` imported instead of redeclared; delete
handlers' malformed-id guards; consents list tiebreak + unique/FK split;
measures `created_at` guard; RekeyJournal orphan sweep; `InsightOut.state_seq`
in the export bundle; `source:"tag"` origin honesty (evidence-day overlap);
token epoch-bound comment corrected; shared-key-across-await snapshots
(web Settings/Share/sync/History/Measures); register scheme-echo adoption;
`documentElement.lang`; access-log page-2 keep; security.txt placeholder
build gate; SRI tool coverage + font limitation documented; `.gitignore`
key-format net; JSC floating pin; empty iOS location key; monitoring-stack
healthchecks; verify_vectors `envelope_vectors` coverage; native-release
keystore pattern broadened; run_all.sh stale-summary and exit-code
surfacing; decrypt_export robustness; corpus/NFD fixture sync; aad corpus
divergence; dead exports/keys/components pruned; stale 13+/count/line-ref
comments; dump_brain_lexicon main-guard; ES pronoun normalization
("¿Qué le confortó hoy?"); QuestionScreen unlock-days fallback; test-suite
hardening (anonymous-401 sweep over the whole route table, entries-create
429 pin, logout sibling-token pin — which immediately caught and docs
confirmed the semantics — six bucketed status asserts tightened to exact).

### Deliberately accepted residuals (documented, not fixed)

- "ending it all" as an un-punctuated noun phrase ("a cool ending it all
  worked out") still fires the dialog tier via the PRIMARY pattern — a
  pre-existing lexical ambiguity, conservative direction, left as is.
- "ki11"-class leet+letter-doubling interactions remain misses (needs a
  leet-aware doubling channel; "k1ll"/"myse1f" families now covered).
- Multi-char leet prefixes needing per-position expansion ("51uicide")
  remain an accepted evasion residual (a uniform run-fold maps them to
  non-words either way) — documented at the engine.
- The four historical SQLite `drop_column` downgrades keep their mixed
  styles (modifying shipped migrations outweighs the SQLite<3.35 risk).
- `_detect_links`' unused `today` parameter, the cadence magic numbers,
  `sense_words` dead payload, and the module-level day-pin ledger notes —
  recorded for the next refactor, zero runtime impact.
- Mobile TLS pinning remains the documented accepted residual
  (docs/SECURITY_RESIDUALS.md), with the first-login origin pin and
  redirect refusal as compensations.

## Gates after remediation

- backend: pytest (full suite) / ruff / mypy — green
- web: typecheck clean; vitest 668 passed | 5 skipped (21 new regression tests)
- portal: typecheck clean; vitest 413 passed
- mobile: typecheck clean; vitest 1965 passed | 1 skipped (37 new/expanded tests)

## Root-cause note — why issues kept reappearing

Three structural patterns explain the recurrence this audit closed:

1. **Cross-platform drift with per-platform green suites.** Four
   implementations of one contract, each tested against its own fixtures —
   the created_at shape, the portal AAD, the language detector, the
   hotline copy all diverged while every suite stayed green. The fixes
   pin the CONTRACT (shared corpora parity tests, engine-mirroring pins,
   cross-engine fixture batteries) rather than the symptom.
2. **Guard rot.** The red-team/tooling layer pinned literals and
   identifiers that legitimately evolve (`FixedWindowCounter`, compose
   strings, route lists) — five guards were dead or falsely-failing on
   HEAD while reported green. Repaired to observe behavior, not spelling,
   with fail-loud seams.
3. **Behavioral gaps the gates structurally miss.** Boot-time compose
   wiring, backup end-to-end success, phase-gated code paths (the
   recompute parser only runs past baseline), and runtime-only flows
   (note edits, evidence drill-down) had no test that exercised them as
   deployed. Each fix here lands with the missing end-to-end pin.
