# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/).

## Unreleased

### 2026-09-19 — Mutation campaign round 3: backend infrastructure (authz, ORM, boundaries, transactions, cache, rate limiting)

Six campaigns (`redteam/mutation_campaign_2026-09-19/`, report:
`reports/mutation_campaign_2026-09-19.md`). 62 hand-written mutants: 36
killed at their targeted suites, 26 survivors → full-suite re-verification
(10 more killed there) → 16 genuine → 14 pinned
(`backend/tests/test_mutation_pins_2026_09_19.py`, hand-verified 14/14 by
re-applying each mutant) + 2 documented residuals.

- **Authorization & access control** (11): epoch kill switch, is_active
  gate, both role walls, revoked-consent reads, note chart scoping, revoke
  ownership, sharing feature flag, keystore owner binding, enrollment
  token, recompute owner pin. Genuine gaps pinned: a suspended account is
  now refused on routes WITHOUT the route-level re-check (`GET /insights`),
  and the therapist enrollment-token gate is route-level tested for the
  first time.
- **Database & ORM** (10): the load-bearing unique constraints, FK cascade,
  SQL DISTINCT, pagination tiebreak, same-day upsert, insight delete scope,
  `populate_existing`, ownership filter, revision guard. Pins: the page
  metadata query's full deterministic ordering (SQL shape), and a same-day
  recompute must rewrite the question blob (the existing upsert test never
  checked that new content wins).
- **Boundaries & business logic** (11): byte budgets, has_more detection,
  note quotas, page sizes, continuation arithmetic, retention windows,
  caseload caps, wrapped-key bound, inner-date tolerance. The
  self-referential test trap struck a THIRD time: the legacy byte-budget
  test imported the budget constant from the code under test, so the ×100
  mutant scaled the test along with it — the pin uses independent
  literals. Caseload cap pinned with literal filler counts.
- **Error handling & transactions** (10): envelope fallback, deep-JSON 400,
  edge headers, FK→410, unique-violation classification, atomic epoch
  bump, export admission release, grant conflict mapping, revoke recheck,
  pairing retry filter. Pins: the losing concurrent same-pair grant answers
  the 409 contract (session-proxy bomb armed on the atomic claim UPDATE),
  and only unique violations are retried during pairing-code allocation
  (direct route call with fakes — an app-level session-poisoning pin is
  impossible: the mutant's retry crashes the poisoned session into a
  different 500).
- **Cache & invalidation** (10): processing-session TTL, owner purge,
  per-owner cap, revision markers (delete advance, stale comparison in BOTH
  directions), phase-gated blob serving, note marker advance, periodic key
  sweep, recompute serialization. Pins: per-owner session cap, ahead-of-
  server markers conflict too, and a threshold regression stops serving the
  stored blob on BOTH the patient's and the therapist's view.
- **Rate limiting & concurrency** (10): limit off-by-one, window rollover
  boundary, probe-vs-failure counting, eviction policy, stale drop, XFF
  trust, IPv6 /64 aggregation, lock overflow discipline, live-lock
  eviction, single-process guard. Pins: forwarded identity requires the
  trusted-peer decision (not just the flag), and absent lock keys stay on
  the overflow lock until it drains.
- **Documented residuals** (genuine but deliberately unpinned): O6
  (cross-therapist note access via the under-lock re-fetch is unreachable
  behind the still-scoped pre-lock read) and S10 (the per-user recompute
  lock's keying is masked by the outer per-user lifecycle fence).
- **PR mutation gate hardened while integrating round 3** (168 behavioral
  mutants now visible to it; validated 83/83 killed/caught over a synthetic
  diff touching every campaign target file): the gate now serves all
  mutants with the round-2 `run_mutant` (round-1's crashed on
  list-of-suites mutants), carries an explicit `DOCUMENTED_RESIDUALS`
  allowlist (I4, J1, N9, O6, S10 — previously permanent red gates on their
  files), and the mutants' targeted lists now include their actual killing
  suites (round-3's full-suite killers, round-2's K4/K5 pins, and this
  campaign's pins file). The gate also caught a ROTTED round-1 pin — C3
  (keystore pop single-use) is killed by nothing in the current suite and
  is re-pinned in `tests/test_mutation_pins_2026_09_19.py`.

### 2026-09-18 (b) — Mutation campaign round 2: portal/mobile Stryker, brain round 2, redteam-as-oracle, PR mutation gate

Ten campaigns (`redteam/mutation_campaign_2026-09-18_round2/`, report:
`reports/mutation_campaign_2026-09-18_round2.md`). 70 hand-written
mutants: 55 killed at their targeted suites, 13 targeted survivors →
full-suite re-verification → 10 genuine → 8 pinned (verified 8/8 by
hand-applying each mutant) + 2 documented defense-in-depth.

- **Portal had effectively no mutation coverage** — first-ever Stryker
  run (`portal/stryker.config.json`, `npm run test:mutation`): 2,262
  mutants, score 1.41%. The security-critical crypto seams are now
  pinned (`portal/tests/crypto.pins.test.ts`): the two portal-only HKDF
  subkeys byte-pinned against backend-derived references, identity
  cross-bindings (key sealed for therapist A must not unlock under B;
  notes fail under every wrong id), wrong-key-size guards. `views/*`
  (~1,266 mutants, ~0.5%) is the recorded follow-up front. A `qs`
  override keeps `npm audit` clean with the Stryker devDependencies.
- **Mobile scoped Stryker re-runs** (first measurement since the
  2026-09-15 99.64% campaign): crypto 83.5%, offlineQueue 87.4%,
  InsightsScreen 84.1%, mood/calendar 73.4%, crisis 75.1% — the drop is
  post-09-15 code without equivalent pins; the semantic non-negotiables
  remain guarded by the hand-written campaigns (M 6/6). Per-mutant
  triage is the recorded follow-up.
- **Brain round 2** (20 mutants): EWMA λ, MinHash/LSH (perms, banding,
  threshold), lag-1 links (direction, lag-0, gap-2-only), replication
  independence, residuals-vs-pooled, lifecycle boundaries 44/45/46 —
  the v2 confound mutants (residuals removed) are killed by the suite
  AND the probe; the ground-truth probe alone catches 2/20 (it detects
  missing planted patterns, not loosened thresholds — the EWMA honesty
  pins now live in `test_mutation_pins_2026_09_18b.py`).
- **Threshold campaign** (7/7 killed): distinct-vs-total days, 29/30/31
  boundaries, streak grace, ±1-day backdating windows, baseline-phase
  reveal-nothing — all pinned.
- **Crypto contract campaign**: HKDF auth/data info swap killed on all
  platforms, fixed-zero nonce killed, pairing single-use killed;
  tampering `shared/vectors.json` / `crisis_phrases.json` /
  `generic_questions.json` fails every consuming suite (portal pins the
  fields it consumes — `encrypt_vectors`, not the legacy
  `vectors[].blob`); the pairing-burn expiry condition is documented
  defense-in-depth (closes only the lookup→burn race).
- **Redteam-as-oracle campaign** (new discipline: mutate a security
  control, check whether the attack harnesses notice): 8/10 caught.
  The two that sailed through are now harness pins — a_crypto's KDF
  floor probe was self-referential (it read the contract value from the
  code under test; now pinned as constants), and b_auth never sent a
  WRONG verifier (new `B1.wrong-verifier-rejected` audit). One residual
  (ALPHA inflation is absorbed by the layered effect gates on the
  harness's corpora), one equivalent-by-cascade (entry deletion).
- **The red-team harnesses had silently rotted**: 5 of 8 backend attack
  scripts crashed at `/auth/register` (in-memory SQLite assumption
  broken by the Alembic-first startup) and `e2_brain` was un-runnable
  (import order). All repaired; every script reports 0 harness errors
  and the full `run_all.sh` is green again.
- **Two harness hazards found live and closed**: (1) stale-bytecode
  poisoning — CPython validates `.pyc` by source mtime at second
  granularity, so a same-size mutant applied and reverted inside one
  clock second leaves the mutated bytecode cached on a byte-clean tree
  (67 phantom suite failures mid-campaign); the harness now runs with
  `PYTHONDONTWRITEBYTECODE=1` and purges the target's `__pycache__`
  after each restore, and all verdicts were re-computed from a purged,
  re-confirmed-green baseline. (2) corpus-regenerating harnesses poison
  fixtures when run under mutation (e_crisis re-exported every crisis
  sample as suppress=false); the corpus was restored and the rule
  recorded.
- **Per-PR incremental mutation gate**
  (`.github/workflows/mutation-pr.yml` +
  `redteam/run_pr_mutation_gate.py`): every behavioral campaign mutant
  (106 across both rounds) whose target file is in the PR diff is
  re-applied and must stay killed (rotted find-strings fail too), plus
  a bounded 20-minute diff-scoped `mutmut run` over changed backend
  files where survivors fail the PR. Validated both ways locally.
- Backend suite grows to 1,037 tests (9 new pins); portal to 131 (7 new
  crypto pins).

### 2026-09-18 — Behavioral mutation campaign over the non-negotiables

36 hand-written semantic mutants across six campaigns (BH/FDR statistics,
lifecycle, crypto & memory boundaries, clinical guardrails, crisis
handling, sharing clients); each applied to production code, tested,
reverted byte-wise. 31/36 killed by the existing suites; the 5 genuine
survivors are now pinned by regression tests and re-verified killed
(36/36). Report: `reports/mutation_campaign_2026-09-18.md`; harness:
`redteam/mutation_campaign_2026-09-18/`.

- **A5** — zeroing the Cohen's d floor (0.5→0.0) survived the entire
  suite: the only prior pin compared the card's `cohens_d` against the
  constant itself (true for any constant). New pin: a deterministic
  tight-theme/noisy-majority corpus with mood_delta ≈ 0.25 but |d| ≈
  0.42 must earn no card across two qualification days, plus a canary
  that proves the corpus discriminates, plus a floor-value pin.
- **D1/D2** — the LLM narrative sanitizer's rules were only tested
  through overlapping inputs (digits AND medication AND domains).
  New pins trip exactly one rule each: diagnosis vocabulary
  ("a doctor would diagnose this…") and bare digits ("87 percent of
  your Saturdays").
- **E3** — the question-interlock label tripwire (the layer covering
  patterns that arrive without the `sensitive` flag: LLM extras,
  legacy payloads) had no isolated pin; composite safety came from the
  other two layers. Now pinned as a predicate and end-to-end.
- **F8** — the fail-closed custody seam where Keychain/Keystore
  *returns false* (rather than throwing) was never exercised; a mutant
  falling back to plaintext AsyncStorage survived the whole mobile
  suite. The keychain test mock gained a `__failWrites` seam and the
  regression asserts rejection AND no key in AsyncStorage.
- Design note recorded (not fixed): `_clean_narrative` has no general
  advice-language denylist ("you should…"); containment is
  architectural (the inverted LLM path cannot mint claims). If the
  narrative path ever gains autonomy, that tripwire is missing.

### 2026-09-17 (c) — Exhaustive full-codebase audit remediation

A file-by-file exhaustive audit of every source file (backend, mobile,
portal, red-team, infra, shared contracts) plus a re-run of the whole
verification battery. One high-severity availability bug found and
proven end-to-end, one red CI gate, and a dozen smaller findings —
all fixed below, each with a regression pin where meaningful.

**High**

- RECOMPUTE BRICK FIXED (both engines): the crisis leet-fold regexes
  matched ALL digits (`[0-9@!$34578]`) while the substitution map covers
  only 0,1,3,4,5,7,8,@,!,$ — a 2, 6 or 9 between letters raised
  `KeyError` on the server ("grade6test" → every future recompute 400s
  with a misleading `entry_payload_malformed` once a digit-bearing
  activity tag surfaced as a pattern label) and spliced the literal
  string "undefined" into the mobile normalizer. The classes now list
  exactly the mapped characters on both engines; regression fixtures
  with 2/6/9 texts are in `shared/crisis_phrases.json` (replayed by both
  suites) plus an end-to-end brain test (digit tag across four recompute
  days). The unmapped digits remain unmapped by design (2=z, 6=b/g,
  9=g/q are ambiguous leet).

**Medium**

- CI lint gate green again: `ruff check .` was RED at HEAD (unused
  import in scripts/loadtest.py, unused variable in the language-gate
  test); redteam/ carried 25+8 ungated F401/F841/E741 findings — all
  cleaned; the stale "verified green" pyproject note is accurate again.
- Pairing is now human-verifiable: both the portal (beside the pairing
  code) and the patient's app (in the confirm step) show an 8-byte
  SHA-256 fingerprint of the therapist's wrap key — read back to each
  other, it detects a server-substituted key (the server relays the key
  during lookup; that trust is now stated in the README security model).
- Pairing-code single-use is now race-free: the burn is an atomic
  conditional UPDATE (`consumed_at IS NULL AND expires_at > now`) — the
  SELECT pre-check is fast-path only; two concurrent redeems cannot both
  win (the loser gets the uniform 404).
- mypy advisory count honest again and lower: every finding outside
  brain.py fixed (typed AsyncConnection for the cross-host guard,
  IO[bytes] lock registry, a typed rowcount() helper for DML results,
  the dedupe-comprehension rewrite, two dialect-insert imports, one
  over-wide annotation) — 21 errors in 7 files → 13 in brain.py only;
  the pyproject status note reflects the measured 2026-09-17 numbers.

**Low / hardening**

- Keystore `get()` returns a zeroizable `bytearray` copy (was immutable
  bytes contradicting its own docstring); production paths use `pop()`.
- `GET /insights` and the therapist read path serve the patterns blob
  only in the insight phase — deleting entries can drop an account back
  below the 30-day threshold, and a stored blob from the insight phase
  must not keep being served in baseline.
- Note idempotency is patient-scoped: reusing a `client_note_id` for a
  different patient answers 409 instead of silently rewriting the first
  patient's note.
- Recompute metrics are observed on EVERY exit (success, 4xx tamper,
  410 account-deleted, 500) — a corpus that 400s after seconds of
  analysis is exactly the spike an operator needs to see; the LLM
  outcome counter only fires when the enricher actually ran.
- Portal fetch has a 15 s deadline (the mobile client always had one) —
  a hung backend can no longer park the clinic UI forever.
- Pairing-code generation uses rejection sampling (256 % 31 = 8 used to
  favor the first 8 alphabet symbols; ~0.4 bits reclaimed).
- The shadowed duplicate `test_rate_limiter_buckets_clients_independently`
  in test_mutation_pins.py is un-shadowed (renamed to
  `test_unlimited_endpoints_create_no_rate_buckets`) — a rate-limit
  regression that silently never ran for years now runs; the F811
  exemption is retired.
- The recompute corpus loader and the entries quota share ONE
  dialect-aware blob-length expression (`octet_length` on Postgres).

Test status after this wave: backend **903 passed** (+1 Postgres-gated
skip), probe 9/9, mobile **1203 passed** (60 files), portal **90
passed**, cross-platform crypto vectors green (4+6+16), `ruff check .`
green in backend and redteam, mypy 13 (brain.py only, advisory).

### 2026-09-17 (b) — Independent-audit remediation

A deep independent audit of the two 2026-09-17 commits (crisis safety,
stats engine, feedback loop, LLM narration, mobile, portal, ops/CI)
verified the test claims and found one shipped-dead feature, one safety
regression, and several correctness gaps. All fixed, each with a pinning
test; crisis fixes are byte-identical across both engines (184-input
parity harness) and promoted into the shared contract corpus.

**Crisis safety (both engines, shared contract)**

- REGRESSION FIXED: the benign-compound mask silenced real ideation
  ("thinking about suicide, silence and pain" — the comma manufactured
  the compound "suicide silence" after punctuation folding). The mask now
  runs on the PRE-punctuation-fold text and requires the compound's words
  to be whitespace/hyphen-joined; punctuation between words is not the
  compound. Ideation adjacent to a masked word fires again.
- Residual splits closed by a third, CONCAT matching variant
  (whitespace-free text vs space-free pattern twins with an anchored
  trailing boundary for extendable endings): "su icide", "ki ll myself",
  "kill my self", "end i t all", "k y s", and plain "killmyself" /
  "i will killmyself tonight" all fire; "i wanna diet" / "wants to diet"
  / "can't go online" stay benign.
- Cross-engine parity: Cyrillic к/м and Turkish dotless ı join the
  homoglyph map; Latin diacritics fold to base letters (é→e); script
  boundaries (ASCII against non-ASCII letters) become spaces — the
  Python-re-vs-ECMAScript divergences (kıll/suıcıde/suicidé/…) now agree,
  verified by a 184-input two-engine parity run and pinned as corpus rows.
- Variation selectors FE00–FE0F, U+034F and U+061C stripped as invisibles;
  leet digits fold at a word's leading edge ("5uicide", "$uicide");
  Hangul survives the punctuation fold. New non-Latin phrases: 我想去死,
  자살하고 싶다, 죽고 싶다, أريد أن أنتحر, Turkish intihar/canımı patterns.
  The shared corpus grew from 40 to 70 adversarial rows.

**Feedback loop (shipped dead → working)**

- The mobile client POSTs `{"feedback_blob": ...}` while the endpoint
  declared a bare scalar Body — every feedback-carrying recompute was a
  422 and one pending tap poisoned all later question loads. The endpoint
  now embeds the body param; an end-to-end HTTP test pins the wire shape
  (there was none).
- A tampered feedback blob no longer triggers the brain-state amnesia
  retry: it is isolated first (entries+state retry) and answered with its
  own `feedback_blob_invalid` 400; the mobile client quarantines the
  undecryptable queue and retries the recompute without it. The retry
  factory bug (retry paths closed over the truthy feedback_item and
  stripped the state blob as feedback) is fixed.
- `_chosen_pattern_pid` now mirrors `build_pool`'s slice-then-skip
  ordering (filter-before-slice misattributed taps whenever a sensitive
  pattern ranked in the top 5); bad base64 is a 422, not a 500.

**LLM narration**

- The narrative is no longer an ungrounded free-text channel: no digits
  at all (minted statistics, phone fragments), no bare domains
  (helpnow.example.com), no clinical/advice vocabulary (dose/medication/
  diagnosis), no consecutive spelled numbers, and crisis-screened through
  both tiers before it can render. The audit's demonstrated hostile
  narrative is now rejected verbatim.

**Engine correctness**

- Avoidance detector: the null is now the skip rate of the theme-day's
  OWN weekday with an exact Poisson-binomial tail (new
  `statsig.poisson_binomial_sf`). A pure Mon–Fri writer mentioning a
  theme on Fridays no longer gets a confident false "you go quiet after
  X" card (p=0.0 under the old pooled-rate binomial); genuine
  weekday-spread avoidance still surfaces.
- mood_correlation copy is direction-aware everywhere it is rendered
  (server `describe()` incl. the sleep and tag branches, and the mobile
  sleep card): a poor-sleep→higher-mood user is no longer told their
  entries "read lower".
- Language gate scores ≥3-letter tokens only: negation-dense Spanish
  ("No me siento bien…", inflated to ~25% "known" by no/me/a) is gated;
  no more English-lexicon rumination cards on Spanish prose.
- Person anchoring: sentence initials are the entry's first token AND
  post-.!? tokens (Telegram-style "Woke tired. Netflix til late." no
  longer mints Netflix/Stayed as persons); name homographs (may/bill/
  sue/june/…) match only their capitalized form.
- Emoji valence counts per occurrence, not per distinct emoji.

**Mobile / portal / ops** (from the same audit)

- Mobile: shell-wrapped screens hoisted to module scope (no more remount
  state loss on context change); Android back handler scoped to History
  focus (no longer swallows back on the screen above); stored-question
  feedback attribution sets/clears `pattern_pid` with the question;
  narrative rendered under the same 500-char cap as labels; account
  deletion clears the question-feedback record (and it is origin-bound);
  theme radio no longer flashes a derived value.
- Portal: the 401 latch re-arms on every new session (one fire per
  session preserved) — a second expiry after re-login locks the UI again.
- Ops: the pg advisory-lock connection commits (no more lifetime
  `idle in transaction` pinning vacuum); `/metrics` token compared with
  `hmac.compare_digest` against the LIVE settings (stale-closure
  fail-open closed); access_log pruning runs as a daily lifespan sweep,
  not only inside pairing-code minting; `rehearse_restore.sh` actually
  finds the encrypted backups the compose stack writes (and fails on
  row-count mismatch); `loadtest.py` logs in on 409 instead of measuring
  401 latencies; release/mutation workflows SHA-pinned (mutable tags
  resolved to commits) with per-job permissions.

### 2026-09-17 — Full-stack improvement wave (audit-driven, five waves)

A complete audit (six parallel deep-dives: backend architecture, the
pattern engine, mobile UX, the therapist portal, testing/ops posture, and
the 2026 clinical/competitive landscape) produced a prioritized roadmap;
this wave implements it end to end. Verification after every wave:
backend 877 passed (+1 Postgres-gated skip), mobile 1,169 tests across 60
files, portal 87 tests + build, probe 9/9, cross-platform vectors all
green (including the new AAD edge-case corpus).

**Wave 0 — safety & correctness**

- The red-team crisis corpus is now a CI GATE on both platforms
  (`shared/crisis_phrases.json` `redteam_corpus`: every row is the
  REQUIRED contract; backend + mobile suites replay it). The two
  documented residuals are closed: "k ill myself" (orphan-letter
  dual-variant matching) and the "suicide squad" false positive
  (benign-compound masking, both engines).
- The 16-vector AAD edge-case corpus (surrogates, CJK, RTL, DEL/controls)
  promoted from `redteam/a_crypto.py` into `shared/vectors.json`, verified
  on backend, mobile, portal AND `tools/verify_vectors.mjs`.
- v1 legacy analyzer RETIRED: `RuleBasedAnalyzer`/`LLMAnalyzer.analyze`
  (the pooled, uncorrected pre-brain statistics) are gone from the
  production graph; an LLM endpoint failure now contributes nothing,
  logs a warning, and the recompute response reports `analyzer: "llm"`
  only for calls that actually succeeded (`last_error` honesty).
- Language gate: Latin-script non-English journals (German/French/Spanish)
  no longer produce garbage topic cards or lexicon-collision mood claims —
  the recognized-token share gates topic mining and text-derived sentiment;
  client mood TAGS stay trusted; rumination's English classifier steps
  aside for non-English clusters.
- Instability detector: variance-ratio F-test → Brown-Forsythe
  (median-centered Levene) with Bartlett-deflated df — robust to discrete
  5-point mood tags, autocorrelation-honest.
- Temporal weekday test: one calendar day, one Bernoulli (k, n AND the
  base rate are day-level; clustered journals can't inflate their own
  reference rate).
- EWMA baseline re-anchors past an established shift (`first_seen` ≥21
  days): a months-old stable improvement stops re-qualifying under copy
  that says "lately".
- Recompute memory bounded by the ANALYSIS budget, not the storage quota:
  `_load_rows` fetches ids+sizes first and only the newest rows within
  `MINDPATTERN_ANALYSIS_BLOB_BUDGET` (8 MiB default) — a max-quota account
  can no longer spike ~750 MB per recompute.
- Cross-host boot guard: on Postgres the app holds a lifetime session
  advisory lock (727273) — a second HOST on the same database refuses to
  boot instead of silently fragmenting every in-process guarantee.
- `/metrics`: privacy-safe aggregate counters (status families, recompute
  histogram, LLM failure counts, keystore length) behind
  `MINDPATTERN_METRICS_TOKEN` (fail-closed: 404 in production without it).

**Wave 1 — the daily-use mobile experience**

- Persistent bottom navigation on every main screen (`MainShell` +
  `BottomNav`; navigation no longer lives inside the entry's scroll
  content), with "Get help" always present.
- The mood sparkline stays visible AFTER the 30-day threshold.
- Readable Markdown export (decrypted on-device, shared as plain text)
  next to the encrypted backup.
- History: plaintext search + month calendar with mood dots + day filter;
  Android hardware-back returns to the list in detail/edit modes.
- Question pool 8 → 60 (evidence-informed families; invariants re-pinned
  on both platforms).
- Multi-dimension check-in: optional energy row; payload v2 structured
  channels (sleep quality, activity tags) in the entry editor.
- Theme override (System/Dark/Light), quiet haptics (10 ms, setting-gated),
  writing prompt chips for blank-page days, native-feature seams for
  reminders/biometrics (`src/nativeFeatures.ts`), and the i18n seam for
  safety-critical crisis copy (`src/strings.ts`).

**Wave 2 — engine depth**

- Structured channels (entry payload v2): sleep quality (1-5), energy,
  activity tags. Poor-sleep nights (strictly below the user's OWN median)
  ride the full theme machinery — weekday concentration, same-day mood
  ties, day-after links — with rating-aware copy; tags feed
  mood-correlation cards marked `source: "tag"`.
- Cadence signals: the `avoidance` detector (theme-days followed by
  journaling silence vs the user's base skip rate; censoring-honest,
  exact binomial into the BH family) and `cadence` (writing-rhythm
  regularity, recent vs the user's earlier norm).
- VADER base lexicon merged (7,208 words; curated values win word-for-
  word; context-dependent removals stay removed) + emoji valence — the
  graded engine sees slang/profanity/emoji now.
- Question feedback loop: "This resonated / Not me" taps (encrypted
  on-device, riding the next recompute as an opaque blob) land in the
  pattern's stored memory and reorder question selection; evidence-
  anchored templates (`{share}% of such days`).
- LLM INVERSION: the model no longer discovers patterns (its output
  bypassed every statistical safeguard). It receives the deterministic
  findings and may only attach one sanitized 240-char narrative —
  label-restricted by construction.
- Person anchoring: recurring mid-sentence proper names ("Maria") become
  theme candidates under strict bars, riding the same gating.

**Wave 3 — the portal becomes a daily driver**

- The visit delta anchors ONLY on the explicit "Mark reviewed" action
  (a 30-second glance no longer resets it; the copy names the anchor).
- Printable session summary (print-CSS; patterns + evidence rows + notes;
  `window.print()`).
- Notes: editable (the PATCH endpoint finally has a UI), searchable,
  template starters, copy-forward.
- Caseload triage scan: per-patient pattern counts, sensitive presence,
  new-since-reviewed badges (sequential, nothing stored).
- Mood sparkline (inline SVG) over drill-down entries + account summary
  stats; review ordering puts sensitive and down-shift cards first.
- Session lifecycle: any 401 swaps to an explicit expired state (latched
  handler); 10-minute idle auto-lock drops all keys from memory.

**Wave 4 — launch & operations**

- `release.yml`: tag-driven delivery — verification spine, multi-arch
  image to GHCR, GitHub release seeded from the matching CHANGELOG
  section (missing section = release blocker).
- `mutation-mobile.yml`: weekly Stryker gate with a 99.0 floor (the score
  silently decayed once before: 100% → 82.7% in 11 days).
- `backend/scripts/rehearse_restore.sh` (the scripted backup-restore
  rehearsal) and `backend/scripts/loadtest.py` (latency percentiles for
  register/entry/recompute against the deployment contract).
- `access_log` retention (2 years, time-based; deletion still never
  cascades audit rows) + compose memory limits (api 1500M, db 1G).
- `docs/`: incident-response runbook, DPIA skeleton (GDPR Art. 9 + EU AI
  Act notes), and a PsyberGuide self-assessment mapped to the repo's
  testable claims.



### Added — Therapist sharing (zero-knowledge patient→clinician sharing)

The feature this app was building toward: a patient can let their therapist
see every surfaced pattern and, on click, the journal entries behind it —
read-only, with the therapist's own encrypted notes. The server stays blind
to content throughout.

- **Zero-knowledge grant (E2E preserved).** The therapist portal (new
  `portal/`, React + WebCrypto) registers with a P-256 wrap keypair; the
  private key is stored only as a password-encrypted blob. A patient types
  a short-lived single-use pairing code in the app ("Share with my
  therapist" in Settings), sees the therapist's name, re-authenticates with
  their password, and their client wraps the data key to the therapist's
  public key (ECDH → HKDF salted with both SPKI keys → AES-256-GCM, AAD
  `("consent-wrap", user, therapist)` — see
  `backend/app/security/sharing.py`, the reference implementation). The
  portal unwraps locally after login; the server never holds anything that
  decrypts patient content.
- **Pairing codes.** 8 chars, 15-minute TTL, single-use, stored only as an
  HMAC; unknown/expired/consumed answer the same 404. Codes replace
  username search so no therapist-enumeration oracle exists.
- **Role separation.** `users.role` gates every route: therapist tokens
  cannot reach journal endpoints (403 by dependency, not UI convention);
  patient tokens cannot reach therapist routes. There is NO therapist
  write path to patient data — read-only by construction.
- **Therapist reads + audit.** `GET /therapist/patients`, per-patient
  insights (byte-identical blob to the patient's own view) and entries
  (paginated, `since`/`until`). Every grant/revoke and patient-data
  read/write appends an `access_log` row; the log outlives account
  deletion (plain-string ids, no FK).
- **Evidence drill-down.** Surfaced patterns now carry
  `detail.evidence_dates` (the capped list of days whose entries fed the
  pattern) and `detail.pattern_pid` (stable id for note attachment). The
  portal fetches exactly those days' entries, decrypts them, and
  highlights label occurrences with per-entry mood — the "see all the data
  under this pattern" view. Sensitive (crisis-adjacent) cards stay
  non-quoting; the drill-down shows the patient's own words.
- **Notes.** Therapist-private (encrypted under the therapist's
  password-derived `portal-notes` key before leaving the browser),
  attachable to a patient or a pattern id, surviving revoke, cascading
  with account deletion on either side.
- **Revoke semantics, honestly stated.** Revoke (password-gated) clears
  the wrapped key — future access dies immediately; already-read data
  cannot be unread (the grant disclosure says so). Re-granting reactivates
  the same consent row, keeping the therapist's note continuity.
- **Cross-platform pins.** `shared/vectors.json` gains `wrap_vectors`
  (fixed test keypairs); backend, mobile (real quick-crypto seam code
  under node) and portal (real WebCrypto) all verify against them.
  Export bundles now carry share records (metadata only). GDPR posture:
  grant records the disclosure version, mirroring the LLM-consent record.
- **Tests.** Backend +64 API/crypto tests (role separation, pairing
  lifecycle, consent boundaries, cross-therapist isolation, E2E decrypt
  round-trips, audit, cascades, evidence dates) — suite 814. Mobile +26
  (wrap vectors, client wire shapes, full share-screen flows incl. wrong
  password/verifier/session-death branches) — suite 1103 at the same 98%
  per-file coverage floor. Portal: 62 (crypto vectors incl. the unwrap
  path, api client, app state machine, all views) with per-file coverage
  thresholds and a CI job.

### Security — 2026-09-16 red-team remediation wave

Full audit: `reports/redteam_audit_2026-09-16.md` (96 executable verdicts);
reproducible harness in `redteam/`. Post-fix re-run: 63 attacks blocked,
every remaining finding is a documented design residual. Highlights:

- **Crisis-language normalization (P0).** Both engines now normalize before
  matching (NFKC, invisible-character stripping, Cyrillic/Greek homograph
  folding — sigma family mapped by codepoint BEFORE NFKC, leet folding
  between letters, punctuation-to-space, >=4 single-letter token joining).
  The red-team bypass corpus went from 30/35 evasions to 1/35 (the partial
  split "k ill myself" is the designed residual — joining single letters
  into intact words would eat ordinary prose). New phrases cover unlisted
  English ("off myself", "out of my misery") and first-person ideation in
  es/fr/de/it/pt/zh/ja/ar/hi; suppress tier gains hopelessness phrasing.
  Pinned cross-engine by the shared JSON fixtures.
- **Recompute availability crash (P0).** `brain.py` mood-shift inflation
  divided by `(1 - phi)` with phi exactly 1.0 on a
  constant-within-float-noise baseline — every future recompute for such
  accounts 500'd. phi is clamped to 0.99 (saturates the existing
  inflation cap; no honest statistic changes).
- **The data key never rides plain HTTP (P0).** `openProcessingSession`
  refuses a consented insecure URL before any fetch — https or loopback
  only. Ordinary requests keep the BYO-server plain-HTTP consent.
- **Single-process deployment is enforced, not just documented (P1).** A
  file-lock keyed by deployment identity makes the second worker of a
  `uvicorn --workers 2` boot refuse to start (live audit previously showed
  one "single-use" token answering 6 recomputes and per-worker rate
  buckets). Same-process re-entrancy preserved for the test suite.
- **KDF iteration floor (both platforms).** `derive_master_key` /
  `deriveMasterKey(Async)` refuse iterations < 100,000 — no honest code
  path can silently downgrade the 600k contract (the server remains
  structurally unable to verify client work factors).
- **Nonce test seam removed from production encrypt (both platforms).**
  Fixed-nonce output moved to unmistakably named `encrypt_with_nonce` /
  `encryptWithFixedNonce`; `encrypt()` has no nonce parameter at all.
- **LLM hardening.** Timeout 30s->10s (the call runs inside the secure
  processing context, so its latency IS the key/plaintext exposure
  window); `max_tokens=512`, `temperature=0`; labels carrying spelled
  contact channels ("evil dot com", "call five five five ...") or >=3
  consecutive number-words are rejected regardless of corpus grounding.
- **Processing-session TTL ceiling 3600s->300s**, matching the mobile
  consent copy's "held in memory for up to 5 minutes".
- **Export bundle no longer carries the cleartext username** (user_id +
  salt remain — required by the AAD binding / future re-import).
- **Backups are encrypted at rest.** The compose backup profile pipes
  pg_dump through `openssl enc -aes-256-cbc -pbkdf2` with a REQUIRED
  `BACKUP_KEY` (the service refuses to start without one). Retention
  remains part of the deletion promise.
- **Mobile error-dialog sanitizer** now strips scheme-less domains
  ("evil.com/x") and phone-like digit runs; character-level bidi/zero-width
  tricks were already neutralized.
- **Startup warning when `TRUST_PROXY_HEADERS=1`** (direct-origin spoofing
  defeats per-IP limits; the compose default keeps loopback-only binding).
- Regression pins: `backend/tests/test_redteam_fixes_2026_09_16.py` +
  `mobile/tests/redteamFixes2026.test.ts`; the obfuscation corpus lives in
  the shared JSON fixtures and `redteam/crisis_corpus.json`.

Known residuals (documented, not fixable in this wave): SecureStore device
key needs Keychain/Keystore native custody; the offline unlock proof is an
offline password oracle (quantified at ~75 ms/guess/core); the auth_key is
a password-equivalent credential with no rotation path (needs a re-key
feature); consented LLM egress discloses plaintext by design; server-side
metadata (journaling dates/sizes) is visible to the operator; lockfile
hash pins need a networked `pip-compile --generate-hashes` run.

Post-release remediation wave across the whole tree, grouped. (Backend now
658 tests + 1 Postgres-gated skip; mobile 759 tests across 33 files; probe
9/9.)

### Security

- Enclave keeps ONE zeroized working copy of the data key per recompute
  run — per-item immutable `bytes(key)` copies would have lingered
  unzeroized until GC.
- Entry dates may be at most server-today + 1 day (device-local timezone
  grace); backdating rules (no pre-account dates) unchanged.
- Unified cross-platform crisis-language contract at
  `shared/crisis_phrases.json`: a conservative client-side `dialog` tier,
  and a suppress tier (`dialog` + `suppress_extra`) for server-side
  question/card suppression. Crisis-adjacent patterns carry
  `detail.sensitive=true`; the app renders a non-quoting card ("A difficult
  thought has been returning…") with a support link instead of quoting the
  text.
- LLM consent is recorded (`llm_consent_at` + `llm_consent_disclosure`
  "v1"), cleared on disable, and included in the export bundle.
- Salt-lookup enumeration posture documented honestly: per-request
  enumeration is closed (identical decoys for unknown AND deactivated
  accounts); the longitudinal membership-transition oracle (decoy→real on
  register, real→decoy on deactivation) is inherent to name-based systems
  and is stated, not claimed away.
- Mobile session token is stored AES-256-GCM-encrypted under a per-install
  device key (`mobile/src/secureStore.ts`) — with the plain limitation that
  the device key currently lives in AsyncStorage too (documented fallback
  pending react-native-keychain), so backups include both key and
  ciphertext.

### Analysis engine

- Full-family Benjamini–Hochberg: every testable candidate's p-value is
  computed pre-gate and the effect gates filter only corrected survivors
  (selecting on extremeness first voided FDR control — measured: ~half of
  pure-noise corpora surfaced a false statistical card).
- Replication gate: statistical kinds (temporal, mood_correlation, link,
  inertia, instability, mood_shift) surface only after qualifying on ≥2
  distinct recompute days that constitute an independent second observation
  — evidence-date kinds need a qualification day contributing NEW evidence;
  window-stat kinds need qualification days ≥2 calendar days apart.
  Consequence: re-running an unchanged corpus the next day no longer
  surfaces anything. Direct-measurement kinds keep immediate surfacing.
- Measured false-card rates on pure noise: 0/60 single-shot; ≤1/24 runs
  (4.2%) at daily cadence (14 recomputes), the survivor a documented
  FDR-budget boundary case, not a gate leak (regression:
  `test_daily_cadence_pure_noise_replication_bound`).
- Sentiment lexicon curated: context-dependent words removed ("kind",
  "fed", "present"); "hardly"/"barely" are negation-only per VADER.
- Link cards report the modal exposed gap (`lag_days` + gap1/gap2 counts)
  and say "the day after" only when gap 1 is the mode.
- Inertia's comparative claim uses a Fisher-z difference test; link/mood
  tests use autocorrelation-deflated effective sample sizes.
- Presence topics require ≥4 distinct following-token contexts and are
  suppressed when ≥80% covered by the run's recurring-phrase clusters
  (anti-boilerplate); they carry `detail.presence=true`.
- `update()` is copy-on-entry pure (input state never mutated); semantic
  flips (dominant weekday / direction) retire the old pid to fading and
  fork `pid~2` instead of silently relabeling under an intact history.
- LLM grounding is word-token based (no substring grounding).

### API

- Canonical mount `/api/v1`; `/api` kept as a deprecated legacy alias.
  `GET /api/v1/meta` returns `{unlock_days, llm_available, api_version,
  version}` so clients can discover the canonical base.
- `GET /readyz` (DB `SELECT 1`; 503 on failure) alongside `/healthz`.
- `DELETE /account` prefers the `X-Account-Verifier` header (JSON body is a
  deprecated fallback — DELETE bodies are unreliable across clients and
  proxies).
- Uniform error envelope `{"detail", "code"}` with snake_case codes:
  unauthorized, invalid_credentials, processing_session_required,
  verification_failed (403, wrong verifier), processing_session_invalid,
  not_found, conflict, account_deleted (410), payload_too_large,
  quota_exceeded, blob_quota_exceeded, validation_error, rate_limited
  (+Retry-After), bad_request, entry_blob_invalid, entry_payload_malformed,
  internal_error, service_unavailable. 422s still never echo input.
- Export endpoint rate-limited (`MINDPATTERN_EXPORT_RATE_LIMIT`/`_WINDOW`,
  defaults 5/60); numeric settings gained upper bounds (token TTL ≤ 30d,
  processing TTL ≤ 3600s, rate windows ≤ 3600s).

### Database

- `insights` carries `UniqueConstraint(user_id, kind, for_date)` with
  dialect upsert writes (`on_conflict_do_update`) — multi-worker-safe.
- Question rows older than 90 days are purged during recompute.
- Recompute reads are SQL-bounded (`LIMIT recompute_entry_limit`) and never
  hold a transaction across analysis (the write phase is a second, short
  transaction).
- Connection pool env-configurable (`MINDPATTERN_DB_POOL_SIZE` /
  `_MAX_OVERFLOW` / `_POOL_TIMEOUT`, defaults 5/10/30).
- Alembic: pg advisory lock (727272) + `lock_timeout` 15s +
  `statement_timeout` 300s on Postgres; the entrypoint retries migration
  5× at 3s intervals before failing closed. New revisions e930dbc4f001
  (insights unique) and a7c91e4b2d03 (consent record).
- `MINDPATTERN_TEST_DB_URL` runs the pytest suite against an external DB
  (CI's Postgres job; non-sqlite URLs must contain "test" in the DB name).

### Mobile

- Entry history screen (read/edit/delete; edit = delete + re-upload under a
  fresh id, delete first so a failed replacement never duplicates).
- Explicit one-tap mood check-in (a deliberate tap always wins over
  inferred sentiment); day-1 generic reflective questions pre-threshold,
  answered fully on-device (pool pinned to `shared/generic_questions.json`);
  "Write about this" question→journal bridge.
- 3-panel first-run onboarding (daily habit + 30-day threshold, encryption
  with the one honest exception, no-recovery warning + 13+ line) and an
  in-app offline privacy policy screen.
- Dark + light theme with a full accessibility pass (labels/roles, ≥ 4.5:1
  contrast pinned by tests, 44pt targets); honest inline save/sync feedback
  ("Saved ✓" / "Saved — will sync when online" / a loud "Not saved").
- Daily auto-recompute removed after the red-team audit: shipping the data
  key is only ever an explicit user act from the Question screen.
- Client targets `/api/v1` and sends the account verifier by header.
- Push-only sync documented as deliberate v1 scope (single-device writer;
  History pulls this account's entries; no multi-device conflict model).
- Recovered-entries surface in Settings: rejected/quarantined uploads are
  preserved, never destroyed.

### CI/DevOps

- CI overhaul: Postgres service job running the full backend suite against
  real Postgres, matrix Python 3.12/3.14, Docker build + compose boot gate
  (healthz/readyz assertions, migration-at-head check), contract gates for
  `probe_brain.py` and `verify_vectors.mjs`, and a supply-chain job
  (pip-audit; npm audit advisory until the Metro chain is fixed).
- Lint/type tooling: ruff gate (green rule set), advisory mypy step,
  pre-commit config, Dependabot for pip/npm/github-actions/docker.
- Scheduled weekly mutation testing (mutmut, resumable cache, results
  artifact); still not a PR gate.
- Packaging/hygiene: Dockerfile base image pinned by digest, compose
  postgres pinned by digest, entrypoint migration retry loop, optional
  profile-gated backup service with documented retention/encryption duties,
  MIT LICENSE, this changelog.
- Deliberate observability trade-off, stated plainly: no metrics or crash
  reporting ship in v1 (privacy posture) — production visibility is
  healthz/readyz + container logs. Documented gap, not an oversight.

## 1.0.0 - 2026-09-07

First release-quality tree after three audit/remediation rounds (security
adversarial audit, analysis-methodology audit, red-team round).

### Engine

- Deterministic, idiographic "mini-brain" v3: temporal (every weekday
  tested, Benjamini–Hochberg FDR), within-person mood correlations on
  residuals, lag-1 day-after links, inertia, instability, EWMA mood shift,
  rumination clustering, emergent topics, MinHash/LSH recurring phrases.
- Pattern lifecycle (`candidate → emerging → confirmed → fading →
  archived`, 45-day evidence half-life) with per-card evidence panels.
- Graded VADER-style sentiment engine; corrupt state degrades to amnesia.
- Ground-truth probe (`probe_brain.py`, 9/9 required, zero false
  associations) that exits non-zero on failure.

### Security model

- Client-side key derivation (PBKDF2-HMAC-SHA256, 600k) with HKDF split
  into auth key (server stores `scrypt(auth_key)`) and data key.
- AES-256-GCM blobs AAD-bound to (user, entry, context); cross-platform
  TS⇄Python crypto pinned by `shared/vectors.json` (incl. non-ASCII AAD).
- Single-use, memory-only processing sessions with key zeroization;
  30-active-day revelation threshold enforced server-side.
- Enumeration-resistant salt lookup with decoys; epoch token revocation;
  re-authentication for account deletion and LLM enablement.
- Fail-closed ops gates (production default env, ≥32-char token secret, no
  SQLite outside development), security headers on every response, 2 MiB
  body cap, bounded rate limiting, no access logs in the image.

### Platform

- FastAPI backend (Python 3.12+), Alembic migrations run by the container
  entrypoint, docker-compose stack (postgres + api).
- React Native mobile client (iOS/Android) with offline sync queue,
  device-local baseline mood trend, offline crisis resources screen.
- Optional consent-gated, output-sanitized LLM analysis path (off by
  default).

### Verification

- 573 backend tests (unit + API integration + crypto vectors +
  production-hardening + adversarial regressions), 97% coverage floor.
- 425 mobile tests with 98% per-file coverage thresholds.
- Mutation-tested security + services cores (mutmut; Stryker on mobile).
