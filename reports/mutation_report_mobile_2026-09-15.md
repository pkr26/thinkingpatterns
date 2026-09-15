# MindPattern Mobile — Deep Mutation Testing Report (2026-09-15)

**Scope:** the entire mobile frontend — `mobile/src/**` (39 files: crypto
stack, vault, store, offline queue, API client, navigation, theme, shared
components, and all ten screens).

**Tooling:** Stryker 10.0.0 + `@stryker-mutator/vitest-runner` · vitest 3.2.7
(react-test-renderer) · Node 22.23.2 · `coverageAnalysis: "all"`,
`vitest.related: false`, `inPlace: true`.

**Baseline at start:** the historical 2026-09-04 report's mobile 100% score
did NOT reproduce: a fresh full campaign over the current tree produced
**4,330 mutants, score 82.73%** (3,531 killed, 51 timeout, 747 survived,
1 no-coverage, 18 pre-existing suppressions). Every screen and most plumbing
modules had grown since the last campaign without equivalent pins — the
survivors concentrated in InsightsScreen (146), HistoryScreen (126),
CrisisScreen (56), offlineQueue (48), SettingsScreen (45), EntryScreen (40),
QuestionScreen (40), LoginScreen (35), client.ts (34), store.tsx (32),
moodLog.ts (27).

---

## Headline results

| | mutants | killed | timeout | survived | ignored¹ | score |
|---|---|---|---|---|---|---|
| **Final full campaign (2026-09-15, post-pins)** | **4,356** | **4,079** | **52** | **15** | **210** | **99.64%** |
| Baseline full campaign (same tree, pre-pins) | 4,330 | 3,531 | 51 | 747 | 18 | 82.73% |

31 of 39 files score **100%**. The 8 files with residuals, and every one
of the 15 survivors (each individually re-verified by hand-applying it):

| File | Survivors | Disposition |
|---|---|---|
| moodLog.ts | 4 | BlockStatement on catch/finally clause bodies: the corrupt-legacy catch fallthrough reaches the identical empty-days result, and the three `finally { zeroize(keyCopy) }` blocks only scrub a private buffer copy — unobservable. No comment form attaches to a clause body precisely (range form would hide killed try-body mutants), so these stay visible rather than suppressed. |
| offlineQueue.ts | 4 | Line-shared typeof-arm equivalents (`attempts`/`notBefore`/`parsed`-object/`raw === null`): `Number.isFinite` subsumes the typeof arm for JSON-persisted values, and the `""`-arm sibling of the raw check is pinned. Suppressing the line would exclude killable siblings of the same mutator. |
| InsightsScreen.tsx | 2 | Static-activation artifact (finding 3): both `sparkBar` borderRadius mutants fail the sparkline-geometry pin when hand-applied; the runner never activates them. Counted as killed-by-pin in the effective score (99.69%). |
| HistoryScreen.tsx | 1 | `if (statusTimer.current)` guard→true: `clearTimeout(null)` is a no-op; the →false sibling is pinned (re-arm removal is a kill). |
| EntryScreen.tsx | 1 | `if (draftRestored) setDraftRestored(false);`→true: React bails on same-value setState; the →false sibling is pinned. |
| store.tsx | 1 | `typeof insights?.active_days === "number"` arm→true: subsumed by `Number.isFinite` for server JSON; the whole-condition mutants on the same line are killed. |
| api/client.ts | 1 | cached-salt `typeof parsed.o !== "string"` arm→false: a non-string origin can never equal the string base URL, so the next check returns null anyway; the `s`-arm sibling is pinned. |
| unlockProof.ts | 1 | `"utf8"` literal: Node treats the empty encoding as utf8 (byte-verified); the marker literal on the same line is pinned. |

¹ `Ignored` = mutants excluded by a justified `// Stryker disable next-line`
comment (192 added by this campaign, 18 historical), each verified to cover
exactly the intended site — every suppression carries a one-line proof of
equivalence in the source, and no killable mutant is hidden behind one.

**Campaign discipline.** Every survivor in the 747 was triaged
mutant-by-mutant: a pin test was written for each killable mutant, and each
pin was verified by hand-applying the exact mutant replacement to the source
and observing at least one test fail (the backend campaign's two-stage
discipline, applied here per-file). Genuinely equivalent mutants were
suppressed at the mutation site with a next-line `Stryker disable` comment
carrying a one-line proof — no killable mutant is hidden behind a
suppression.

- Suite growth: **783 → 1,014 tests** (231 new pin tests in 15 new
  `*.pins.test.ts(x)` files), full suite green in ~3 s, 100% lines /
  statements / functions, ≥98% branches per file (v8, perFile thresholds).
- `tsc --noEmit` clean; `verify_vectors` (real compiled modules × shared
  vectors) green.
- `stryker.config.json` `thresholds.break` raised 50 → 99 (the measured
  floor minus margin for the two static-activation artifacts).

## Real findings (beyond missing pins)

1. **Time-zone tests were silently pool-dependent (fixed).** The
   `localDateISO` tests switched `process.env.TZ` per assertion. Under
   vitest's default `forks` pool that works; under the `threads` pool —
   which Stryker's vitest-runner hardcodes (`pool: 'threads',
   maxWorkers: 1`, an inline override the config file cannot change) — the
   assignment never reaches the process timezone, the getters stay on the
   ambient zone, and the east-of-UTC case fails deterministically. The
   Stryker dry run refused to start. The tests were rewritten to derive
   expectations from `getTimezoneOffset()` — the same zone state the
   implementation's Date getters read — valid under any pool and any
   ambient zone, with the UTC-day rejection asserted per-instant whenever
   the oracle actually differs (every non-UTC zone puts at least one of the
   two probe instants on a different local day).
2. **Stryker `disable/restore` RANGE comments leak (tooling finding).** A
   `// Stryker restore …` comment placed as the last statement inside a
   block does not attach to any AST node babel visits, so the preceding
   `disable` stays active for the rest of the file — suppressing mutants
   that were already killed by pins (verified: 139 mutants over-ignored
   from 13 intended sites). Only the **next-line** form
   (`// Stryker disable next-line <mutators>: <reason>`, no restore) is
   safe, and even then the comment must attach to the mutated node — a
   comment above `}, [deps]);` does not attach to the array; it must sit
   inside the call, directly above the array literal. This campaign uses
   next-line form exclusively, and each suppression's ignore set was
   verified to cover exactly the intended mutants.
3. **Static mutants inside `StyleSheet.create` are not reliably activated
   by the runner (documented artifact).** The two `sparkBarUp/Down
   {borderRadius: 1}` ObjectLiteral mutants in InsightsScreen register as
   `static: true`; isolated single-mutant runs (`--mutate file:574-575`,
   also at `--concurrency 1`) still report them surviving while the
   hand-applied mutants deterministically fail the sparkline-geometry pin
   (exact bar style objects). Both are counted as killed-by-pin in the
   effective score; the tool report shows them as survivors.
4. **Masked style assertions.** Several style mutants survived only because
   `expectStyle` matches ANY node in the tree — e.g. navigation's BootSplash
   styles were shadowed by CrisisScreen rendering identical theme objects,
   and GhostButton's text style aliased `{color:"#8a91a3",fontSize:14}`
   with the chip overlays. The pins assert the exact style ARRAY of the
   specific node instead.
5. **Trust-boundary gaps worth naming** (now pinned): pattern-card
   sanitization accepted a hostile 600-char label without asserting the
   500-char truncation; evidence-row guards mutated to `true` rendered
   "undefined entries…" rows unchallenged; the null-user mood log
   (`buildAad("moodlog", null)`) must never be read when no user id is
   known — removing the `userId && dataKey` guard makes that log observable
   (AAD-matched pin).

## Methodology

1. **Fresh full campaign** over `src/**` (4,330 mutants, 4m21s wall on 18
   cores) → per-file survivor listings with exact replacements.
2. **Triage** every survivor into killable / provably equivalent / unknown.
3. **Pin tests** in new `*.pins.test.ts(x)` files, one per module,
   mirroring each existing test file's mock harness (dynamic
   `await import` of sources after `vi.mock` so mutants fail at test
   level, not at collection).
4. **Hand verification**: apply the mutant → run existing+pins tests →
   ≥1 failure = kill; restore. Equivalents verified in the inverse
   direction (mutant applied, suite stays green).
5. **Serial per-file Stryker re-verification** of every touched file (the
   table above), then a final full campaign for the record.
6. Suppressions: next-line form only, with a one-line proof, each verified
   to ignore exactly the intended mutants.

## Equivalent-mutant classes (the recurring proofs)

- `typeof x === "number" && Number.isFinite(x)` — the typeof arm is
  subsumed whenever x is JSON-parsed (`Number.isFinite` is false for every
  non-number; NaN/Infinity cannot survive JSON). Killable when the value
  is computed (e.g. `parseRetryAfter("-5")`).
- Hook dependency arrays whose elements are stable identities under the
  test seam (mocked callbacks, string-literal arrays) — `[]` is
  behaviorally identical there.
- Dead stores / dead inits never read on any reachable path (pre-effect
  initial state under act(), flags with no consumer — e.g. moodLog's
  `legacy` return flag).
- Defensive no-op guards: `clearTimeout(null)` is a no-op; React 18
  post-unmount setState is silent; `.catch(() => {})` swallows the
  mutant's TypeError leaving the same fallback.
- Truncation that cannot change a comparison (`kind.slice(0,64)` against
  known kinds ≤12 chars; base64url 9-byte nonces never pad).
- Arithmetic coincidences proven per-site (e.g. `i <= a.length` XOR loop
  where the extra iteration XORs `undefined^undefined → 0`; the
  generic-questions seed where 33 ≡ 1 mod the 8-item pool).
- Line-shared equivalents: a few provably-equivalent operand-arm mutants
  share a line with killable siblings of the same mutator (next-line
  suppression is line-granular) — they remain as documented survivors
  rather than hiding their killable neighbors.

The per-site justifications live in the source next to each suppression;
the survivor dispositions live in the table above. The pin files:
`tests/*.pins.test.ts(x)` and `tests/screens/*.pins.test.tsx` (15 files,
231 tests) — every pin was verified by hand-applying its mutant and
observing the failure before it was trusted.
## Reproduce

```bash
cd mobile
npx vitest run --coverage.enabled=false   # 1,014 tests green
npm test                                  # with coverage thresholds
npm run typecheck && npm run verify:vectors
npx stryker run                           # full campaign, ~4–5 min
```

Per-file verification: `npx stryker run --mutate src/screens/HistoryScreen.tsx`
(any file path).
