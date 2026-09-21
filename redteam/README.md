# Red-team campaign harness

Executable attack harnesses for the security audits (2026-09-16 through
2026-09-20). The original per-finding reports were removed in the
production cleanup; the remediations live on as regression pins in the
backend/mobile test suites, and the full audit history is preserved in git
history (commits tagged 2026-09-16 .. 2026-09-21). Run everything:

```bash
bash redteam/run_all.sh
```

| Script | Audits | What it attacks |
|---|---|---|
| `a_crypto.py` | A1, A4, A5, A6 | processing-session keystore, KDF downgrade, nonce seam, AAD corpus generation |
| `b_auth.py` | B1–B3 | verifier replay, token forgery, rate-limit evasion, enumeration/timing |
| `c_api.py` | C2, C3 | DoS amplification, logic abuse, the phi=1.0 recompute crash |
| `c1_multiworker.py` | C1 | live `uvicorn --workers 2` (port 8971): rate/quota/keystore fragmentation |
| `d_llm.py` | D1, D2 | sanitizer corpus, fake-LLM egress/consent/hang endpoint |
| `e_crisis.py` | E1, E3 | crisis bypass corpus (Python engine + corpus export), clinical boundary |
| `e2_brain.py` | E2 | adversarial corpora vs `brain.update` |
| `g_infra.py` | G1–G3 | backup config, supply chain, fail-closed boots, hygiene |
| `h_privacy.py` | H1–H3 | metadata inference, export, erasure |
| `../mobile/redteam/f_mobile.test.ts` | E1-TS, A2, A3, A4-TS, A6-TS, F1, F2, F4 | real mobile modules under vitest |
| `mutation_campaign_2026-09-18/` | — | behavioral mutation campaign: 36 mutants over the non-negotiables (campaign report preserved in git history) |
| `mutation_campaign_2026-09-18_round2/` | — | round 2: 70 mutants over brain round 2, threshold, crypto contracts, crisis, ops, idiographic isolation, sync queue, and REDTEAM-AS-ORACLE (mutate a control, check these harnesses notice) — which found and fixed the harness rot below |
| `mutation_campaign_2026-09-19/` | — | round 3: 62 mutants over backend infrastructure — authorization & access control, database/ORM, boundaries & business logic, error handling & transactions, cache & invalidation, rate limiting & concurrency (adds `pin_check.py`, the hand-verification driver that re-applies each mutant against its pin) |
| `run_pr_mutation_gate.py` | — | per-PR gate: re-applies every behavioral mutant whose target file is in the diff (wired in `.github/workflows/mutation-pr.yml` with a bounded diff-scoped mutmut job) |

Generated at runtime (gitignored): `results/*.json` verdicts and per-campaign `results/`. Tracked fixtures: `aad_corpus.json`, `crisis_corpus.json`
(promote both into the main suites as regression fixtures). Everything runs
against throwaway in-process or localhost servers; nothing leaves the machine.

Harness health notes (2026-09-18 round 2): the shared `make_settings` now
uses a per-process temp FILE sqlite (in-memory gave every pool connection
its own empty database since the Alembic-first startup — `/auth/register`
500'd with "no such table"); `direct_insert_entry` writes tz-aware
`received_at`; `e2_brain.py` imports `common` before `app.*` (sys.path
bootstrap). Never regenerate corpus fixtures while the engine is mutated,
and never let a campaign run write `.pyc` (the round-2 harness sets
`PYTHONDONTWRITEBYTECODE=1` — same-size mutants reverted inside one clock
second otherwise leave poisoned bytecode behind).
