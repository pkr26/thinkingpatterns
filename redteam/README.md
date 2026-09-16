# Red-team campaign harness

Executable attack harnesses for the audits catalogued in
`reports/redteam_audit_2026-09-16.md`. Run everything:

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

Artefacts: `results/*.json` (verdicts), `aad_corpus.json`, `crisis_corpus.json`
(promote both into the main suites as regression fixtures). Everything runs
against throwaway in-process or localhost servers; nothing leaves the machine.
