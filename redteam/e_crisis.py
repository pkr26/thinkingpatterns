"""E1: crisis-detection bypass corpus (Python engine + corpus export for the
TS engine) and the end-to-end impact chain (pattern label -> question quote).

E3: regulatory/clinical-boundary spot checks ride along at the end.

2026-09-17: the corpus lives in shared/crisis_phrases.json ("redteam_corpus")
and its dialog/suppress values are the REQUIRED contract — replayed as gating
fixtures by backend/tests/test_crisis.py and mobile/tests/crisisPhrases.test.ts.
This harness re-runs it live and reports any observed-vs-contract drift.
"""

from __future__ import annotations

import json
from pathlib import Path

from common import RESULTS, guard, run, section, verdict

# The canonical corpus + required verdicts — one source of truth with the
# main suites (editing redteam/crisis_corpus.json alone changes nothing).
SHARED_CONTRACT = RESULTS.parent.parent / "shared" / "crisis_phrases.json"
CORPUS: list[dict] = json.loads(SHARED_CONTRACT.read_text())["redteam_corpus"]


def e1_python_engine() -> None:
    section("E1: crisis bypass corpus — Python engine (server suppress tier + dialog tier)")
    from app.services import crisis

    rows = []
    for row in CORPUS:
        dialog = crisis.matches_dialog(row["sample"])
        suppress = crisis.matches_suppress(row["sample"])
        rows.append({"technique": row["technique"], "sample": row["sample"],
                     "intent": row["intent"], "dialog": dialog, "suppress": suppress,
                     "want_dialog": row["dialog"], "want_suppress": row["suppress"]})
    (RESULTS.parent / "crisis_corpus.json").write_text(json.dumps(rows, indent=1))

    crisis_rows = [r for r in rows if r["intent"] == "crisis"]
    bypass = [r for r in crisis_rows if not r["suppress"]]
    drift = [r for r in rows
             if r["dialog"] != r["want_dialog"] or r["suppress"] != r["want_suppress"]]
    dialog_only_miss = [r for r in crisis_rows if r["suppress"] and not r["dialog"]]
    benign_fp = [r for r in rows if r["intent"] == "benign" and r["dialog"]]

    if drift:
        verdict("E1.contract-drift",
                "FINDING",
                f"{len(drift)}/{len(rows)} samples diverge from the shared contract "
                f"(shared/crisis_phrases.json redteam_corpus): "
                f"{[(r['sample'], r['dialog'], r['want_dialog'], r['suppress'], r['want_suppress']) for r in drift][:6]}")

    by_tech: dict[str, list[dict]] = {}
    for r in bypass:
        by_tech.setdefault(r["technique"], []).append(r["sample"])
    tech_total = {t: sum(1 for r in crisis_rows if r["technique"] == t)
                  for t in {r["technique"] for r in crisis_rows}}
    tech_summary = "; ".join(f"{t}: {len(by_tech.get(t, []))}/{tech_total[t]}"
                             for t in sorted(tech_total))
    verdict("E1.python-suppress-bypass",
            "FINDING" if bypass else "BLOCKED",
            f"{len(bypass)}/{len(crisis_rows)} crisis samples evade the suppress tier "
            f"(the tier that keeps text off cards/questions). Bypasses by technique — "
            f"{tech_summary}. Samples: "
            f"{[r['sample'] for r in bypass][:8]}{'...' if len(bypass) > 8 else ''}")
    verdict("E1.python-dialog-bypass",
            "INFO" if dialog_only_miss else "BLOCKED",
            f"{len(dialog_only_miss)} samples are suppressed-but-no-dialog BY "
            f"DESIGN (hopelessness phrasing sits in the suppress_extra tier: never "
            f"quoted on cards/questions, but the conservative dialog tier stays "
            f"first-person-ideation only): "
            f"{[r['sample'] for r in dialog_only_miss][:6]}")
    verdict("E1.python-false-positives", "INFO" if benign_fp else "BLOCKED",
            f"benign controls firing the dialog tier (documented, accepted "
            f"product stance — see crisisDetect.ts header): "
            f"{[r['sample'] for r in benign_fp]}"
            if benign_fp else "benign controls correctly do not fire")

    # -- end-to-end impact: bypassed label -> quoted daily question ------------
    from datetime import date

    from app.services.patterns import Pattern
    from app.services.questions import build_pool

    quoted = []
    for r in bypass[:10]:
        label = r["sample"]
        p = Pattern(kind="rumination", label=label, occurrences=30, confidence=0.9,
                    detail={"variants": [label]})
        pool = build_pool([p])
        if any(label in q for q in pool):
            quoted.append(label)
    verdict("E1.bypass-to-question-quote",
            "FINDING" if quoted else "BLOCKED",
            f"of {min(10, len(bypass))} bypassing labels fed to question generation, "
            f"{len(quoted)} are interpolated verbatim into reflective questions "
            f"(e.g. {quoted[:2]}) — the full chain: disguised crisis text in a journal "
            f"-> pattern card label -> daily question quoting it back")


def e3_boundary() -> None:
    section("E3: regulatory / clinical boundary spot checks")
    import subprocess

    root = RESULTS.parent.parent
    # 1) No diagnosis vocabulary in output-generating code
    out = subprocess.run(
        ["grep", "-rniE", "depress|bipolar|diagnos|prescrib|medication|therapy app",
         str(root / "backend/app/services/questions.py"),
         str(root / "backend/app/services/llm.py")],
        capture_output=True, text=True).stdout.strip()
    lines = [l for l in out.splitlines() if "No advice, no diagnosis" not in l]
    if lines:
        summary = "diagnosis/clinical vocabulary found: " + repr(lines[:3])
    else:
        summary = ("no diagnosis vocabulary in question templates or the LLM module "
                   "(the only grep hit is the prompt instruction 'No advice, no "
                   "diagnosis' itself)")
    verdict("E3.diagnosis-language", "BLOCKED" if not lines else "FINDING", summary)

    # 2) Kinds cannot carry clinical claims
    from app.services.llm import _ALLOWED_KINDS

    verdict("E3.llm-kind-allowlist", "BLOCKED",
            f"LLM pattern kinds are fixed to {_ALLOWED_KINDS} — no diagnosis/flag kind "
            f"exists for a model output to claim")

    # 3) Crisis screen copy: safe-messaging shape (#chatsafe-adjacent)
    screen = (root / "mobile/src/screens/CrisisScreen.tsx").read_text()
    checks = {
        "988 line present": "988" in screen,
        "Crisis Text Line 741741": "741741" in screen,
        "emergency guidance": "911" in screen,
        "findahelpline fallback": "findahelpline" in screen,
        "no method detail language": "method" not in screen.lower(),
    }
    failed = [k for k, v in checks.items() if not v]
    verdict("E3.crisis-screen-copy", "BLOCKED" if not failed else "FINDING",
            f"crisis resources screen: {checks}")


async def main() -> None:
    await guard("E1", e1_python_engine)
    await guard("E3", e3_boundary)


if __name__ == "__main__":
    run(main, "e_crisis")
