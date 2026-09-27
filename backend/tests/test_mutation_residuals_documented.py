"""The PR mutation gate's residual allowlist cannot silently grow.

``redteam/run_pr_mutation_gate.py`` re-runs the behavioral campaign
mutants on every PR but deliberately WARNs instead of failing for the
ids in its ``DOCUMENTED_RESIDUALS`` set — genuine survivors whose
survival carries a written defense-in-depth or unreachability argument.
That allowlist is a security register, and a register nobody cross-checks
drifts: an id added during a rushed triage would silently exempt a live
mutant from every future PR gate. This file pins the gate's set against
``docs/SECURITY_RESIDUALS.md`` (both parsed READ-ONLY — the gate and the
register each stay owned by their own tooling), the same contract the
weekly red-team workflow already enforces for harness FINDING residuals
(.github/workflows/redteam.yml asserts its allowlist ids appear in that
document).

Register debt (2026-09-26 test-infrastructure audit, item 3): the six
ids allowlisted when this test was written — I4, J1, N4, N9, O6, S10 —
carry their defenses in the gate's own comment block and the campaign
reports preserved in git history, NOT yet in SECURITY_RESIDUALS.md.
Editing that document is outside this suite's ownership, so
``REGISTER_DEBT`` below freezes exactly that starting set: every debt id
is exempt until the day it gains a ``\\`id\\``-style entry in the
register, at which point keeping it here FAILS this test (prune it) —
the debt ratchets down, never up. Any NEW id added to the gate's
allowlist must be registered in SECURITY_RESIDUALS.md in the same
change; there is no path to a silently undocumented residual anymore.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
GATE_PATH = REPO_ROOT / "redteam" / "run_pr_mutation_gate.py"
REGISTER_PATH = REPO_ROOT / "docs" / "SECURITY_RESIDUALS.md"

#: Frozen 2026-09-26 (see module docstring). May only shrink; an entry
#: leaves either when its id is killed out of the gate's allowlist or
#: when SECURITY_RESIDUALS.md gains its defense paragraph.
REGISTER_DEBT = frozenset({"I4", "J1", "N4", "N9", "O6", "S10"})


def _gate_residual_ids() -> set[str]:
    """The literal DOCUMENTED_RESIDUALS set from the gate, via ast — the
    test always reads the live allowlist, never a copy of it."""
    tree = ast.parse(GATE_PATH.read_text(encoding="utf-8"), filename=str(GATE_PATH))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(t, ast.Name) and t.id == "DOCUMENTED_RESIDUALS" for t in node.targets
        ):
            continue
        if not isinstance(node.value, ast.Set):
            raise AssertionError(
                "DOCUMENTED_RESIDUALS in redteam/run_pr_mutation_gate.py is no "
                "longer a set literal — update this test's parser alongside it"
            )
        ids: set[str] = set()
        for element in node.value.elts:
            if not isinstance(element, ast.Constant) or not isinstance(element.value, str):
                raise AssertionError(
                    "DOCUMENTED_RESIDUALS contains a non-string literal — update "
                    "this test's parser alongside it"
                )
            ids.add(element.value)
        return ids
    raise AssertionError("DOCUMENTED_RESIDUALS not found in redteam/run_pr_mutation_gate.py")


def _registered_ids() -> set[str]:
    """Ids with a defense paragraph in the register. Mirrors the weekly
    red-team workflow's convention: the id appears backticked (the form
    the document's tables use, `` `I4` ``-style) anywhere in the doc."""
    text = REGISTER_PATH.read_text(encoding="utf-8")
    return {residual for residual in _gate_residual_ids() if f"`{residual}`" in text}


def test_gate_residual_allowlist_is_documented_or_frozen_debt():
    """Every allowlisted mutant id either already has its defense in
    docs/SECURITY_RESIDUALS.md or is one of the frozen REGISTER_DEBT ids.
    A NEW id with neither fails here — register it in the document in the
    same change that adds it to the gate."""
    residuals = _gate_residual_ids()
    assert residuals, "the gate's DOCUMENTED_RESIDUALS parsed empty — parser rot"
    undocumented = residuals - _registered_ids() - REGISTER_DEBT
    assert not undocumented, (
        "redteam/run_pr_mutation_gate.py DOCUMENTED_RESIDUALS ids without a "
        "defense entry in docs/SECURITY_RESIDUALS.md (and not in this test's "
        "frozen REGISTER_DEBT): "
        + ", ".join(sorted(undocumented))
        + " — write the defense paragraph, or kill the mutant and drop the id"
    )


def test_register_debt_ratchets_down_only():
    """REGISTER_DEBT hygiene, both directions: no phantom entries (an id
    whose mutant got killed and left the gate's allowlist must leave the
    debt set too), and no lazy entries (once SECURITY_RESIDUALS.md carries
    an id's defense, the debt exemption is dead weight — prune it and let
    the strict check own the id from then on)."""
    residuals = _gate_residual_ids()
    phantoms = REGISTER_DEBT - residuals
    assert not phantoms, (
        "REGISTER_DEBT names ids no longer in the gate's DOCUMENTED_RESIDUALS "
        "(killed mutants — prune them): " + ", ".join(sorted(phantoms))
    )
    lazy = REGISTER_DEBT & _registered_ids()
    assert not lazy, (
        "REGISTER_DEBT ids that ARE now documented in docs/SECURITY_RESIDUALS.md "
        "(prune the debt entry — the strict check owns them): " + ", ".join(sorted(lazy))
    )
