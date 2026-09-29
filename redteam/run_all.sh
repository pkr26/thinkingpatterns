#!/usr/bin/env bash
# Red-team campaign runner — every audit, in order, results to redteam/results/.
# Usage: bash redteam/run_all.sh
set -uo pipefail
cd "$(dirname "$0")"
PY=../.venv/bin/python
NODEBIN=../.tools/node/bin

# 2026-09-28 audit: stale results poisoned the summary — a campaign that
# crashed before writing its file left LAST run's verdicts standing, and
# the summary happily counted them as this run's. Clear the slate first.
rm -f results/*.json

# Each harness's exit code is surfaced loudly (2026-09-28 audit): the old
# runner printed the summary even when a campaign had just died, and a
# non-zero exit vanished into the scroll. `run`-style harnesses write an
# ERROR verdict on internal failure, but an import/collection crash never
# gets that far — the WARN lines below are the only trace.
declare -a FAILED=()
run_campaign() {
  if ! "$@"; then
    FAILED+=("$1")
    echo "WARN: campaign $1 exited non-zero" >&2
  fi
}

echo "== backend in-process campaigns =="
run_campaign "$PY" a_crypto.py
run_campaign "$PY" b_auth.py
run_campaign "$PY" c_api.py
run_campaign "$PY" e_crisis.py
run_campaign "$PY" e2_brain.py
run_campaign "$PY" g_infra.py
run_campaign "$PY" g_voice.py
run_campaign "$PY" h_privacy.py

echo "== fake-LLM egress campaign =="
run_campaign "$PY" d_llm.py

echo "== live multi-worker campaign (spawns uvicorn --workers 2 on :8971) =="
run_campaign "$PY" c1_multiworker.py

echo "== mobile campaign (real shipping modules under vitest) =="
(cd ../mobile && PATH="$NODEBIN:$PATH" node_modules/.bin/vitest run \
   --config redteam.vitest.config.ts redteam)
mobile_rc=$?
if [ "$mobile_rc" -ne 0 ]; then
  echo "WARN: mobile vitest campaign exited $mobile_rc" >&2
  FAILED+=("mobile-vitest(rc=$mobile_rc)")
fi

if [ "${#FAILED[@]}" -gt 0 ]; then
  echo "WARN: ${#FAILED[@]} campaign(s) exited non-zero this run: ${FAILED[*]}" >&2
fi

echo
echo "== verdict summary =="
"$PY" - <<'EOF'
import json
from pathlib import Path
rows = []
for f in sorted(Path("results").glob("*.json")):
    rows += json.loads(f.read_text())
from collections import Counter
c = Counter(r["status"] for r in rows)
print(f"{len(rows)} verdicts: " + ", ".join(f"{k}={v}" for k, v in sorted(c.items())))
for r in rows:
    if r["status"] == "FINDING":
        print(f"  FINDING {r['id']}")
EOF
