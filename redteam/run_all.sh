#!/usr/bin/env bash
# Red-team campaign runner — every audit, in order, results to redteam/results/.
# Usage: bash redteam/run_all.sh
set -uo pipefail
cd "$(dirname "$0")"
PY=../.venv/bin/python
NODEBIN=../.tools/node/bin

echo "== backend in-process campaigns =="
"$PY" a_crypto.py
"$PY" b_auth.py
"$PY" c_api.py
"$PY" e_crisis.py
"$PY" e2_brain.py
"$PY" g_infra.py
"$PY" h_privacy.py

echo "== fake-LLM egress campaign =="
"$PY" d_llm.py

echo "== live multi-worker campaign (spawns uvicorn --workers 2 on :8971) =="
"$PY" c1_multiworker.py

echo "== mobile campaign (real shipping modules under vitest) =="
(cd ../mobile && PATH="$NODEBIN:$PATH" node_modules/.bin/vitest run \
   --config redteam.vitest.config.ts redteam)

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
