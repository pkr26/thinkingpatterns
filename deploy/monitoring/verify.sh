#!/usr/bin/env bash
# Validate the monitoring stack WITHOUT docker.
#
# What it checks:
#   1. promtool (if on PATH): full semantic validation —
#        promtool check config prometheus.yml   (also loads rule_files)
#        promtool check rules  alerts.yml
#      A placeholder MINDPATTERN_METRICS_TOKEN is exported because
#      prometheus.yml fails closed on the real one being unset.
#   2. Always: YAML syntax + structure of every file in this directory
#      (and ../backup-offsite/docker-compose.yml when present), using the
#      repo virtualenv's python (../../.venv) with PyYAML, falling back to
#      any python3 that imports yaml. The structural pass ALSO verifies
#      that every alert expression only references metric names that
#      backend/app/metrics.py actually exports (plus Prometheus' own up /
#      probe_success and the textfile heartbeat) — so an alert can never
#      silently drift from the exposition.
#   3. sh -n syntax check of the two shell scripts (shellcheck if present).
#
# Exit 0 = everything checked passed. Exit 1 = at least one check failed.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd -P)
cd "$SCRIPT_DIR"

status=0
note() { printf 'verify: %s\n' "$*"; }
fail() { printf 'verify: FAIL: %s\n' "$*" >&2; status=1; }

# --- interpreter for the YAML/structure pass -------------------------------
PY=""
for candidate in "$SCRIPT_DIR/../../.venv/bin/python" python3; do
  if command -v "$candidate" >/dev/null 2>&1 \
     && "$candidate" -c 'import yaml' >/dev/null 2>&1; then
    PY="$candidate"
    break
  fi
done
if [ -n "$PY" ]; then
  note "YAML interpreter: $PY ($( "$PY" -c 'import yaml; print("PyYAML", yaml.__version__)' ))"
else
  fail "no python with PyYAML found (expected ../../.venv/bin/python or python3); cannot validate YAML"
fi

# --- promtool (optional, semantic) ------------------------------------------
if command -v promtool >/dev/null 2>&1; then
  note "promtool $(promtool --version 2>&1 | head -n 1): check config + check rules"
  if MINDPATTERN_METRICS_TOKEN=verify-placeholder promtool check config prometheus.yml; then
    note "promtool check config prometheus.yml: OK"
  else
    fail "promtool check config prometheus.yml"
  fi
  if MINDPATTERN_METRICS_TOKEN=verify-placeholder promtool check rules alerts.yml; then
    note "promtool check rules alerts.yml: OK"
  else
    fail "promtool check rules alerts.yml"
  fi
else
  note "promtool not on PATH — skipping semantic validation (YAML syntax + structure still checked below)"
fi

# --- YAML syntax + structure + metric grounding -----------------------------
if [ -n "$PY" ]; then
  if "$PY" - "$SCRIPT_DIR" <<'PYEOF'
import re
import sys
from pathlib import Path

import yaml

base = Path(sys.argv[1])

# Exactly what backend/app/metrics.py renders (keep in sync with its
# render() method). Anything else mindpattern_* in an alert expr is a bug.
EXPORTED = {
    "mindpattern_requests_total",
    "mindpattern_recompute_seconds_bucket",
    "mindpattern_recompute_seconds_count",
    "mindpattern_recompute_seconds_sum",
    "mindpattern_llm_calls_total",
    "mindpattern_keystore_sessions",
}
TEXTFILE = {"mindpattern_backup_last_success_timestamp_seconds"}  # backup-heartbeat.sh
BUILTIN = {"up", "probe_success"}  # provided by Prometheus / blackbox job

errors = []

def load(rel):
    path = base / rel
    try:
        with path.open("r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        print(f"verify: yaml parse OK: {rel}")
        return doc
    except FileNotFoundError:
        errors.append(f"missing file: {rel}")
        return None
    except yaml.YAMLError as exc:
        errors.append(f"yaml parse FAILED: {rel}: {exc}")
        return None

prom = load("prometheus.yml")
if isinstance(prom, dict):
    if not isinstance(prom.get("global"), dict):
        errors.append("prometheus.yml: missing global section")
    jobs = prom.get("scrape_configs")
    if not isinstance(jobs, list) or not jobs:
        errors.append("prometheus.yml: scrape_configs must be a non-empty list")
    else:
        for job in jobs:
            if not isinstance(job, dict) or not job.get("job_name"):
                errors.append("prometheus.yml: every scrape config needs a job_name")
        if not any(j.get("job_name") == "mindpattern-api" for j in jobs):
            errors.append("prometheus.yml: no mindpattern-api scrape job")
    rules = prom.get("rule_files")
    if not isinstance(rules, list) or "alerts.yml" not in rules:
        errors.append("prometheus.yml: rule_files must include alerts.yml")

alerts = load("alerts.yml")
if isinstance(alerts, dict):
    groups = alerts.get("groups")
    seen_names = set()
    n_alerts = 0
    if not isinstance(groups, list) or not groups:
        errors.append("alerts.yml: groups must be a non-empty list")
    else:
        for group in groups:
            gname = group.get("name", "<unnamed>")
            for rule in group.get("rules", []):
                name = rule.get("alert")
                if not name:
                    errors.append(f"alerts.yml: rule in group {gname} has no alert name")
                    continue
                n_alerts += 1
                if name in seen_names:
                    errors.append(f"alerts.yml: duplicate alert name {name}")
                seen_names.add(name)
                severity = (rule.get("labels") or {}).get("severity")
                if severity not in {"S1", "S2", "S3"}:
                    errors.append(f"alerts.yml: {name} severity must be S1/S2/S3 (got {severity!r})")
                runbook = (rule.get("annotations") or {}).get("runbook")
                if not runbook:
                    errors.append(f"alerts.yml: {name} has no runbook annotation")
                expr = rule.get("expr")
                if not expr or not str(expr).strip():
                    errors.append(f"alerts.yml: {name} has an empty expr")
                    continue
                tokens = set(re.findall(r"[a-zA-Z_][a-zA-Z0-9_:]*", str(expr)))
                used = sorted(t for t in tokens if t.startswith("mindpattern_"))
                bad = sorted(t for t in used if t not in EXPORTED | TEXTFILE)
                if bad:
                    errors.append(
                        f"alerts.yml: {name} references metric(s) metrics.py does NOT export: {', '.join(bad)}"
                    )
                grounded = sorted(tokens & (EXPORTED | TEXTFILE | BUILTIN))
                if not grounded:
                    errors.append(f"alerts.yml: {name} expr references no known metric")
                else:
                    print(f"verify: alert {name} [{severity}] grounded in: {', '.join(grounded)}")
    print(f"verify: alerts.yml: {n_alerts} alert rule(s) across {len(groups)} group(s)")
else:
    errors.append("alerts.yml: not a rule-file mapping (expected groups:)")

for rel in [
    "docker-compose.yml",
    "grafana/provisioning/datasources/datasource.yml",
    "../backup-offsite/docker-compose.yml",
]:
    path = base / rel
    if not path.exists():
        if rel.startswith("../"):
            print(f"verify: yaml skip (not present): {rel}")
            continue
        errors.append(f"missing file: {rel}")
        continue
    doc = load(rel)
    if rel.endswith("docker-compose.yml") and isinstance(doc, dict):
        if not isinstance(doc.get("services"), dict) or not doc["services"]:
            errors.append(f"{rel}: no services")
        for svc_name, svc in doc["services"].items():
            if not (svc or {}).get("image"):
                errors.append(f"{rel}: service {svc_name} has no image")

if errors:
    for e in errors:
        print(f"verify: FAIL: {e}", file=sys.stderr)
    sys.exit(1)
print("verify: structure + metric grounding OK")
PYEOF
  then
    note "YAML structure pass: OK"
  else
    fail "YAML structure pass (see messages above)"
  fi
fi

# --- shell scripts ------------------------------------------------------------
for sh_file in check-backup-freshness.sh backup-heartbeat.sh; do
  if sh -n "$sh_file"; then
    note "sh -n $sh_file: OK"
  else
    fail "sh -n $sh_file"
  fi
done
if command -v shellcheck >/dev/null 2>&1; then
  if shellcheck check-backup-freshness.sh backup-heartbeat.sh; then
    note "shellcheck: OK"
  else
    fail "shellcheck"
  fi
else
  note "shellcheck not on PATH — skipped (sh -n syntax check still ran)"
fi

if [ "$status" -eq 0 ]; then
  note "ALL CHECKS PASSED"
else
  note "CHECKS FAILED (see above)"
fi
exit "$status"
