#!/usr/bin/env bash
# Validate the monitoring stack WITHOUT docker.
#
# What it checks:
#   1. promtool (if on PATH): full semantic validation —
#        promtool check config prometheus.yml   (also loads rule_files)
#        promtool check rules  alerts.yml
#      The config check runs against a staged copy whose bearer_token_file
#      path is rewritten to a placeholder file: the committed config points
#      at the CONTAINER path /etc/prometheus/metrics-token, which cannot
#      exist on the host.
#   2. Always: YAML syntax + structure of every file in this directory
#      (and ../backup-offsite/docker-compose.yml when present), using the
#      repo virtualenv's python (../../.venv) with PyYAML, falling back to
#      any python3 that imports yaml. The structural pass ALSO derives the
#      exported metric list from backend/app/metrics.py's render() itself
#      (read-only) and verifies that every alert expression references
#      only names the API actually exports (plus Prometheus' own up /
#      probe_success and the textfile heartbeat) — so neither an alert nor
#      the grounding check itself can silently drift from the exposition.
#      It further fails if the mindpattern-api job stops using
#      bearer_token_file (the ${VAR} env-expansion class of breakage).
#   3. sh -n syntax check of the two shell scripts (shellcheck if present).
#
# Exit 0 = everything checked passed. Exit 1 = at least one check failed.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd -P)
cd "$SCRIPT_DIR"

# --- optional --production: enforce the digest-pinning contract (G-7) -------
PRODUCTION=0
if [ "${1:-}" = "--production" ]; then
  PRODUCTION=1
fi

status=0
note() { printf 'verify: %s\n' "$*"; }
fail() { printf 'verify: FAIL: %s\n' "$*" >&2; status=1; }

if [ "$PRODUCTION" -eq 1 ]; then
  note "--production: enforcing the digest-pinned image contract"
  # 2026-09-21 audit G-7: the "pin before production" comment on the
  # operator overlays was unenforced. Under --production every image
  # reference in the production compose and BOTH overlays must be either
  # the required-env form (no mutable default) or repo:tag@sha256:<64hex>.
  for compose_file in ../../docker-compose.yml \
                      docker-compose.yml \
                      ../backup-offsite/docker-compose.yml; do
    while IFS= read -r image_line; do
      image_ref="${image_line#*image: }"
      image_ref="${image_ref%%#*}"
      if [ -z "$image_ref" ]; then
        continue
      fi
      case "$image_ref" in
        *\$\{*:\?\ *|*\$\{*\:\?\ *|*\$\{*\:?*)
          # required-env form (${VAR:?message}) — no mutable default to pin
          ;;
        *@sha256:[a-f0-9]*)
          ;;
        *)
          fail "--production: $compose_file serves a mutable image ref: $image_ref (pin its digest; see the file's pinning notes)"
          ;;
      esac
    done < <(grep -E '^\s*image:' "$compose_file" || true)
  done
  if [ "$status" -eq 0 ]; then
    note "--production digest assertion: OK"
  fi
fi

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
  # The committed config points bearer_token_file at the CONTAINER path
  # /etc/prometheus/metrics-token. Stage a copy with that path rewritten
  # to a placeholder file (and alerts.yml reachable from both resolution
  # bases promtool is known to use for rule_files) so the check is honest
  # about the config as shipped.
  promtool_tmp=$(mktemp -d)
  mkdir -p "$promtool_tmp/etc/prometheus"
  sed "s|/etc/prometheus/metrics-token|$promtool_tmp/etc/prometheus/metrics-token|" \
    prometheus.yml > "$promtool_tmp/etc/prometheus/prometheus.yml"
  cp alerts.yml "$promtool_tmp/etc/prometheus/"
  cp alerts.yml "$promtool_tmp/"
  printf 'verify-placeholder-token' > "$promtool_tmp/etc/prometheus/metrics-token"
  if (cd "$promtool_tmp" && promtool check config etc/prometheus/prometheus.yml); then
    note "promtool check config prometheus.yml: OK"
  else
    fail "promtool check config prometheus.yml"
  fi
  rm -rf "$promtool_tmp"
  if promtool check rules alerts.yml; then
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

# Derive the exported metric list from backend/app/metrics.py ITSELF
# (read-only) instead of a hand-copied set: parse the render() method —
# the single place exposition lines are emitted — and collect every
# mindpattern_* name literal it writes. Drift (a metric added to or
# removed from the exposition) then fails or relaxes this check in lock
# step, instead of silently leaving a removed metric "grounded".
metrics_src = (base / ".." / ".." / "backend" / "app" / "metrics.py").read_text(
    encoding="utf-8"
)
render_match = re.search(
    r"^    def render\(.*?(?=^    def |^class |\Z)", metrics_src, re.M | re.S
)
if not render_match:
    errors = ["could not locate render() in backend/app/metrics.py"]
    EXPORTED = set()
else:
    # Skip comment lines and "# TYPE ..." string literals: the base
    # histogram family named there is not itself a series — only the
    # _bucket/_count/_sum exposition lines are.
    render_code = "\n".join(
        line for line in render_match.group(0).splitlines()
        if not line.lstrip().startswith("#")
    )
    render_code = re.sub(r'"# TYPE [^"]*"', '""', render_code)
    EXPORTED = set(re.findall(r"mindpattern_[a-zA-Z0-9_:]+", render_code))
    print(f"verify: metrics.py render() exports: {', '.join(sorted(EXPORTED))}")
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
        else:
            api_job = next(j for j in jobs if j.get("job_name") == "mindpattern-api")
            # The credential MUST travel by bearer_token_file: Prometheus
            # does not env-expand config contents, so `bearer_token: ${VAR}`
            # would send the literal string and 401 every scrape.
            if str(api_job.get("bearer_token", "")).find("$") != -1 or (
                api_job.get("bearer_token") and not api_job.get("bearer_token_file")
            ):
                errors.append(
                    "prometheus.yml: mindpattern-api uses bearer_token (env vars are "
                    "NOT expanded — use bearer_token_file)"
                )
            if api_job.get("bearer_token_file") != "/etc/prometheus/metrics-token":
                errors.append(
                    "prometheus.yml: mindpattern-api must use "
                    "bearer_token_file: /etc/prometheus/metrics-token "
                    "(mounted by the monitoring compose configs: entry)"
                )
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

# --- provisioned Grafana dashboards: JSON + metric grounding --------------
# Same discipline as alerts.yml (2026-09-21 follow-up): every panel
# expression must reference only names metrics.py actually exports (plus
# the textfile heartbeat), and every panel must point at the provisioned
# datasource uid — a dashboard that drifts from the exposition fails here,
# not at 3am on a blank chart.
import json  # noqa: E402 — local to this pass on purpose

for db_rel in sorted((base / "grafana" / "dashboards").glob("*.json")):
    rel = f"grafana/dashboards/{db_rel.name}"
    try:
        dashboard = json.loads(db_rel.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        errors.append(f"{rel}: JSON parse FAILED: {exc}")
        continue
    panels = dashboard.get("panels")
    if not isinstance(panels, list) or not panels:
        errors.append(f"{rel}: no panels")
        continue
    n_exprs = 0
    for panel in panels:
        if not isinstance(panel, dict) or not panel.get("title"):
            errors.append(f"{rel}: every panel needs a title")
            continue
        ds = panel.get("datasource")
        if not isinstance(ds, dict) or ds.get("uid") != "mindpattern-prometheus":
            errors.append(
                f"{rel}: panel {panel['title']!r} must use the provisioned "
                "datasource uid mindpattern-prometheus"
            )
        for target in panel.get("targets") or []:
            expr = target.get("expr") if isinstance(target, dict) else None
            if not expr or not str(expr).strip():
                continue
            n_exprs += 1
            tokens = set(re.findall(r"[a-zA-Z_][a-zA-Z0-9_:]*", str(expr)))
            used = sorted(t for t in tokens if t.startswith("mindpattern_"))
            bad = sorted(t for t in used if t not in EXPORTED | TEXTFILE)
            if bad:
                errors.append(
                    f"{rel}: panel {panel['title']!r} references metric(s) "
                    f"metrics.py does NOT export: {', '.join(bad)}"
                )
    print(f"verify: dashboard {rel}: {len(panels)} panel(s), {n_exprs} grounded expression(s)")

for rel in [
    "docker-compose.yml",
    "grafana/provisioning/datasources/datasource.yml",
    "grafana/provisioning/dashboards/dashboards.yml",
    "alertmanager/alertmanager.example.yml",
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
