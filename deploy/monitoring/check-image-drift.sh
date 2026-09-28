#!/usr/bin/env bash
# Digest-drift gate for every pinned image in the compose contracts, the
# CI workflows, the Dockerfiles, and the shell scripts.
#
# WHY (2026-09-26 infra audit): dependabot covers pip/npm/actions/docker
# ecosystems but NOT compose-service images, so a pinned base can silently
# age while its tag moves on — exactly how the 2026-09-07 postgres pin
# ended up ~6 weeks stale behind a Trivy-failing rebuild. This script is
# the compose-side replacement: for every repo:tag@sha256 reference in the
# production compose + both overlays + the monitoring stack (re-audit
# 2026-09-27: also every repo:tag@sha256 image pin in .github/workflows/),
# it asks the registry what the TAG currently resolves to and compares.
#
# Independent audit 2026-09-27 — the gate used to be fail-open in three
# ways, all closed here:
#   1. a registry lookup failure (network blip, auth hiccup) was a note;
#      a DELETED tag was indistinguishable from a network blip because the
#      fetch was `curl || true`. Lookups now distinguish HTTP 404
#      (tag gone -> FAIL) from transport errors (one retry, then FAIL),
#      so the gate cannot be silenced by connectivity.
#   2. a pin whose digest was absent from the deploy/README inventory
#      only produced a note — forgetting the README row permanently
#      exempted the pin from the 90-day rule. Unknown age -> FAIL.
#   3. the scan covered compose `image:` lines and workflows only; the
#      stale superseded postgres digest in backend/scripts
#      /rehearse_restore.sh:120 was invisible to both the gate and the
#      inventory. Dockerfiles and shell scripts are now scanned too.
#
# FAILURE POLICY:
#   * tag no longer resolves at the registry (HTTP 404)    -> FAIL
#   * registry unreachable / auth failed after one retry   -> FAIL
#   * registry digest != pinned digest, pin age unknown    -> FAIL
#     (deploy/README.md inventory row missing or unparseable)
#   * registry digest != pinned digest, pin date >90d      -> FAIL
#   * registry digest != pinned digest, pin <=90d old      -> note only
#     (normal tag motion inside the refresh window)
#
# Runs in CI (monitoring-verify job: --selftest first, then the live
# registry walk) and standalone:
#   bash deploy/monitoring/check-image-drift.sh [--selftest]
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd -P)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd -P)
MAX_AGE_DAYS=90

status=0
note() { printf 'drift: %s\n' "$*"; }
fail() { printf 'drift: FAIL: %s\n' "$*" >&2; status=1; }

# Pin dates from the deploy README's inventory table rows like:
#   | `postgres:16-alpine@sha256:721873c3…` | where | 2026-09-26 (...) | ... |
# Scoped to TABLE rows (lines starting with "|") and parsed cell-wise: the
# PINNED ON cell is the first cell whose trimmed content begins with a
# date, so prose dates elsewhere in a row ("previous pin 2026-09-07...")
# can never mis-age the pin.
pin_age_days() {
  local digest="${1#sha256:}"   # caller passes the full sha256:<hex> form
  local prefix="${digest:0:12}"
  local row
  row=$(grep -F "$prefix" "$REPO_ROOT/deploy/README.md" 2>/dev/null \
    | grep '^[[:space:]]*|' | head -n 1 || true)
  if [ -z "$row" ]; then
    printf '%s\n' "unknown"
    return
  fi
  local pinned
  # Cell-wise: split the row on "|", trim each cell, take the FIRST cell
  # that starts with a calendar date, and take the FIRST date in it.
  pinned=$(printf '%s\n' "$row" | awk -F'|' '{
    for (i = 1; i <= NF; i++) {
      cell = $i
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", cell)
      if (cell ~ /^20[0-9][0-9]-[0-9][0-9]-[0-9][0-9]/) {
        if (match(cell, /20[0-9][0-9]-[0-9][0-9]-[0-9][0-9]/)) {
          print substr(cell, RSTART, RLENGTH)
          exit
        }
      }
    }
  }')
  if [ -z "$pinned" ]; then
    printf '%s\n' "unknown"
    return
  fi
  # BSD + GNU portable day arithmetic via epoch seconds / 86400.
  local now_epoch pinned_epoch
  now_epoch=$(date +%s)
  pinned_epoch=$(date -j -f '%Y-%m-%d' "$pinned" +%s 2>/dev/null \
    || date -d "$pinned" +%s 2>/dev/null || printf '%s\n' 0)
  if [ "$pinned_epoch" -eq 0 ]; then
    printf '%s\n' "unknown"
    return
  fi
  printf '%s\n' $(( (now_epoch - pinned_epoch) / 86400 ))
}

registry_digest() {
  # Resolve what repo:tag currently points at (manifest-list or manifest).
  # Prints exactly one of:
  #   sha256:<hex>   the tag resolves to this digest
  #   NOTFOUND       the registry ANSWERED: tag does not exist (404/405)
  #   LOOKUP-FAIL    transport/auth failure after the one retry
  local image="$1"  # repo:tag form
  local repo="${image%%:*}"
  local tag="${image##*:}"
  # Official images live under library/ on the registry: a bare "postgres"
  # scope queries a nonexistent repo and 401s.
  case "$repo" in
    */*) ;;
    *) repo="library/$repo" ;;
  esac
  local attempt hdr token code digest
  hdr=$(mktemp)
  trap 'rm -f "$hdr"' RETURN
  for attempt in 1 2; do
    token=$( (curl -fsS --max-time 20 \
      "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${repo}:pull" 2>/dev/null \
      || true) | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
    if [ -z "$token" ]; then
      if [ "$attempt" -lt 2 ]; then sleep 2; continue; fi
      printf '%s\n' "LOOKUP-FAIL"
      return
    fi
    : > "$hdr"
    code=$(curl -fsS --max-time 20 \
      -H "Authorization: Bearer $token" \
      -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json" \
      -H "Accept: application/vnd.oci.image.index.v1+json" \
      -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
      -H "Accept: application/vnd.oci.image.manifest.v1+json" \
      -D "$hdr" -o /dev/null -w '%{http_code}' \
      "https://registry-1.docker.io/v2/${repo}/manifests/${tag}" 2>/dev/null || true)
    digest=$(tr -d '\r' < "$hdr" | awk 'tolower($1)=="docker-content-digest:" {print $2}' | head -n 1)
    case "$code" in
      200|201)
        if [ -n "$digest" ]; then
          printf '%s\n' "$digest"
          return
        fi
        ;;
      404|405)
        # The registry ANSWERED and the tag does not exist: the stale-tag
        # case the gate exists to catch. Never treat this as a network
        # blip.
        printf '%s\n' "NOTFOUND"
        return
        ;;
    esac
    if [ "$attempt" -lt 2 ]; then sleep 2; continue; fi
  done
  printf '%s\n' "LOOKUP-FAIL"
}

# Collect every pinned ref into one file, deduplicated below, so a pin used
# in several places (e.g. the postgres digest in compose + workflows +
# restore scripts) is resolved against the registry exactly once.
collect_pins() {
  # $1 = output file
  local out="$1"
  local compose_file wf_file other_file
  : > "$out"
  for compose_file in "$REPO_ROOT/docker-compose.yml" \
                      "$SCRIPT_DIR/docker-compose.yml" \
                      "$REPO_ROOT/deploy/backup-offsite/docker-compose.yml"; do
    [ -f "$compose_file" ] || continue
    while IFS= read -r image_line; do
      image_ref="${image_line#*image: }"
      image_ref="${image_ref%%#*}"
      image_ref="${image_ref//[[:space:]]/}"
      # Skip required-env placeholders and unpinned refs (--production in
      # verify.sh already fails those; drift here needs a concrete pin).
      case "$image_ref" in
        *'$'*|*'@sha256:'*) ;;
        *) continue ;;
      esac
      case "$image_ref" in
        *'$'*) continue ;;
      esac
      printf '%s\n' "$image_ref" >> "$out"
    done < <(grep -E '^[[:space:]]*image:' "$compose_file" || true)
  done

  # Workflow-side pins (re-audit 2026-09-27): every repo:tag@sha256:<64hex>
  # image reference anywhere in .github/workflows/*.yml — service containers
  # (postgres), throwaway restore containers, and digest-pinned scanner
  # images (trivy, promtool's prom/prometheus). Same repo:tag@sha256 rule
  # as the compose files; tagless repo@sha256 release references are not
  # pins and do not match the pattern.
  for wf_file in "$REPO_ROOT"/.github/workflows/*.yml "$REPO_ROOT"/.github/workflows/*.yaml; do
    [ -f "$wf_file" ] || continue
    grep -Eo '[a-zA-Z0-9][a-zA-Z0-9._/-]*:[a-zA-Z0-9][a-zA-Z0-9._-]*@sha256:[a-f0-9]{64}' \
      "$wf_file" >> "$out" || true
  done

  # Independent audit 2026-09-27: Dockerfiles and shell scripts carry pins
  # too (FROM ... @sha256 in backend/Dockerfile and
  # deploy/backup-offsite/Dockerfile; POSTGRES_IMAGE="...@sha256:..." in
  # backend/scripts/rehearse_restore.sh) — the stale restore-script digest
  # lived precisely in this blind spot.
  while IFS= read -r -d '' other_file; do
    # Skip THIS script: its --selftest block embeds fixture pins that must
    # never enter the live scan (they exist only under the selftest's
    # throwaway repo root).
    [ "$other_file" = "$SCRIPT_DIR/check-image-drift.sh" ] && continue
    grep -Eo '([a-zA-Z0-9][a-zA-Z0-9._/-]*:[a-zA-Z0-9][a-zA-Z0-9._-]*)?@sha256:[a-f0-9]{64}' \
      "$other_file" | sed 's/^@//' >> "$out" || true
  done < <(find "$REPO_ROOT/backend/Dockerfile" "$REPO_ROOT/deploy/backup-offsite/Dockerfile" \
    "$REPO_ROOT/deploy" "$REPO_ROOT/backend/scripts" "$REPO_ROOT/scripts" "$REPO_ROOT/backup" \
    -type f \( -name '*.sh' -o -name 'Dockerfile' \) -print0 2>/dev/null)

  sort -u -o "$out" "$out"
}

# One pin's comparison; factored so --selftest can run the exact same
# logic against a stubbed registry_digest.
check_pin() {
  local image_ref="$1"
  repo_tag="${image_ref%@sha256:*}"
  pinned="${image_ref##*@sha256:}"
  current=$(registry_digest "$repo_tag")
  short="${repo_tag}@sha256:${pinned:0:12}"
  case "$current" in
    LOOKUP-FAIL|"")
      # DRIFT_ALLOW_NETWORK_FAIL=1 is the CONSCIOUS escape hatch for an
      # operator with no registry egress — the gate never fail-opens
      # silently (independent audit 2026-09-27: the old code silently
      # treated every lookup failure as a note).
      if [ "${DRIFT_ALLOW_NETWORK_FAIL:-0}" = "1" ]; then
        note "$short: registry unreachable (network fail allowed via DRIFT_ALLOW_NETWORK_FAIL=1) — skipped"
      else
        fail "$short: registry unreachable or auth failed after retry — the gate fails loud (set DRIFT_ALLOW_NETWORK_FAIL=1 to consciously skip)"
      fi
      return
      ;;
    NOTFOUND)
      fail "$short: tag no longer resolves at the registry (404) — stale pin, re-pin deliberately"
      return
      ;;
  esac
  if [ "$current" != "sha256:$pinned" ]; then
    age=$(pin_age_days "sha256:$pinned")
    if [ "$age" = "unknown" ]; then
      fail "$short: tag moved (registry ${current#sha256:}) AND the pin has no deploy/README.md inventory row — add the row, then re-pin deliberately"
    elif [ "$age" -lt 0 ]; then
      fail "$short: inventory date is in the future — fix the deploy/README.md row (bad data, not a window)"
    elif [ "$age" -gt "$MAX_AGE_DAYS" ]; then
      fail "$short: tag moved AND pin is ${age}d old (>${MAX_AGE_DAYS}d) — re-pin deliberately (deploy/README.md, 'Digest pinning')"
    else
      note "$short: tag moved (registry ${current#sha256:}); pin is ${age}d old (within the ${MAX_AGE_DAYS}d window)"
    fi
  else
    note "$short: current"
  fi
}

if [ "${1:-}" = "--selftest" ]; then
  # Prove the gate's failure modes actually fail, without touching the
  # network. Runs the REAL pin-collection + comparison logic against a
  # stubbed registry_digest and a fixture repo skeleton (temp REPO_ROOT
  # with an inventory README, a compose file, a Dockerfile, and a .sh).
  selftest_root=$(mktemp -d)
  trap 'rm -rf "$selftest_root"' EXIT
  # Yesterday, portably (BSD/GNU): the fresh-pin fixture must be inside
  # the 90d window no matter when the selftest runs.
  selftest_yesterday=$(date -j -v-1d +%Y-%m-%d 2>/dev/null || date -d '1 day ago' +%Y-%m-%d)
  # One year OUT (portably): the future-dated-row fixture must postdate
  # the run no matter when the selftest runs (and must stay inside the
  # README parser's 20xx date grammar — 2100-style years do not match it).
  selftest_next_year=$(date -j -v+1y +%Y-%m-%d 2>/dev/null || date -d '+1 year' +%Y-%m-%d)
  mkdir -p "$selftest_root/deploy"
  cat > "$selftest_root/deploy/README.md" <<'EOF'
# fixture inventory
| `stale:1@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` | fixture | 2020-01-01 | fixture |
| `fresh:1@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb` | fixture | FRESH_DATE_PLACEHOLDER | fixture |
EOF
  cat > "$selftest_root/docker-compose.yml" <<'EOF'
services:
  stale:
    image: stale:1@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  fresh:
    image: fresh:1@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  unknown:
    image: unknown:1@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
EOF
  # Quoted heredocs above can't expand the date: patch the fresh row here
  # so the fresh-pin fixture sits inside the 90d window whenever this runs.
  sed -i '' "s/FRESH_DATE_PLACEHOLDER/${selftest_yesterday}/" "$selftest_root/deploy/README.md" 2>/dev/null \
    || sed -i "s/FRESH_DATE_PLACEHOLDER/${selftest_yesterday}/" "$selftest_root/deploy/README.md"
  # Under deploy/ on purpose: the Dockerfile scan walks REPO_ROOT/deploy.
  cat > "$selftest_root/deploy/Dockerfile" <<'EOF'
FROM gone:1@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
EOF
  # 2026-09-28 audit L-5: the future-dated-inventory fixture — a README
  # row whose PINNED ON date is in the future is bad data, not a window,
  # and must fail loudly. Quoted heredocs can't expand the date: patched
  # below like the fresh-row fixture.
  cat >> "$selftest_root/docker-compose.yml" <<'EOF'
  future:
    image: future:1@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
EOF
  cat >> "$selftest_root/deploy/README.md" <<'EOF'
| `future:1@sha256:ffffffffffffffffffffffffffffffff` | fixture | FUTURE_DATE_PLACEHOLDER | fixture |
EOF
  sed -i '' "s/FUTURE_DATE_PLACEHOLDER/${selftest_next_year}/" "$selftest_root/deploy/README.md" 2>/dev/null \
    || sed -i "s/FUTURE_DATE_PLACEHOLDER/${selftest_next_year}/" "$selftest_root/deploy/README.md"
  # The fixture repo IS the script's REPO_ROOT for this run: re-exec the
  # collection + comparison against the stub by sourcing this same file
  # with REPO_ROOT pointed there.
  REPO_ROOT="$selftest_root" SCRIPT_DIR="$selftest_root/deploy"
  registry_digest() {
    case "$1" in
      stale:1)  printf '%s\n' "sha256:1111111111111111111111111111111111111111111111111111111111111111" ;; # moved + old pin
      fresh:1)  printf '%s\n' "sha256:2222222222222222222222222222222222222222222222222222222222222222" ;; # moved + fresh pin
      unknown:1) printf '%s\n' "sha256:3333333333333333333333333333333333333333333333333333333333333333" ;; # moved + no inventory row
      gone:1)   printf '%s\n' "NOTFOUND" ;;                                                        # deleted tag
      netfail:1) printf '%s\n' "LOOKUP-FAIL" ;;                                                   # transport down
      future:1) printf '%s\n' "sha256:4444444444444444444444444444444444444444444444444444444444444444" ;; # moved + future-dated row
    esac
  }
  # 2026-09-28 audit L-5: prove EVERY failure mode fires INDIVIDUALLY.
  # The old selftest asserted only "at least one mode failed" — a
  # regression that silenced any single mode kept the selftest green
  # while claiming all modes were proven. Each case resets status and
  # asserts the expected outcome for that mode alone.
  selftest_case() {
    # selftest_case <expect: fail|pass> <description> <image_ref...>
    local expect="$1"; shift
    local desc="$1"; shift
    status=0
    check_pin "$@"
    if [ "$expect" = "fail" ] && [ "$status" -eq 0 ]; then
      printf 'drift: SELFTEST FAILED — mode did NOT fail: %s\n' "$desc" >&2
      exit 1
    fi
    if [ "$expect" = "pass" ] && [ "$status" -ne 0 ]; then
      printf 'drift: SELFTEST FAILED — mode wrongly fails: %s\n' "$desc" >&2
      exit 1
    fi
  }
  selftest_case fail "moved + stale pin (>90d)" \
    "stale:1@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  selftest_case pass "moved + fresh pin (<=90d) is a note, not a failure" \
    "fresh:1@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  selftest_case fail "moved + missing inventory row" \
    "unknown:1@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
  selftest_case fail "deleted tag (registry 404)" \
    "gone:1@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
  selftest_case fail "transport failure" \
    "netfail:1@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
  selftest_case fail "future-dated inventory row" \
    "future:1@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  # Collection must also see the fixture files: the Dockerfile and shell
  # scan is part of what the selftest exercises.
  pins_file=$(mktemp)
  collect_pins "$pins_file"
  if ! grep -q '^gone:1@' "$pins_file"; then
    printf 'drift: SELFTEST FAILED — Dockerfile/shell scan collected nothing\n' >&2
    exit 1
  fi
  rm -f "$pins_file"
  printf 'drift: selftest OK — every failure mode proven individually: moved/stale, missing-inventory, deleted-tag, transport, future-dated row\n'
  exit 0
fi

# 2026-09-28 audit L-5: the live walk must never pass on an EMPTY or
# shrunken pin set (a glob or find regression collecting zero pins would
# otherwise print ALL CHECKS PASSED over nothing). The expected count
# lives with the pin inventory; bump it WITH the pin, in the same commit.
MIN_PINS_EXPECTED=9

pins_file=$(mktemp)
trap 'rm -f "$pins_file"' EXIT
collect_pins "$pins_file"
pin_count=$(grep -c . "$pins_file" || true)
if [ "$pin_count" -lt "$MIN_PINS_EXPECTED" ]; then
  fail "collected ${pin_count} pins, expected at least ${MIN_PINS_EXPECTED} — the scan scope regressed (a whole pin class went invisible)"
fi

while IFS= read -r image_ref; do
  [ -n "$image_ref" ] || continue
  check_pin "$image_ref"
done < "$pins_file"

if [ "$status" -eq 0 ]; then
  note "ALL CHECKS PASSED"
else
  note "FAILURES ABOVE — re-pin the flagged images (update tag AND digest together)"
fi
exit "$status"
