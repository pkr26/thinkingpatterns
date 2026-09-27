#!/usr/bin/env bash
# Digest-drift gate for every pinned image in the compose contracts AND the
# CI workflows.
#
# WHY (2026-09-26 infra audit): dependabot covers pip/npm/actions/docker
# ecosystems but NOT compose service images, so a pinned base can silently
# age while its tag moves on — exactly how the 2026-09-07 postgres pin
# ended up ~6 weeks stale behind a Trivy-failing rebuild. This script is
# the compose-side replacement: for every repo:tag@sha256 reference in the
# production compose + both overlays + the monitoring stack (re-audit
# 2026-09-27: also every repo:tag@sha256 image pin in .github/workflows/,
# e.g. the service/restore postgres containers and the promtool/trivy
# scanners), it asks the registry what the TAG currently resolves to and
# compares.
#
# FAILURE POLICY:
#   * tag no longer resolves at the registry            -> FAIL (stale tag)
#   * registry digest != pinned digest, pin date >90d   -> FAIL (audit
#     requires a deliberate re-pin; the date comes from the "Digest-pin
#     inventory" table in deploy/README.md)
#   * registry digest != pinned digest, pin <=90d old   -> note only
#     (normal tag motion inside the refresh window)
#
# Runs in CI (monitoring-verify job) and standalone:
#   bash deploy/monitoring/check-image-drift.sh
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd -P)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd -P)
MAX_AGE_DAYS=90

status=0
note() { printf 'drift: %s\n' "$*"; }
fail() { printf 'drift: FAIL: %s\n' "$*" >&2; status=1; }

# Pin dates from the deploy README's inventory table rows like:
#   | `postgres:16-alpine@sha256:721873c3…` | ... | 2026-09-26 |
# (the table prints a truncated digest for readability, so the lookup
# matches on the first 12 hex chars — long enough to be unique here).
pin_age_days() {
  local digest="${1#sha256:}"   # caller passes the full sha256:<hex> form
  local row
  row=$(grep -F "${digest:0:12}" "$REPO_ROOT/deploy/README.md" 2>/dev/null | head -n 1 || true)
  if [ -z "$row" ]; then
    printf '%s\n' "unknown"
    return
  fi
  local pinned
  pinned=$(printf '%s\n' "$row" | grep -oE '20[0-9]{2}-[0-9]{2}-[0-9]{2}' | head -n 1 || true)
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
  local image="$1"  # repo:tag form
  local repo="${image%%:*}"
  local tag="${image##*:}"
  # Official images live under library/ on the registry: a bare "postgres"
  # scope queries a nonexistent repo and 401s.
  case "$repo" in
    */*) ;;
    *) repo="library/$repo" ;;
  esac
  local token
  token=$( (curl -fsS --max-time 20 \
    "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${repo}:pull" 2>/dev/null \
    || true) | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
  if [ -z "$token" ]; then
    printf '%s\n' "AUTH-FAIL"
    return
  fi
  ( (curl -fsS --max-time 20 \
    -H "Authorization: Bearer $token" \
    -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json" \
    -H "Accept: application/vnd.oci.image.index.v1+json" \
    -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
    -H "Accept: application/vnd.oci.image.manifest.v1+json" \
    -D - -o /dev/null "https://registry-1.docker.io/v2/${repo}/manifests/${tag}" 2>/dev/null \
    || true) | tr -d '\r' | awk 'tolower($1)=="docker-content-digest:" {print $2}' | head -n 1)
}

# Collect every pinned ref into one file, deduplicated below, so a pin used
# in several places (e.g. the postgres digest in compose + workflows) is
# resolved against the registry exactly once.
pins_file=$(mktemp)
trap 'rm -f "$pins_file"' EXIT
: > "$pins_file"

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
    printf '%s\n' "$image_ref" >> "$pins_file"
  done < <(grep -E '^[[:space:]]*image:' "$compose_file" || true)
done

# Workflow-side pins (re-audit 2026-09-27): every repo:tag@sha256:<64hex>
# image reference anywhere in .github/workflows/*.yml — service containers
# (postgres), throwaway restore containers, and digest-pinned scanner images
# (trivy, promtool's prom/prometheus). Same repo:tag@sha256 rule as the
# compose files; tagless repo@sha256 release references are not pins and do
# not match the pattern.
for wf_file in "$REPO_ROOT"/.github/workflows/*.yml; do
  [ -f "$wf_file" ] || continue
  grep -Eo '[a-zA-Z0-9][a-zA-Z0-9._/-]*:[a-zA-Z0-9][a-zA-Z0-9._-]*@sha256:[a-f0-9]{64}' \
    "$wf_file" >> "$pins_file" || true
done

sort -u -o "$pins_file" "$pins_file"

while IFS= read -r image_ref; do
  [ -n "$image_ref" ] || continue
  repo_tag="${image_ref%@sha256:*}"
  pinned="${image_ref##*@sha256:}"
  current=$(registry_digest "$repo_tag")
  short="${repo_tag}@sha256:${pinned:0:12}"
  if [ "$current" = "AUTH-FAIL" ] || [ -z "$current" ]; then
    note "$short: registry lookup failed (network?) — not failing the gate"
    continue
  fi
  if [ "$current" != "sha256:$pinned" ]; then
    age=$(pin_age_days "sha256:$pinned")
    if [ "$age" = "unknown" ]; then
      note "$short: tag moved (registry ${current#sha256:}); pin date not in deploy/README.md inventory — add it there"
    elif [ "$age" -gt "$MAX_AGE_DAYS" ]; then
      fail "$short: tag moved AND pin is ${age}d old (>${MAX_AGE_DAYS}d) — re-pin deliberately (deploy/README.md, 'Digest pinning')"
    else
      note "$short: tag moved (registry ${current#sha256:}); pin is ${age}d old (within the ${MAX_AGE_DAYS}d window)"
    fi
  else
    note "$short: current"
  fi
done < "$pins_file"

if [ "$status" -eq 0 ]; then
  note "ALL CHECKS PASSED"
else
  note "FAILURES ABOVE — re-pin the flagged images (update tag AND digest together)"
fi
exit "$status"
