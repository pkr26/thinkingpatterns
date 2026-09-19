#!/usr/bin/env bash
# Validate the public release-image fragment without sourcing it.  It is
# intentionally limited to the two image variables so an operator cannot
# accidentally treat a downloaded release asset as executable shell input.
set -euo pipefail

usage() {
  echo "usage: $0 path/to/mindpattern-release-vX.Y.Z.env" >&2
  exit 64
}

[ "$#" -eq 1 ] || usage
env_file=$1
[ -f "$env_file" ] || {
  echo "release env file does not exist: $env_file" >&2
  exit 66
}

api_image=""
backup_image=""
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in
    ''|'#'*)
      ;;
    MINDPATTERN_API_IMAGE=*)
      [ -z "$api_image" ] || {
        echo "release env repeats MINDPATTERN_API_IMAGE" >&2
        exit 65
      }
      api_image=${line#MINDPATTERN_API_IMAGE=}
      ;;
    MINDPATTERN_BACKUP_IMAGE=*)
      [ -z "$backup_image" ] || {
        echo "release env repeats MINDPATTERN_BACKUP_IMAGE" >&2
        exit 65
      }
      backup_image=${line#MINDPATTERN_BACKUP_IMAGE=}
      ;;
    *)
      echo "release env contains an unexpected line; it may only carry image references" >&2
      exit 65
      ;;
  esac
done < "$env_file"

for name in api_image backup_image; do
  image_ref=${!name}
  # The repository path is matched per segment — `name` runs of
  # `[._-]-joined` alphanumerics — instead of a single `[a-z0-9._/-]*`
  # run: a run also admits `..`/`.`/empty path segments, which a registry
  # resolves differently and which no legitimate release image uses.
  # Segments must start and end with an alphanumeric.
  if [[ ! "$image_ref" =~ ^ghcr\.io/[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*@sha256:[a-f0-9]{64}$ ]]; then
    echo "$name must be a lowercase ghcr.io image manifest digest (…@sha256:<64 lowercase hex>, without dot-path segments)" >&2
    exit 65
  fi
done

printf 'validated immutable release image references:\n  API: %s\n  backup: %s\n' \
  "$api_image" "$backup_image"
