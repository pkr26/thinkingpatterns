#!/usr/bin/env bash
# Mutation-test runner wrapper.
#
# mutmut 2.4.x treats "tests failed" as pytest exiting exactly 1. Collection
# errors (import-time crashes — common when a mutant breaks a module) exit 2
# and were silently classified as SURVIVED. This wrapper normalizes every
# nonzero exit to 1 so any test failure counts as a kill.
set -u
python -m pytest -x -q -m 'not slow' tests/
status=$?
if [ "$status" -eq 0 ]; then
  exit 0
fi
exit 1
