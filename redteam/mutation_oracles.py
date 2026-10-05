"""Reject unavailable/broken test runners before assigning mutation credit."""

from __future__ import annotations
import re


def oracle_setup_error(kind: str, returncode: int, output: str) -> str | None:
    # CI/terminal color settings must not change a runner's verdict.
    output = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output)
    if kind == "pytest":
        if returncode not in (0, 1):
            return f"pytest exited {returncode} (oracle unavailable, not a kill)"
        if "no tests ran" in output or "collected 0 items" in output:
            return "pytest collected no tests"
        # Pytest's short-summary ERROR names a test node. Captured application
        # logging also starts with ERROR, including when a real regression
        # makes an HTTP assertion fail; that is not a fixture/setup verdict.
        if re.search(r"^ERROR\s+\S+\.py(?:::|\s+-)", output, re.M):
            return "pytest emitted an oracle error verdict"
        if returncode == 1 and not re.search(r"^FAILED\s+\S+", output, re.M):
            return "pytest failed without a failing test verdict"
        if returncode == 0 and not (
            re.search(r"\b[1-9]\d* passed\b", output)
            # Repository addopts plus the harness's -q can omit the summary.
            # A progress dot is a passed test; skipped/xfail-only runs lack it.
            or re.search(r"^[.sFxXE ]*\.[.sFxXE ]*\s+\[\s*\d+%\]", output, re.M)
        ):
            return "pytest emitted no passing test verdict"
    elif kind == "vitest":
        if re.search(r"Unhandled (?:Error|Rejection)|Unhandled Errors", output):
            return "vitest emitted an unhandled oracle error"
        if re.search(
            r"No test files found|Tests\s+no tests|Failed to (?:resolve|load)|Transform failed|Parse failure|Cannot find (?:package|module)|ERR_MODULE_NOT_FOUND",
            output,
            re.I,
        ):
            return "vitest could not load or collect its oracle"
        if returncode != 0 and not re.search(
            r"(?:Tests\s+.*\b[1-9]\d* failed|FAIL\s+\S+.* > |×\s+\S)", output
        ):
            return "vitest failed without a failing test verdict"
        if returncode == 0 and not re.search(r"Tests\s+[^\n]*\b[1-9]\d* passed\b", output):
            return "vitest emitted no passing test verdict"
    elif kind == "probe":
        if returncode != 0 and not re.search(r"^\s*FAIL\b", output, re.M):
            return "probe exited without a behavioral FAIL verdict"
        if returncode == 0 and not re.search(r"^\s*PASS\b", output, re.M):
            return "probe emitted no behavioral PASS verdict"
    elif kind == "redteam":
        lines = [line for line in output.splitlines() if line.startswith("AUDIT|")]
        if not lines:
            return "redteam emitted no audit verdicts"
        if any("|ERROR|" in line for line in lines):
            return "redteam emitted an ERROR verdict (not a finding)"
        if returncode != 0 and not any("|FINDING|" in line for line in lines):
            return f"redteam exited {returncode} without a finding"
    else:
        return f"unknown oracle kind: {kind}"
    return None


def redteam_baseline_error(spec: dict, output: str) -> str | None:
    """Require an observed blocked control before accepting a later finding."""
    selected = [
        line
        for line in output.splitlines()
        if line.startswith("AUDIT|") and any(value in line for value in spec["oracle"])
    ]
    if not selected:
        return "redteam baseline emitted no matching control verdict"
    if any("|FINDING|" in line or "|ERROR|" in line or "|PARTIAL|" in line for line in selected):
        return "redteam baseline control was failing, incomplete, or unavailable"
    if not any("|BLOCKED|" in line for line in selected):
        return "redteam baseline did not establish that the control blocked the attack"
    return None
