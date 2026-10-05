"""Read-only validation of semantic mutation anchors and their test selectors.

This checks applicability and oracle structure, not whether a mutation is killed.
It uses only the Python standard library and does not import application code.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path


class ApplicabilityError(ValueError):
    pass


def inside(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise ApplicabilityError(f"expected a relative repository path: {relative!r}")
    path = root / relative
    if not path.resolve().is_relative_to(root.resolve()):
        raise ApplicabilityError(f"path escapes repository: {relative!r}")
    return path


def _selector(root: Path, cwd: str, value: str) -> None:
    filename, *names = value.split("::")
    path = inside(root, str(Path(cwd) / filename))
    if not path.is_file():
        raise ApplicabilityError(f"oracle file is missing: {cwd}/{filename}")
    if not names:
        return
    if path.suffix != ".py":
        raise ApplicabilityError(f"unsupported node selector: {value}")
    body = ast.parse(path.read_text(), filename=str(path)).body
    for name in names:
        # Parametrized node IDs refer to the underlying function definition.
        symbol = name.split("[", 1)[0]
        found = next(
            (
                node
                for node in body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and node.name == symbol
            ),
            None,
        )
        if found is None:
            raise ApplicabilityError(f"oracle selector is missing: {value}")
        body = found.body


def validate_oracle(root: Path, spec: dict) -> None:
    if not isinstance(spec, dict):
        raise ApplicabilityError("oracle specification must be an object")
    cwd = spec.get("cwd")
    if not inside(root, cwd).is_dir():
        raise ApplicabilityError(f"oracle working directory is missing: {cwd}")
    command = spec.get("cmd")
    if (
        not isinstance(command, list)
        or not command
        or not all(isinstance(arg, str) and arg for arg in command)
    ):
        raise ApplicabilityError("oracle command must be a nonempty string array")
    timeout = spec.get("timeout")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        raise ApplicabilityError("oracle timeout must be positive")
    kind = spec.get("kind")
    if kind == "pytest":
        if "-m" not in command or "pytest" not in command:
            raise ApplicabilityError("pytest oracle must invoke pytest")
        targets = [
            arg
            for arg in command[command.index("pytest") + 1 :]
            if ".py" in arg and not arg.startswith("-")
        ]
        if not targets:
            raise ApplicabilityError("pytest oracle must name at least one test file")
        for target in targets:
            _selector(root, cwd, target)
    elif kind == "vitest":
        if "vitest" not in command or "run" not in command:
            raise ApplicabilityError("vitest oracle must invoke vitest run")
        targets = [arg for arg in command if arg.startswith("tests/")]
        if not targets:
            raise ApplicabilityError("vitest oracle must name at least one test file")
        for target in targets:
            _selector(root, cwd, target)
    elif kind in ("probe", "redteam"):
        if len(command) < 2 or not command[1].endswith(".py"):
            raise ApplicabilityError(f"{kind} oracle must name its Python script")
        _selector(root, cwd, command[1])
        if kind == "redteam":
            wanted = spec.get("oracle")
            if (
                not isinstance(wanted, list)
                or not wanted
                or not all(isinstance(value, str) and value for value in wanted)
            ):
                raise ApplicabilityError("redteam oracle must name its expected audit selectors")
    else:
        raise ApplicabilityError(f"unknown oracle kind: {kind!r}")


def validate_mutant(root: Path, mutant: dict) -> dict:
    if not isinstance(mutant, dict):
        raise ApplicabilityError("mutant must be an object")
    identifier = mutant.get("id")
    if not isinstance(identifier, str) or not identifier:
        raise ApplicabilityError("mutant ID is missing")
    target = inside(root, mutant.get("file"))
    if not target.is_file():
        raise ApplicabilityError(f"target file is missing: {mutant.get('file')}")
    find, replace = mutant.get("find"), mutant.get("replace")
    if not isinstance(find, str) or not find or not isinstance(replace, str) or find == replace:
        raise ApplicabilityError("mutation must replace a nonempty anchor with different text")
    count = mutant.get("count", 1)
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        raise ApplicabilityError("expected anchor count must be a positive integer")
    original = target.read_text()
    actual = original.count(find)
    if actual != count:
        raise ApplicabilityError(f"find-string matched {actual} times, expected exactly {count}")
    mutated = original.replace(find, replace, count)
    if target.suffix == ".py":
        try:
            ast.parse(mutated, filename=str(target))
        except SyntaxError as error:
            raise ApplicabilityError(f"mutation produces invalid Python: {error}") from error
    elif target.suffix == ".json":
        try:
            json.loads(mutated)
        except json.JSONDecodeError as error:
            raise ApplicabilityError(f"mutation produces invalid JSON: {error}") from error
    specs = mutant.get("tests")
    specs = specs if isinstance(specs, list) else [specs]
    if not specs:
        raise ApplicabilityError("mutation has no oracle")
    for spec in specs:
        validate_oracle(root, spec)
    return {
        "id": identifier,
        "file": mutant["file"],
        "matches": actual,
        "expected": count,
        "oracles": len(specs),
        "status": "APPLICABLE",
    }


def inventory(root: Path, mutants: list[dict]) -> list[dict]:
    if not mutants:
        raise ApplicabilityError("mutation inventory is empty")
    rows, seen = [], set()
    for mutant in mutants:
        identifier = mutant.get("id") if isinstance(mutant, dict) else None
        try:
            if not isinstance(identifier, str) or not identifier:
                raise ApplicabilityError("mutant ID must be a nonempty string")
            if identifier in seen:
                raise ApplicabilityError(f"duplicate mutant ID: {identifier}")
            seen.add(identifier)
            rows.append(validate_mutant(root, mutant))
        except (ApplicabilityError, OSError, UnicodeError, SyntaxError) as error:
            rows.append(
                {
                    "id": identifier,
                    "file": mutant.get("file") if isinstance(mutant, dict) else None,
                    "status": "SETUP-ERROR",
                    "detail": str(error),
                }
            )
    return rows
