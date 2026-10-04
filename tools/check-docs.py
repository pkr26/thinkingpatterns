#!/usr/bin/env python3
"""Check maintained documentation links and the backend error-code reference.

Run from any directory with Python 3.12+. Historical reports retain snapshot
paths, so only their indexes participate in the link check.
"""

from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
API_REFERENCE = Path("docs/api.md")
LINK = re.compile(r"\[[^\]\n]+\]\((?:<([^>]+)>|([^\s)]+))(?:\s+\"[^\"]*\")?\)")


def backend_error_codes(source: Path) -> set[str]:
    """Collect literal response codes and HTTP status defaults without importing the app."""
    codes: set[str] = set()
    defaults_found = False
    for path in sorted(source.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            values: list[ast.AST | None] = []
            if isinstance(node, ast.keyword) and node.arg == "code":
                values.append(node.value)
            elif isinstance(node, ast.Dict):
                values.extend(
                    value
                    for key, value in zip(node.keys, node.values)
                    if isinstance(key, ast.Constant) and key.value == "code"
                )
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                if any(
                    isinstance(target, ast.Name) and target.id == "DEFAULT_ERROR_CODES"
                    for target in targets
                ):
                    if not isinstance(node.value, ast.Dict):
                        raise ValueError(
                            "DEFAULT_ERROR_CODES must be a literal mapping"
                        )
                    defaults_found = True
                    values.extend(node.value.values)
            codes.update(
                value.value
                for value in values
                if isinstance(value, ast.Constant)
                and isinstance(value.value, str)
                and re.fullmatch(r"[a-z0-9_]+", value.value)
            )
    if not defaults_found:
        raise ValueError("DEFAULT_ERROR_CODES was not found in the backend")
    return codes


def broken_links(document: Path, root: Path) -> list[str]:
    """Validate local inline Markdown link destinations; leave remote URLs untouched."""
    content = document.read_text(encoding="utf-8")
    # Code samples are illustrative text, not rendered links.
    content = re.sub(r"(?ms)^(`{3,}|~{3,})[^\n]*\n.*?^\1\s*$", "", content)
    errors = []
    for match in LINK.finditer(content):
        target = match.group(1) or match.group(2)
        url = urlsplit(target)
        if url.scheme or url.netloc or not url.path:
            continue
        destination = (document.parent / unquote(url.path)).resolve()
        if not destination.is_relative_to(root.resolve()) or not destination.exists():
            errors.append(f"{document.relative_to(root)}: missing link target {target}")
    return errors


def maintained_documents(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        capture_output=True,
        check=True,
    )
    documents = set()
    for name in result.stdout.decode().split("\0"):
        path = Path(name)
        if path.suffix != ".md" or not (root / path).is_file():
            continue
        if name.startswith(("reports/", "docs/archive/", "redteam/mutation_campaign_")):
            if name not in {"reports/README.md", "docs/archive/README.md"}:
                continue
        if path.name.startswith("GUI_DRILL_REPORT_"):
            continue
        documents.add(root / path)
    return sorted(documents)


def main() -> int:
    documents = maintained_documents(ROOT)
    errors = [error for document in documents for error in broken_links(document, ROOT)]
    codes = backend_error_codes(ROOT / "backend/app")
    reference = (ROOT / API_REFERENCE).read_text(encoding="utf-8")
    missing = sorted(code for code in codes if f"`{code}`" not in reference)
    if missing:
        errors.append(
            f"{API_REFERENCE}: undocumented error codes: {', '.join(missing)}"
        )
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(
        f"Documentation checks passed: {len(documents)} files, {len(codes)} API error codes."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
