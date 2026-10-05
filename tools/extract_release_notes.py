"""Extract exactly one release section, failing closed on absent/duplicate notes."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?")
HEADING = re.compile(r"^##\s+(?:\[([^\]\s]+)\]|([^\s]+))(?:\s+-\s+.*)?\s*$")


def extract_release_notes(changelog: str, version: str) -> str:
    if not VERSION.fullmatch(version):
        raise ValueError("invalid release version")
    sections: list[list[str]] = []
    current: list[str] | None = None
    for line in changelog.splitlines():
        if re.match(r"^##(?:\s|$)", line):
            current = None
            heading = HEADING.fullmatch(line)
            if heading and (heading.group(1) or heading.group(2)) == version:
                current = []
                sections.append(current)
        elif current is not None:
            current.append(line)
    if len(sections) != 1:
        raise ValueError(
            f"expected one CHANGELOG section for {version}; found {len(sections)}"
        )
    notes = "\n".join(sections[0]).strip()
    if not notes:
        raise ValueError(f"empty CHANGELOG section for {version}")
    return notes + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    parser.add_argument("changelog", type=Path, nargs="?", default=Path("CHANGELOG.md"))
    args = parser.parse_args()
    try:
        notes = extract_release_notes(
            args.changelog.read_text(encoding="utf-8"), args.version
        )
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    sys.stdout.write(notes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
