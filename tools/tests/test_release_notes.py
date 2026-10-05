"""The real release extractor must reject ambiguous or unrelated release notes."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools/extract_release_notes.py"
spec = importlib.util.spec_from_file_location("release_notes", SCRIPT)
notes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(notes)


class ReleaseNotesTests(unittest.TestCase):
    def test_exact_section_stops_before_next_release(self):
        text = "# Changes\n## [1.0.0] - 2026-10-04\nRIGHT\n### Added\nDetail\n## [0.9.0]\nOLD\n"
        self.assertEqual(
            notes.extract_release_notes(text, "1.0.0"), "RIGHT\n### Added\nDetail\n"
        )

    def test_bare_and_prerelease_sections_are_literal(self):
        self.assertEqual(
            notes.extract_release_notes("## 1.0.0-rc.1 - today\nRIGHT", "1.0.0-rc.1"),
            "RIGHT\n",
        )
        self.assertEqual(
            notes.extract_release_notes("## [1.0.0]\nRIGHT", "1.0.0"), "RIGHT\n"
        )

    def test_absent_prefix_malformed_duplicate_and_empty_sections_fail(self):
        cases = [
            "## [9.9.9]\nUNRELATED",
            "## [1.0.01]\nPREFIX",
            "## [1x0x0]\nREGEX",
            "## [1.0.0]junk\nMALFORMED",
            "## [1.0.0]\nONE\n## 1.0.0\nTWO",
            "## [1.0.0]\n \n## [0.9.0]\nOLD",
        ]
        for text in cases:
            with self.subTest(text=text), self.assertRaises(ValueError):
                notes.extract_release_notes(text, "1.0.0")

    def test_version_cannot_inject_a_regular_expression_or_heading(self):
        for version in ["1.0.*", "1.0.0\n## 9.9.9", "1x0x0", "1.0.0/../../"]:
            with self.subTest(version=version), self.assertRaises(ValueError):
                notes.extract_release_notes("## [1.0.0]\nRIGHT", version)

    def test_cli_fails_without_emitting_unrelated_notes(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "CHANGELOG.md"
            path.write_text("## [9.9.9]\nWRONG\n")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "1.0.0", str(path)],
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("found 0", result.stderr)

    def test_both_workflow_paths_use_the_same_extractor(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertEqual(workflow.count("python3 tools/extract_release_notes.py"), 2)
        self.assertNotIn("awk -v ver=", workflow)


if __name__ == "__main__":
    unittest.main()
