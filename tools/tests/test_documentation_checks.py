"""Regression coverage for documentation gates used by local checks and CI."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "check-docs.py"
spec = importlib.util.spec_from_file_location("documentation_checks", SCRIPT)
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


class DocumentationChecksTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)

    def test_codes_cover_response_constructions_and_status_defaults(self):
        (self.root / "api.py").write_text(
            'DEFAULT_ERROR_CODES: dict[int, str] = {400: "bad_request"}\n'
            'raise ApiError(code="version_conflict")\n'
            "envelope = {'code': 'rate_limited'}\n"
            'description = "code=not_a_response"\n'
        )
        self.assertEqual(
            checks.backend_error_codes(self.root),
            {"bad_request", "version_conflict", "rate_limited"},
        )

    def test_missing_default_map_cannot_silently_weaken_coverage(self):
        (self.root / "api.py").write_text('raise ApiError(code="not_found")\n')
        with self.assertRaisesRegex(ValueError, "DEFAULT_ERROR_CODES"):
            checks.backend_error_codes(self.root)

    def test_links_resolve_relative_to_document_and_fail_after_target_is_removed(self):
        folder = self.root / "docs"
        folder.mkdir()
        target = self.root / "target file.md"
        target.write_text("# Target\n")
        document = folder / "guide.md"
        document.write_text(
            "[Target](../target%20file.md#target)\n"
            "[Remote](https://example.com/not-fetched)\n"
            "[Section](#local)\n"
            "```md\n[Illustration](not-a-real-file.md)\n```\n"
        )
        self.assertEqual(checks.broken_links(document, self.root), [])
        target.unlink()
        self.assertEqual(len(checks.broken_links(document, self.root)), 1)

    def test_links_cannot_depend_on_files_outside_the_repository(self):
        document = self.root / "guide.md"
        document.write_text("[Host directory](../)\n")
        self.assertEqual(len(checks.broken_links(document, self.root)), 1)


if __name__ == "__main__":
    unittest.main()
