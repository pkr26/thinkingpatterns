"""Required export identities must stay public; actual secrets must not leak."""

import base64
import copy
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "export_evidence", ROOT / "redteam/export_evidence.py"
)
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class ExportPrivacyEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.expected = {
            "version": 2,
            "username": "canonical-account",
            "user_id": "owner-uuid",
            "salt": base64.b64encode(bytes(range(16))).decode(),
            "key_scheme": "v2",
            "wrapped_data_key": "encrypted-envelope",
            "kdf_params": {
                "algorithm": "pbkdf2-sha256",
                "version": 1,
                "iterations": 600000,
            },
        }
        self.bundle = {
            **self.expected,
            "entries": [{"client_entry_id": "entry-id", "blob": "encrypted-journal"}],
        }
        self.secrets = {
            "journal": "unique-private-journal-sentinel",
            "password": "unique-password-sentinel",
            "data key": bytes(range(32)),
            "authentication verifier": bytes(reversed(range(32))),
        }

    def test_required_recovery_metadata_is_allowed_without_claiming_plaintext_content(
        self,
    ):
        self.assertEqual(
            evidence.inspect_export(self.bundle, self.expected, self.secrets), []
        )

    def test_missing_or_substituted_binding_salt_and_version_fail(self):
        for key in (
            "username",
            "user_id",
            "salt",
            "version",
            "wrapped_data_key",
            "kdf_params",
        ):
            with self.subTest(field=key):
                body = copy.deepcopy(self.bundle)
                body.pop(key)
                self.assertTrue(
                    evidence.inspect_export(body, self.expected, self.secrets)
                )
        body = copy.deepcopy(self.bundle)
        body["username"] = "another-account"
        self.assertTrue(evidence.inspect_export(body, self.expected, self.secrets))

    def test_plaintext_journal_and_password_in_unexpected_fields_fail(self):
        for label in ("journal", "password"):
            body = copy.deepcopy(self.bundle)
            body["entries"][0]["unexpected_diagnostic"] = self.secrets[label]
            self.assertIn(
                f"plaintext secret present: {label}",
                evidence.inspect_export(body, self.expected, self.secrets),
            )

    def test_raw_keys_and_verifiers_fail_in_base64_hex_and_byte_array_forms(self):
        for label in ("data key", "authentication verifier"):
            secret = self.secrets[label]
            for value in (
                base64.b64encode(secret).decode(),
                secret.hex(),
                list(secret),
            ):
                with self.subTest(secret=label, encoding=type(value).__name__):
                    body = copy.deepcopy(self.bundle)
                    body["unexpected_diagnostic"] = value
                    self.assertIn(
                        f"plaintext secret present: {label}",
                        evidence.inspect_export(body, self.expected, self.secrets),
                    )


if __name__ == "__main__":
    unittest.main()
