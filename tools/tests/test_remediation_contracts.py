"""Behavioral regression checks for delivery/recovery audit findings.

Run: python -m unittest discover -s tools/tests -v
All credentials and input records here are synthetic.
"""
from __future__ import annotations

import base64
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
NODE = str(ROOT / '.tools/node/bin/node') if (ROOT / '.tools/node/bin/node').exists() else shutil.which('node')
PYTHON = os.sys.executable


def module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class MutationEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.path = Path(self.scratch.name)

    def gate(self, statuses, floor=65):
        report = self.path / 'mutation.json'
        report.write_text(json.dumps({'files': {'web/src/a.ts': {'mutants': [{'status': status} for status in statuses]}}}))
        return subprocess.run([NODE, str(ROOT / 'tools/check-mutation-score.mjs'), str(report), str(floor)], capture_output=True, text=True)

    def test_floor_is_inclusive_and_failures_are_real(self):
        for floor in (65, 84):
            self.assertEqual(self.gate(['Killed'] * floor + ['Survived'] * (100-floor), floor).returncode, 0)
            self.assertEqual(self.gate(['Killed'] * (floor-1) + ['Survived'] * (101-floor), floor).returncode, 1)
            self.assertEqual(self.gate(['Killed'] * 100, floor).returncode, 0)

    def test_empty_pending_unknown_and_runtime_error_cannot_pass(self):
        for statuses in ([], ['Pending'], ['Unknown'], ['RuntimeError'], ['Killed', 'RuntimeError']):
            self.assertNotEqual(self.gate(statuses).returncode, 0)

    def comparison(self, next_status, *, prior_status='Survived', omit=False, source='const a = 1;', replacement='2'):
        mutant = {'id': '0', 'mutatorName': 'NumberLiteral', 'replacement': '2', 'location': {'start': {'line': 1, 'column': 10}, 'end': {'line': 1, 'column': 11}}, 'status': prior_status}
        before = self.path / 'before.json'
        after = self.path / 'after.json'
        before.write_text(json.dumps({'files': {'portal/src/a.ts': {'source': 'const a = 1;', 'mutants': [mutant]}}}))
        next_mutant = {**mutant, 'status': next_status, 'replacement': replacement}
        after.write_text(json.dumps({'files': {'portal/src/a.ts': {'source': source, 'mutants': [] if omit else [next_mutant]}}}))
        return subprocess.run([NODE, str(ROOT / 'redteam/mutation_campaign_2026-09-22_frontend/verify_kills.js'), str(before), str(after)], capture_output=True, text=True)

    def test_only_actual_terminal_kills_are_credited(self):
        for status in ('Killed', 'Timeout'):
            result = self.comparison(status)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('killed by the pin batch: 1', result.stdout)
        for status in ('RuntimeError', 'CompileError', 'Ignored'):
            result = self.comparison(status)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('killed by the pin batch: 0', result.stdout)
        self.assertNotEqual(self.comparison('Killed', omit=True).returncode, 0)
        self.assertNotEqual(self.comparison('Killed', source='const a = 3;').returncode, 0)
        self.assertNotEqual(self.comparison('Killed', replacement='4').returncode, 0)

    def test_previous_kills_cannot_become_errors_or_ignored(self):
        for before in ('Killed', 'Timeout'):
            for after in ('RuntimeError', 'CompileError', 'Ignored'):
                self.assertNotEqual(self.comparison(after, prior_status=before).returncode, 0)
        self.assertNotEqual(self.comparison('RuntimeError', prior_status='Ignored').returncode, 0)


class CampaignEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.validator = module('campaign_validator', ROOT / 'redteam/validate_results.py')
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.path = Path(self.scratch.name)
        for name in self.validator.EXPECTED:
            (self.path / f'{name}.json').write_text(json.dumps([{'id': verdict_id, 'status': 'BLOCKED', 'summary': 'synthetic complete case'} for verdict_id in self.validator.INVENTORY[name]]))

    def test_complete_inventory_includes_voice(self):
        self.assertEqual(len(self.validator.validate(self.path)), sum(map(len, self.validator.INVENTORY.values())))
        (self.path / 'g_voice.json').unlink()
        with self.assertRaisesRegex(ValueError, 'g_voice'):
            self.validator.validate(self.path)

    def test_empty_or_error_campaign_cannot_look_complete(self):
        for payload in ([], [{'id': 'voice', 'status': 'ERROR', 'summary': 'failed'}], [{'id': 'voice', 'status': 'UNKNOWN', 'summary': 'invalid'}]):
            (self.path / 'g_voice.json').write_text(json.dumps(payload))
            with self.assertRaises(ValueError):
                self.validator.validate(self.path)

    def test_partial_inventory_and_skipped_attack_cannot_pass(self):
        name = 'a_crypto'
        rows = json.loads((self.path / f'{name}.json').read_text())
        (self.path / f'{name}.json').write_text(json.dumps(rows[:-1]))
        with self.assertRaisesRegex(ValueError, 'inventory'):
            self.validator.validate(self.path)
        rows[0]['status'] = 'NOT-RUN'
        (self.path / f'{name}.json').write_text(json.dumps(rows))
        with self.assertRaisesRegex(ValueError, 'did not run'):
            self.validator.validate(self.path)


class BackupRoundTripTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.path = Path(self.scratch.name)
        self.keyfile = self.path / 'backup-key'
        self.keyfile.write_text('synthetic file key for audit regression\n')
        self.env = {k: v for k, v in os.environ.items() if k not in ('BACKUP_KEY', 'BACKUP_KEY_FILE')}
        self.env['BACKUP_KEY_FILE'] = str(self.keyfile)
        self.cipher = self.path / 'backup.dump.enc'
        self.payload = b'PGDMP synthetic binary payload\x00\xff' * 31

    def command(self, *args, data=None, env=None):
        return subprocess.run([PYTHON, str(ROOT / 'backup/backup_mac.py'), *map(str, args)], input=data, capture_output=True, env=env or self.env)

    def encrypt_and_tag(self, env=None):
        result = self.command('encrypt', self.cipher, data=self.payload, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.command('write', self.cipher, self.cipher.with_suffix('.enc.hmac'), env=env)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_default_file_secret_roundtrip_and_owner_only_artifacts(self):
        self.encrypt_and_tag()
        result = self.command('decrypt', self.cipher)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, self.payload)
        self.assertEqual(self.cipher.stat().st_mode & 0o777, 0o600)
        self.assertEqual(Path(str(self.cipher)+'.hmac').stat().st_mode & 0o777, 0o600)

    def test_mixed_sources_resolve_consistently_and_env_only_works(self):
        mixed = {**self.env, 'BACKUP_KEY': 'synthetic env override key'}
        self.encrypt_and_tag(env=mixed)
        self.assertEqual(self.command('decrypt', self.cipher, env=mixed).stdout, self.payload)
        env_only = {k:v for k,v in mixed.items() if k != 'BACKUP_KEY_FILE'}
        self.assertEqual(self.command('decrypt', self.cipher, env=env_only).stdout, self.payload)
        wrong = self.command('decrypt', self.cipher)
        self.assertNotEqual(wrong.returncode, 0)
        self.assertEqual(wrong.stdout, b'')

    def test_tampered_or_missing_mac_emits_no_plaintext(self):
        self.encrypt_and_tag()
        self.cipher.write_bytes(self.cipher.read_bytes()+b'tampered')
        result = self.command('decrypt', self.cipher)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        Path(str(self.cipher)+'.hmac').unlink()
        result = self.command('decrypt', self.cipher)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')

    def test_multiline_keys_are_rejected_before_output(self):
        bad = {**self.env, 'BACKUP_KEY': 'first\nsecond'}
        result = self.command('encrypt', self.cipher, data=self.payload, env=bad)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.cipher.exists())

    def test_long_common_prefix_keys_are_rejected_before_output(self):
        for suffix in ('A', 'B'):
            result = self.command('encrypt', self.cipher, data=self.payload, env={**self.env, 'BACKUP_KEY': 'x'*3000 + suffix})
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(self.cipher.exists())

    def test_combined_encryption_and_tag_use_one_secret_during_file_rotation(self):
        helper = module('backup_rotation', ROOT / 'backup/backup_mac.py')
        initial_key = self.keyfile.read_text().strip()
        openssl = helper._openssl
        def rotate_after_encryption(*args, **kwargs):
            result = openssl(*args, **kwargs)
            self.keyfile.write_text('synthetic replacement key during encryption\n')
            return result
        with tempfile.TemporaryFile() as payload, \
             mock.patch.dict(os.environ, self.env, clear=True), \
             mock.patch.object(helper, '_openssl', rotate_after_encryption), \
             mock.patch.object(helper.sys, 'stdin') as stdin:
            payload.write(self.payload)
            payload.seek(0)
            stdin.buffer = payload
            self.assertEqual(helper._crypt_file('encrypt', self.cipher, Path(str(self.cipher)+'.hmac'), seal=True), 0)
        original = self.command('decrypt', self.cipher, env={**self.env, 'BACKUP_KEY': initial_key})
        self.assertEqual(original.returncode, 0, original.stderr)
        self.assertEqual(original.stdout, self.payload)
        wrong = self.command('decrypt', self.cipher)
        self.assertNotEqual(wrong.returncode, 0)
        self.assertEqual(wrong.stdout, b'')

    def test_in_place_change_after_authentication_cannot_change_decrypted_bytes(self):
        self.encrypt_and_tag()
        original = self.cipher.read_bytes()
        helper = module('backup_snapshot', ROOT / 'backup/backup_mac.py')
        sidecar = Path(str(self.cipher) + '.hmac')
        tag = sidecar.read_bytes()
        captured = []

        def replace_after_snapshot(path):
            self.assertEqual(path, sidecar)
            self.cipher.write_bytes(b'untrusted concurrent replacement')
            return tag

        def consume_snapshot(secret, source, destination, *, decrypt):
            self.assertTrue(decrypt)
            captured.append(source.read())
            return 0

        with mock.patch.dict(os.environ, self.env, clear=True), \
             mock.patch.object(Path, 'read_bytes', replace_after_snapshot), \
             mock.patch.object(helper, '_openssl', consume_snapshot):
            self.assertEqual(helper._crypt_file('decrypt', self.cipher, sidecar), 0)
        self.assertEqual(captured, [original])
        self.assertEqual(self.cipher.read_bytes(), b'untrusted concurrent replacement')


class AadFixtureTests(unittest.TestCase):
    def test_promoted_corpus_is_byte_exact_and_normalizations_are_distinct(self):
        original = json.loads((ROOT / 'redteam/aad_corpus.json').read_text())
        shared = json.loads((ROOT / 'shared/vectors.json').read_text())['aad_edge_cases']
        promoted = {case['name']:case for case in shared}
        for case in original:
            with self.subTest(name=case['name']):
                self.assertEqual(promoted[case['name']]['parts'], case['parts'])
                self.assertEqual(base64.b64decode(promoted[case['name']]['aad_b64']), bytes.fromhex(case['aad_hex']))
        self.assertNotEqual(promoted['combining']['aad_b64'], promoted['combining-nfc']['aad_b64'])


if __name__ == '__main__':
    unittest.main()
