import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { deriveDataKey, deriveMasterKey } from '../src/crypto/kdf';
import { buildAad, encrypt } from '../src/crypto/envelope';
import { envelopeKek, wrapDataKey, type KdfParams } from '../src/crypto/keyEnvelope';

const directories: string[] = [];
afterEach(() => { for (const path of directories.splice(0)) rmSync(path, { recursive: true, force: true }); });
const password = 'export password café 🔐';
const params: KdfParams = { algorithm: 'pbkdf2-sha256', version: 1, iterations: 100000 };
function fixture(scheme: 'v1' | 'v2' = 'v2') {
  const salt = randomBytes(16), master = deriveMasterKey(password, salt, params.iterations);
  const user = '0123456789abcdef0123456789abcdef', username = 'canonical-name';
  const key = scheme === 'v2' ? randomBytes(32) : deriveDataKey(master);
  const json = (value: unknown, aad: Buffer) => encrypt(key, Buffer.from(JSON.stringify(value)), aad).toString('base64');
  const recording = Buffer.from('original recording bytes\u0000\ufffd');
  const audio = encrypt(key, recording, buildAad('audio', user, 'voice-entry', '1'));
  const bundle = {
    version: 2, user_id: user, username, salt: salt.toString('base64'), key_scheme: scheme, kdf_params: params,
    wrapped_data_key: scheme === 'v2' ? wrapDataKey(key, envelopeKek(master, salt), username, params).toString('base64') : null,
    entries: [
      { client_entry_id: 'v2-entry', content_version: 3, blob: json({ text: 'current bound entry café' }, buildAad('entry', user, 'v2-entry', '3')) },
      { client_entry_id: 'legacy-entry', content_version: 4, blob: json({ text: 'legacy entry' }, buildAad('entry', user, 'legacy-entry')) },
    ],
    insights: [{ kind: 'brain', blob: json({ schema: 1 }, buildAad('insights', user, 'brain')) }, { kind: 'question', for_date: '2026-10-03', blob: json({ question: 'What did you notice?' }, buildAad('question', user, '2026-10-03')) }],
    measures: [{ client_measure_id: 'measure-1', blob: json({ measure: 'phq9', score: 2 }, buildAad('measure', user, 'measure-1')) }],
    audio: [{ id: 'audio-1', client_entry_id: 'voice-entry', content_version: 1, mime_type: 'audio/webm', size_bytes: audio.length, blob: audio.toString('base64') }],
  };
  return { bundle, recording };
}
function run(bundle: unknown, secret = password, source?: string) {
  const directory = mkdtempSync(join(tmpdir(), 'fathom-export-test-')); directories.push(directory);
  const input = join(directory, 'export.json'), out = join(directory, 'opened');
  writeFileSync(input, source ?? JSON.stringify(bundle));
  const processResult = spawnSync(process.execPath, [resolve('tools/decrypt_export.mjs'), '--bundle', input, '--out', out], { encoding: 'utf8', env: { ...process.env, MINDPATTERN_PASSWORD: secret }, timeout: 10000 });
  return { ...processResult, out };
}

describe('standalone export tool opens shipping-client envelopes', () => {
  for (const scheme of ['v1', 'v2'] as const) it(`opens ${scheme}, mixed entry AAD, dated insights, measures and recording`, () => {
    const { bundle, recording } = fixture(scheme); const result = run(bundle);
    expect(result.status, result.stderr).toBe(0);
    const output = JSON.parse(readFileSync(result.out + '.json', 'utf8'));
    expect(output.entries.map((row: { decrypted: { text: string } }) => row.decrypted.text)).toEqual(['current bound entry café', 'legacy entry']);
    expect(output.insights[1].decrypted.question).toBe('What did you notice?');
    expect(output.measures[0].decrypted.score).toBe(2);
    expect(readFileSync(output.audio[0].file)).toEqual(recording);
    expect(statSync(result.out + '.json').mode & 0o777).toBe(0o600);
    expect(statSync(output.audio[0].file).mode & 0o777).toBe(0o600);
    expect(statSync(result.out + '.audio').mode & 0o777).toBe(0o700);
  });
  it('rejects wrong password without publishing partial plaintext', () => {
    const result = run(fixture().bundle, 'wrong password'); expect(result.status).toBe(1); expect(existsSync(result.out + '.json')).toBe(false);
  });
  it('rejects v2 missing canonical name and excessive KDF cost before work', () => {
    const bundle = fixture().bundle;
    for (const hostile of [{ ...bundle, username: undefined }, { ...bundle, kdf_params: { ...params, iterations: 10000001 } }, { ...bundle, kdf_params: { ...params, version: 2 } }]) {
      const result = run(hostile); expect(result.status).toBe(1); expect(existsSync(result.out + '.json')).toBe(false);
    }
  });
  it('rejects duplicate audio keys and malformed base64', () => {
    const bundle = fixture().bundle;
    const duplicate = run(bundle, password, JSON.stringify(bundle).replace('"audio":[', '"audio":[],"audio":[')); expect(duplicate.status).toBe(1); expect(duplicate.stderr).toContain('duplicate JSON key');
    bundle.entries[0].blob += '!'; const invalid = run(bundle); expect(invalid.status).toBe(1); expect(existsSync(invalid.out + '.json')).toBe(false);
  });
  it('rejects a damaged single row even if other rows authenticate', () => {
    const bundle = fixture().bundle; bundle.measures[0].blob = Buffer.alloc(60).toString('base64');
    const result = run(bundle); expect(result.status).toBe(1); expect(existsSync(result.out + '.json')).toBe(false);
  });
  it('requires audio version metadata in new exports and never uses IDs as paths', () => {
    const bundle = fixture().bundle; delete (bundle.audio[0] as { content_version?: number }).content_version;
    const result = run(bundle); expect(result.status).toBe(1); expect(existsSync(result.out + '.audio')).toBe(false);
  });
});
