#!/usr/bin/env node
/** Local, bounded v1/v2 export opening. No network or build step is required. */
import { readFileSync, statSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { createDecipheriv, hkdfSync, pbkdf2Sync } from 'node:crypto';
import { createInterface } from 'node:readline';
import { Writable } from 'node:stream';

const MAX_FILE = 256 * 1024 * 1024;
const MAX_BLOB = 64 * 1024 * 1024;
const MAX_PLAINTEXT = 128 * 1024 * 1024;
const MAX_ROWS = 100000;
const MIN_ITERATIONS = 100000;
const MAX_ITERATIONS = 10000000;
const asciiJson = value => JSON.stringify(value).replace(/[\u007f-\uffff]/g, c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
const aad = (...parts) => Buffer.from(asciiJson(parts), 'utf8');

function args() {
  const result = {};
  const input = process.argv.slice(2);
  for (let i = 0; i < input.length; i++) {
    if (!['--bundle', '--out'].includes(input[i]) || !input[i + 1] || input[i + 1].startsWith('--')) throw new Error('usage: decrypt_export.mjs --bundle export.json [--out output-prefix]');
    const key = input[i].slice(2);
    if (result[key]) throw new Error('duplicate command option');
    result[key] = input[++i];
  }
  if (!result.bundle) throw new Error('--bundle is required');
  return result;
}

function decode(value, label, maximum = MAX_BLOB) {
  if (typeof value !== 'string' || !value.length || value.length > Math.ceil(maximum / 3) * 4 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new Error(`${label}: invalid or oversized base64`);
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length > maximum || bytes.toString('base64') !== value) throw new Error(`${label}: invalid or oversized base64`);
  return bytes;
}

// JSON.parse otherwise silently accepts a duplicate audio/envelope key. The
// bounded structural walk also refuses deeply nested untrusted documents.
function rejectDuplicateKeys(source) {
  let cursor = 0;
  const ws = () => { while (/\s/.test(source[cursor] ?? '') && cursor < source.length) cursor++; };
  function string() {
    const start = cursor++;
    while (cursor < source.length) {
      if (source[cursor] === '\\') { cursor += 2; continue; }
      if (source[cursor++] === '"') return JSON.parse(source.slice(start, cursor));
    }
    throw new Error('unterminated JSON string');
  }
  function value(depth) {
    if (depth > 64) throw new Error('JSON nesting exceeds limit');
    ws();
    if (source[cursor] === '{') {
      cursor++; ws(); const keys = new Set();
      if (source[cursor] === '}') { cursor++; return; }
      while (true) {
        ws(); const key = string();
        if (keys.has(key)) throw new Error('duplicate JSON key');
        keys.add(key); ws(); cursor++; value(depth + 1); ws();
        if (source[cursor++] === '}') break;
      }
    } else if (source[cursor] === '[') {
      cursor++; ws();
      if (source[cursor] === ']') { cursor++; return; }
      while (true) { value(depth + 1); ws(); if (source[cursor++] === ']') break; }
    } else if (source[cursor] === '"') string();
    else { while (cursor < source.length && !/[\s,}\]]/.test(source[cursor])) cursor++; }
  }
  value(0);
}

async function password() {
  if (process.env.MINDPATTERN_PASSWORD) return process.env.MINDPATTERN_PASSWORD;
  if (process.stdin.isTTY) process.stderr.write('Password (hidden): ');
  const hidden = new Writable({ write(_data, _encoding, done) { done(); } });
  const previousRaw = process.stdin.isRaw;
  const rl = createInterface({ input: process.stdin, output: hidden, terminal: Boolean(process.stdin.isTTY) });
  try {
    return await new Promise((accept, reject) => {
      rl.once('line', accept);
      rl.once('SIGINT', () => reject(new Error('password input cancelled')));
      rl.once('close', () => reject(new Error('password input ended')));
    });
  } finally {
    rl.close();
    if (process.stdin.isTTY) { process.stdin.setRawMode(Boolean(previousRaw)); process.stderr.write('\n'); }
  }
}

function parameters(value) {
  if (value == null) return { algorithm: 'pbkdf2-sha256', version: 1, iterations: 600000 };
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(k => !['algorithm', 'version', 'iterations'].includes(k)) || value.algorithm !== 'pbkdf2-sha256' || value.version !== 1 || !Number.isSafeInteger(value.iterations) || value.iterations < MIN_ITERATIONS || value.iterations > MAX_ITERATIONS) throw new Error('unsupported or unsafe kdf_params');
  // AAD order is algorithm, version, iterations; server storage sorts keys.
  return { algorithm: value.algorithm, version: value.version, iterations: value.iterations };
}

function open(key, blob, binding) {
  if (blob.length < 28) throw new Error('ciphertext is too short');
  const cipher = createDecipheriv('aes-256-gcm', key, blob.subarray(0, 12));
  cipher.setAAD(binding); cipher.setAuthTag(blob.subarray(-16));
  return Buffer.concat([cipher.update(blob.subarray(12, -16)), cipher.final()]);
}

async function main() {
  const options = args();
  if (statSync(options.bundle).size > MAX_FILE) throw new Error('bundle exceeds the 256 MiB file limit');
  const source = readFileSync(options.bundle, 'utf8');
  const bundle = JSON.parse(source);
  rejectDuplicateKeys(source);
  if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle) || ![1, 2].includes(bundle.version ?? 1) || typeof bundle.user_id !== 'string' || !bundle.user_id.length || bundle.user_id.length > 64) throw new Error('invalid export identity/version');
  const scheme = bundle.key_scheme ?? 'v1';
  if (!['v1', 'v2'].includes(scheme)) throw new Error('unsupported key scheme');
  if (scheme === 'v2' && (typeof bundle.username !== 'string' || !bundle.username.length || bundle.username.length > 64 || !bundle.kdf_params || !bundle.wrapped_data_key)) throw new Error('v2 export requires canonical username, kdf_params and wrapped_data_key; re-export from the app');
  const salt = decode(bundle.salt, 'salt', 128);
  if (salt.length < 8 || salt.length > 64) throw new Error('invalid KDF salt size');
  const params = parameters(bundle.kdf_params);
  let totalRows = 0;
  for (const collection of ['entries', 'insights', 'measures', 'audio']) {
    if (bundle[collection] != null && !Array.isArray(bundle[collection])) throw new Error(`invalid ${collection} collection`);
    totalRows += (bundle[collection] ?? []).length;
  }
  if (totalRows > MAX_ROWS) throw new Error('bundle exceeds the row limit');
  const secret = await password();
  if (!secret || Buffer.byteLength(secret, 'utf8') > 4096) throw new Error('password is empty or exceeds the limit');
  let master, kek, key;
  const audioBuffers = [];
  try {
    master = pbkdf2Sync(secret, salt, params.iterations, 32, 'sha256');
    if (scheme === 'v2') {
      kek = Buffer.from(hkdfSync('sha256', master, salt, Buffer.from('mindpattern/envelope/v2'), 32));
      const wrapped = decode(bundle.wrapped_data_key, 'wrapped_data_key', 60);
      if (wrapped.length !== 60) throw new Error('invalid wrapped data key size');
      key = open(kek, wrapped, Buffer.from(asciiJson({ context: 'envelope', kdf_params: params, username: bundle.username })));
      if (key.length !== 32) throw new Error('invalid data key');
    } else key = Buffer.from(hkdfSync('sha256', master, Buffer.alloc(32), Buffer.from('mindpattern/data/v1'), 32));
    let plaintextBytes = 0;
    const reserve = bytes => { plaintextBytes += bytes; if (plaintextBytes > MAX_PLAINTEXT) throw new Error('decrypted data exceeds the 128 MiB output limit'); };
    function identifier(value) {
      if (typeof value !== 'string' || !value.length || value.length > 64) throw new Error('missing or invalid AAD identifier');
      return value;
    }
    function payload(row, bindings) {
      const blob = decode(row.blob, 'ciphertext');
      let plain;
      for (const binding of bindings) { try { plain = open(key, blob, binding); break; } catch { /* bounded legacy AAD ladder */ } }
      if (!plain) throw new Error('ciphertext authentication failed (wrong password or damaged export)');
      try {
        reserve(plain.length);
        const value = JSON.parse(plain.toString('utf8'));
        if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid encrypted JSON payload');
        const { blob: _blob, ...metadata } = row;
        return { ...metadata, decrypted: value };
      } finally { plain.fill(0); }
    }
    const entries = (bundle.entries ?? []).map(row => {
      const id = identifier(row.client_entry_id);
      if (row.content_version != null && (!Number.isSafeInteger(row.content_version) || row.content_version < 1)) throw new Error('invalid entry content_version');
      const bindings = row.content_version == null ? [] : [aad('entry', bundle.user_id, id, String(row.content_version))];
      bindings.push(aad('entry', bundle.user_id, id));
      return payload(row, bindings);
    });
    const insights = (bundle.insights ?? []).map(row => {
      if (!['patterns', 'brain', 'question'].includes(row.kind)) throw new Error('unsupported insight kind');
      if (row.kind === 'question' && (typeof row.for_date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(row.for_date))) throw new Error('missing question AAD date');
      return payload(row, [row.kind === 'question' ? aad('question', bundle.user_id, row.for_date) : aad('insights', bundle.user_id, row.kind)]);
    });
    const measures = (bundle.measures ?? []).map(row => payload(row, [aad('measure', bundle.user_id, identifier(row.client_measure_id))]));
    const extensions = { 'audio/webm': 'webm', 'audio/mp4': 'm4a', 'audio/m4a': 'm4a', 'audio/wav': 'wav', 'audio/mpeg': 'mp3', 'audio/ogg': 'ogg', 'audio/aac': 'aac' };
    const audio = (bundle.audio ?? []).map((row, index) => {
      const version = row.content_version ?? (bundle.version === 2 ? null : 1);
      if (!Number.isSafeInteger(version) || version < 1) throw new Error('missing audio content_version');
      const blob = decode(row.blob, 'audio');
      if (row.size_bytes != null && row.size_bytes !== blob.length) throw new Error('audio ciphertext size mismatch');
      const plain = open(key, blob, aad('audio', bundle.user_id, identifier(row.client_entry_id), String(version)));
      audioBuffers.push(plain); reserve(plain.length);
      const { blob: _blob, ...metadata } = row;
      return { ...metadata, content_version: version, file: `${String(index + 1).padStart(6, '0')}.${extensions[row.mime_type] ?? 'bin'}`, plaintext_bytes: plain.length };
    });
    const prefix = resolve(options.out ?? options.bundle.replace(/\.json$/i, '') + '-decrypted');
    const jsonPath = prefix + '.json', mdPath = prefix + '.md', audioPath = prefix + '.audio';
    if ([jsonPath, mdPath, ...(audio.length ? [audioPath] : [])].some(existsSync)) throw new Error('output already exists; choose another --out prefix');
    mkdirSync(dirname(prefix), { recursive: true, mode: 0o700 });
    const lines = [`# MindPattern journal — ${bundle.user_id}`, ''];
    for (const row of entries) lines.push(`## ${row.decrypted.created_at ?? row.entry_date ?? ''}`, '', row.decrypted.text ?? '', '');
    if (measures.length) { lines.push('## Wellbeing measures', ''); for (const row of measures) lines.push(`- ${row.decrypted.completed_at ?? row.measure_date ?? ''}: ${row.decrypted.measure ?? 'questionnaire'} score ${row.decrypted.score}`); }
    writeFileSync(jsonPath, JSON.stringify({ user_id: bundle.user_id, entries, insights, measures, audio: audio.map(row => ({ ...row, file: `${audioPath}/${row.file}` })) }, null, 2), { mode: 0o600, flag: 'wx' });
    writeFileSync(mdPath, lines.join('\n'), { mode: 0o600, flag: 'wx' });
    if (audio.length) { mkdirSync(audioPath, { mode: 0o700 }); audio.forEach((row, index) => writeFileSync(`${audioPath}/${row.file}`, audioBuffers[index], { mode: 0o600, flag: 'wx' })); }
    console.log(`Authenticated and opened ${entries.length} entries, ${insights.length} insights, ${measures.length} measures, ${audio.length} recordings.`);
    console.log(`Wrote ${jsonPath} and ${mdPath}${audio.length ? ` plus ${audioPath}` : ''}.`);
  } finally {
    for (const buffer of [master, kek, key, salt, ...audioBuffers]) buffer?.fill(0);
  }
}

try { await main(); } catch (error) { console.error(`Export failed: ${error.message}`); process.exitCode = 1; }
