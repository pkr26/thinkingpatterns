import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { captureInputs, residualMutationRanges, validateReport, verifyInputs } from './mutation-evidence.mjs';

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'portal-evidence-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const portal = join(root, 'portal');
  for (const path of ['src', 'tests/__snapshots__', 'tools', 'public', 'data']) await mkdir(join(portal, path), { recursive: true });
  for (const path of ['src/example.ts', 'tests/__snapshots__/example.snap', 'package.json', 'package-lock.json', 'vite.config.ts', 'tsconfig.json', 'index.html', 'stryker.config.json', '../shared/vector.json', '../deploy/nginx/mindpattern.conf.example']) {
    await mkdir(join(portal, path, '..'), { recursive: true });
    await writeFile(join(portal, path), 'frozen input\n');
  }
  return portal;
}

test('each shard rejects modified source, snapshot or shared fixture inputs', async t => {
  for (const file of ['src/example.ts', 'tests/__snapshots__/example.snap', '../shared/vector.json']) {
    const portal = await fixture(t);
    const inputs = await captureInputs(portal);
    await verifyInputs(portal, inputs, 'pristine');
    await writeFile(join(portal, file), 'changed by a test or mutant\n');
    await assert.rejects(verifyInputs(portal, inputs, 'after file execution'), /frozen inputs changed/);
  }
});

test('new test or shared fixture files invalidate a shard baseline', async t => {
  for (const file of ['tests/unexpected.test.ts', '../shared/unexpected.json']) {
    const portal = await fixture(t);
    const inputs = await captureInputs(portal);
    await writeFile(join(portal, file), 'unexpected input\n');
    await assert.rejects(verifyInputs(portal, inputs, 'after baseline'), /frozen inputs changed/);
  }
});

test('a source-only snapshot permits absent local data and detects later materialization', async t => {
  const portal = await fixture(t);
  await rm(join(portal, 'data'), { recursive: true });
  const inputs = await captureInputs(portal);
  assert.equal(inputs.data, null);
  await verifyInputs(portal, inputs, 'pristine source-only snapshot');
  await mkdir(join(portal, 'data'));
  await writeFile(join(portal, 'data/unexpected.json'), 'created by a test');
  await assert.rejects(verifyInputs(portal, inputs, 'after baseline'), /frozen inputs changed in data/);
});

const source = 'export const example = 1;';
const expected = { 'src/example.ts': createHash('sha256').update(source).digest('hex') };
const report = status => ({ files: { 'src/example.ts': { source, mutants: [{ status }] } } });

test('ordinary threshold failure remains a complete report; fatal exit does not', () => {
  assert.deepEqual(validateReport(report('Survived'), expected, 1, 65).counts, { Survived: 1 });
  assert.throws(() => validateReport(report('Killed'), expected, 1, 65), /runner exit/);
  assert.throws(() => validateReport(report('Survived'), expected, 137, 65), /runner exit/);
});

test('partial, empty, stale and wrong-scope reports cannot be accepted', () => {
  assert.throws(() => validateReport(report('Pending'), expected, 0, 65), /unfinished/);
  const empty = report('Killed'); empty.files['src/example.ts'].mutants = [];
  assert.throws(() => validateReport(empty, expected, 0, 65), /no operators/);
  const stale = report('Killed'); stale.files['src/example.ts'].source += '// stale';
  assert.throws(() => validateReport(stale, expected, 0, 65), /frozen input/);
  const wrongScope = report('Killed'); wrongScope.files['src/other.ts'] = wrongScope.files['src/example.ts'];
  assert.throws(() => validateReport(wrongScope, expected, 0, 65), /unexpected files/);
});

test('residual replay includes producer refusals, watchdogs and invalid observations without replaying assertion kills', () => {
  const mutant = (line, status, statusReason = '', testsCompleted = 1) => ({ status, statusReason, testsCompleted,
    location: { start: { line, column: 2 }, end: { line, column: 5 } } });
  const rows = [
    mutant(1, 'Killed', 'expected "request timed out after 15s" to equal "offline"'),
    mutant(2, 'Killed', 'SetupError: public chart producer did not settle'),
    mutant(3, 'Killed', 'Error: Test timed out in 5000ms.'),
    mutant(4, 'Killed', 'expected current editor to be present', 0),
    mutant(5, 'Survived'), mutant(6, 'NoCoverage'), mutant(7, 'Timeout'),
    mutant(2, 'Killed', 'SetupError: duplicate operator at the same source range'),
  ];
  assert.deepEqual(residualMutationRanges('src/views/PatientView.tsx', rows), [2, 3, 4, 5, 6, 7].map(line => `src/views/PatientView.tsx:${line}:1-${line}:4`));
});
