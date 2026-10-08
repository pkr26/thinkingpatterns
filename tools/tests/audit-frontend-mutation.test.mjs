import assert from 'node:assert/strict';
import { test } from 'node:test';
import { auditReport, enumerate, mutantKey } from '../audit-frontend-mutation.mjs';
import { resolve } from 'node:path';

const source = 'export const enabled = true;\n';
const mutant = { id: '0', mutatorName: 'BooleanLiteral', replacement: 'false',
  location: { start: { line: 1, column: 24 }, end: { line: 1, column: 28 } } };
const sources = new Map([['src/example.ts', source], ['src/types.ts', 'export type Flag = boolean;\n']]);
const enumeration = [{ ...mutant, fileName: 'src/example.ts' }];
function report(status = 'Killed') {
  return { files: { 'src/example.ts': { source, mutants: [{ ...mutant, status }] } } };
}

test('accepts complete current-source inventory, including zero-operator modules', () => {
  const result = auditReport(sources, enumeration, report());
  assert.equal(result.total, 1);
  assert.equal(result.targets.length, 2);
  assert.equal(result.targets[1].mutants, 0);
  assert.equal(result.complete, true);
});

test('rejects stale target bytes and omitted mutants', () => {
  const stale = report();
  stale.files['src/example.ts'].source += '// change\n';
  assert.throws(() => auditReport(sources, enumeration, stale), /Stale report source/);
  assert.throws(() => auditReport(sources, enumeration, { files: {} }), /1 enumerated mutants are missing/);
});

test('rejects duplicated or altered operators and out-of-scope files', () => {
  const duplicate = report();
  duplicate.files['src/example.ts'].mutants.push({ ...mutant, id: '1', status: 'Killed' });
  assert.throws(() => auditReport(sources, enumeration, duplicate), /Unexpected\/duplicate mutant/);
  const changed = report();
  changed.files['src/example.ts'].mutants[0].replacement = 'undefined';
  assert.throws(() => auditReport(sources, enumeration, changed), /Unexpected\/duplicate mutant/);
  assert.throws(() => auditReport(sources, enumeration, { files: { 'tests/a.ts': { source, mutants: [] } } }), /Out-of-scope file/);
});

test('never gives timeout, runner error, ignore or uncovered controls runtime kill credit', () => {
  for (const status of ['Timeout', 'RuntimeError', 'Ignored', 'NoCoverage', 'Survived']) {
    const result = auditReport(sources, enumeration, report(status));
    assert.equal(result.counts.Killed, 0);
    assert.equal(result.unresolved, 1);
    assert.equal(result.complete, false);
  }
});

test('rejects nonterminal or unknown statuses', () => {
  for (const status of [undefined, 'Pending', 'MadeUp']) {
    const incomplete = report();
    incomplete.files['src/example.ts'].mutants[0].status = status;
    assert.throws(() => auditReport(sources, enumeration, incomplete), /Unknown\/incomplete status/);
  }
});

test('operator identities are independent of report object-property ordering', () => {
  const reordered = { ...mutant, location: { end: { column: 28, line: 1 }, start: { column: 24, line: 1 } } };
  assert.equal(mutantKey('src/example.ts', reordered), mutantKey('src/example.ts', mutant));
});

test('converts installed instrumenter zero-based lines and columns to report coordinates', async () => {
  const operators = await enumerate(resolve(import.meta.dirname, '../../mobile'), new Map([['src/example.ts', source]]));
  assert.equal(operators.length, 1);
  assert.deepEqual(operators[0].location, mutant.location);
  assert.equal(mutantKey('src/example.ts', operators[0]), mutantKey('src/example.ts', mutant));
});

test('equivalent reviews must identify a surviving operator and retain reasoning and evidence', () => {
  const key = mutantKey('src/example.ts', mutant);
  const review = { key, disposition: 'Equivalent', contract: 'Same exported behavior for all supported inputs.',
    reason: 'Producer invariant makes the alternative branch unreachable.', evidence: ['causal-review.json'] };
  const result = auditReport(sources, enumeration, report('Survived'), [review]);
  assert.equal(result.equivalent, 1);
  assert.equal(result.counts.Killed, 0);
  assert.equal(result.complete, true);
  assert.throws(() => auditReport(sources, enumeration, report('Survived'), [{ ...review, evidence: [] }]), /Incomplete residual review/);
  assert.throws(() => auditReport(sources, enumeration, report('Survived'), [{ ...review, key: 'stale' }]), /Stale\/unmatched/);
  assert.throws(() => auditReport(sources, enumeration, report('Timeout'), [review]), /requires a survivor/);
  assert.throws(() => auditReport(sources, enumeration, report('Survived'), [review, review]), /Duplicate review/);
});

test('reviewed loop nontermination is separate from runtime kills and equivalents', () => {
  const review = { key: mutantKey('src/example.ts', mutant), disposition: 'NonTermination',
    contract: 'The operation terminates for this finite supported input.', reason: 'The mutated update never advances the loop index.',
    evidence: ['longer-budget-replay.json', 'loop-causal-review.json'] };
  const result = auditReport(sources, enumeration, report('Timeout'), [review]);
  assert.equal(result.nonTerminating, 1);
  assert.equal(result.counts.Killed, 0);
  assert.equal(result.equivalent, 0);
  assert.equal(result.complete, true);
  assert.throws(() => auditReport(sources, enumeration, report('Survived'), [review]), /requires a timeout/);
});

test('a Vitest timeout reported as Killed earns no runtime kill credit', () => {
  const stalled = report('Killed');
  stalled.files['src/example.ts'].mutants[0].statusReason = 'Test timed out in 5000ms.\nIf this is a long-running test, pass a timeout value.';
  const initial = auditReport(sources, enumeration, stalled);
  assert.equal(initial.counts.Killed, 1);
  assert.equal(initial.runtimeKills, 0);
  assert.equal(initial.testTimeoutFailures, 1);
  assert.equal(initial.unresolved, 1);
  const review = { key: mutantKey('src/example.ts', mutant), disposition: 'NonTermination',
    contract: 'Finite supported input completes.', reason: 'The mutant removes the only completion callback.', evidence: ['callback-replay.json'] };
  const result = auditReport(sources, enumeration, stalled, [review]);
  assert.equal(result.nonTerminating, 1);
  assert.equal(result.complete, true);
  assert.equal(result.runtimeKills, 0);
});

test('reviewed finite resource expansion stays separate from nontermination and kills', () => {
  const review = { key: mutantKey('src/example.ts',mutant), disposition: 'ResourceExhaustion', contract: 'A short on-device input completes within the established execution budget.',
    reason: 'Each empty global mask doubles its intermediate string; 27 fixed masks expand empty input to 134217727 characters.', evidence: ['growth-proof.json','bounded-replay.json'] };
  const result = auditReport(sources,enumeration,report('Timeout'),[review]);
  assert.equal(result.resourceExhaustion,1); assert.equal(result.nonTerminating,0); assert.equal(result.runtimeKills,0); assert.equal(result.complete,true);
  assert.throws(()=>auditReport(sources,enumeration,report('Survived'),[review]),/requires a timeout/);
});

test('zero-test runner observations cannot earn runtime kills or equivalent closure', () => {
  for (const status of ['Killed','Survived']) {
    const empty = report(status); empty.files['src/example.ts'].mutants[0].testsCompleted = 0;
    const result = auditReport(sources,enumeration,empty);
    assert.equal(result.runtimeKills,0); assert.equal(result.zeroTestObservations,1);
    assert.equal(result.unresolved,1); assert.equal(result.complete,false);
    if (status === 'Survived') assert.throws(()=>auditReport(sources,enumeration,empty,[{
      key:mutantKey('src/example.ts',mutant),disposition:'Equivalent',contract:'Public behavior.',reason:'Guard redundancy.',evidence:['review.json'],
    }]),/valid test observation/);
  }
});
