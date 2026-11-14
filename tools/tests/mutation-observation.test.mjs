import assert from 'node:assert/strict';
import test from 'node:test';
import { observationClassifierVersion, runtimeKill, timedOut, runnerFault } from '../mutation-observation.mjs';

const killed = statusReason => ({ status: 'Killed', testsCompleted: 1, statusReason });

test('real Vitest test and hook watchdog messages remain nonbehavioral observations', () => {
  for (const reason of [
    'Test timed out in 5000ms.\nIf this is a long-running test, pass a timeout value.',
    'Hook timed out in 10000ms.\nIf this is a long-running hook, configure hookTimeout.',
    'Error: Test timed out in 120000ms.',
  ]) {
    assert.equal(timedOut(killed(reason)), true, reason);
    assert.equal(runtimeKill(killed(reason)), false, reason);
  }
  assert.equal(observationClassifierVersion, 2);
});

test('actual API timeout expectation failures retain behavioral kill credit', () => {
  // Representative raw failure messages from the current client campaign;
  // these compare public ApiError behavior rather than indicate test expiry.
  for (const reason of [
    "expected 'request timed out after 15s' to be 'server unreachable — check the server…' // Object.is equality",
    "expected 'server unreachable — check the server…' to be 'request timed out after 15s' // Object.is equality",
    "expected '' to be 'request timed out after 15s' // Object.is equality",
    'expected ApiError: request timed out after 15s { …(3) } to match object { status: 502, …(1) }\n(3 matching properties omitted from actual)',
    'expected "Test timed out in 5000ms." to be "request timed out after 15s"',
  ]) {
    assert.equal(timedOut(killed(reason)), false, reason);
    assert.equal(runnerFault(killed(reason)), false, reason);
    assert.equal(runtimeKill(killed(reason)), true, reason);
  }
});

test('hook and fixture diagnostic words inside assertions do not establish runner failure', () => {
  for (const reason of [
    'expected "retry hook" to equal "ready hook"',
    'expected "beforeAll failed" to equal "completed"',
    'expected "Worker exited unexpectedly" to equal "ready"',
    'expected "SetupError: fixture unavailable" to equal "available"',
    'Failed to load patient recording',
  ]) {
    assert.equal(runnerFault(killed(reason)), false, reason);
    assert.equal(runtimeKill(killed(reason)), true, reason);
  }
  for (const reason of [
    'Worker exited unexpectedly', 'Worker [12] crashed', 'Unhandled error in test worker',
    'beforeAll failed', 'afterEach failure', 'Hook failed to initialize the suite',
    'Failed to collect test', 'Failed to load url /tests/fixture.ts', 'Test runner failed',
    'ExecutionError: producer did not complete', 'Error: SetupError: unsupported fixture',
    'MemoWitnessScheduleFault: producer order missed',
  ]) {
    assert.equal(runnerFault(killed(reason)), true, reason);
    assert.equal(runtimeKill(killed(reason)), false, reason);
  }
});
