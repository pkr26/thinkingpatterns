// Raw Stryker status alone does not prove that a consumer executed.
export const observationClassifierVersion = 2;
// Vitest's adapter forwards the first error's message. Assertions can include
// application timeout/hook text in their expected and actual values; only a
// runner diagnostic at the message boundary is infrastructure evidence.
const diagnostic = mutant => typeof mutant.statusReason === 'string'
  ? mutant.statusReason.trimStart().replace(/^(?:Error|TimeoutError|AggregateError):[ \t]*/, '') : '';
export const timedOut = mutant => mutant.status === 'Killed'
  && /^(?:Test|Hook) timed out in \d+(?:\.\d+)?ms\.(?:\r?\n|$)/i.test(diagnostic(mutant));
export const runnerFault = mutant => mutant.status === 'Killed'
  && /^(?:worker(?: process| \[\d+\])? (?:exited|crashed|failed)\b|unhandled (?:error|rejection)\b|(?:beforeall|afterall|beforeeach|aftereach)\b|hook (?:timed out|failed|failure|error)\b|test runner\b.*(?:failed|error)|failed to (?:load (?:url|module|config|tests?)\b|collect (?:test|suite))|(?:ExecutionError|SetupError|MemoWitnessScheduleFault):)/i.test(diagnostic(mutant));
export const incompleteRun = mutant => ['Killed', 'Survived'].includes(mutant.status)
  && (!Number.isSafeInteger(mutant.testsCompleted) || mutant.testsCompleted <= 0);
export const runtimeKill = mutant => mutant.status === 'Killed' && !timedOut(mutant) && !runnerFault(mutant) && !incompleteRun(mutant);
