// Raw Stryker status alone does not prove that a consumer executed.
export const timedOut = mutant => mutant.status === 'Killed' && /\btimed out\b/i.test(mutant.statusReason ?? '');
export const runnerFault = mutant => mutant.status === 'Killed'
  && /worker (?:exited|crashed|failed)|unhandled (?:error|rejection)|beforeall|afterall|beforeeach|aftereach|\bhook\b|test runner.*(?:failed|error)|failed to (?:load|collect)|\b(?:ExecutionError|SetupError|MemoWitnessScheduleFault)\b/i.test(mutant.statusReason ?? '');
export const incompleteRun = mutant => ['Killed', 'Survived'].includes(mutant.status)
  && (!Number.isSafeInteger(mutant.testsCompleted) || mutant.testsCompleted <= 0);
export const runtimeKill = mutant => mutant.status === 'Killed' && !timedOut(mutant) && !runnerFault(mutant) && !incompleteRun(mutant);
